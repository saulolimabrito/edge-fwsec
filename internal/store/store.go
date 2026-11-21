// Package store persists configuration revisions and the apply state.
//
// Layout under the state directory (0700, owned by the agent):
//
//	lock                  exclusive flock held by the single writer
//	state.json            confirmed revision, revision under test, deadline
//	revisions/<n>.json    immutable revisions (config + metadata)
//	history.jsonl         append-only audit log
//
// Every file is replaced atomically (temp file, fsync, rename, fsync dir),
// so a crash leaves either the old or the new version, never a mix.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

var (
	// ErrConflict means the proposal was based on a revision that is no
	// longer the confirmed one (another change landed first).
	ErrConflict = errors.New("base revision is not the confirmed revision")
	// ErrBusy means a revision is already under test.
	ErrBusy = errors.New("another revision is under test")
	// ErrNotTesting means there is no revision under test (or a different one).
	ErrNotTesting = errors.New("revision is not under test")
	// ErrLocked means another process holds the state directory.
	ErrLocked = errors.New("state directory is locked by another process")
)

// Revision is one immutable configuration version.
type Revision struct {
	Number       int             `json:"revision"`
	BaseRevision int             `json:"base_revision"`
	Author       string          `json:"author"`
	Message      string          `json:"message,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	Config       json.RawMessage `json:"config"`
}

// Testing describes the revision currently applied and awaiting confirmation.
type Testing struct {
	Revision  int       `json:"revision"`
	StartedAt time.Time `json:"started_at"`
	Deadline  time.Time `json:"deadline"`
	Author    string    `json:"author"`
	// Checkpoint is the NetworkManager checkpoint guarding the network part
	// of the change ("" when the change has no network step).
	Checkpoint string `json:"checkpoint,omitempty"`
}

// State is the durable apply state. Confirmed is 0 before the first
// confirmation (no appliance policy).
type State struct {
	Confirmed    int      `json:"confirmed"`
	Testing      *Testing `json:"testing"`
	LastRevision int      `json:"last_revision"`
}

// Event is one audit record.
type Event struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"` // propose, apply, confirm, rollback, recover, apply_failed
	Revision int       `json:"revision"`
	Author   string    `json:"author"`
	Result   string    `json:"result"` // ok | error text | reason
}

// Store is safe for concurrent use within one process; across processes the
// flock on <dir>/lock guarantees a single writer.
type Store struct {
	dir  string
	lock *os.File
	mu   sync.Mutex
	st   State
	now  func() time.Time
}

// Open takes the exclusive lock and loads the state, creating the layout
// if needed.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "revisions"), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lf.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	s := &Store{dir: dir, lock: lf, now: time.Now}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		s.Close()
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.st); err != nil {
			s.Close()
			return nil, fmt.Errorf("state.json is corrupt: %w", err)
		}
	}
	return s, nil
}

// Close releases the lock.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close() // closing the fd drops the flock
	s.lock = nil
	return err
}

// State returns a copy of the current state.
func (s *Store) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	if st.Testing != nil {
		t := *st.Testing
		st.Testing = &t
	}
	return st
}

// Get loads a revision.
func (s *Store) Get(n int) (*Revision, error) {
	b, err := os.ReadFile(s.revPath(n))
	if err != nil {
		return nil, err
	}
	var r Revision
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("revision %d is corrupt: %w", n, err)
	}
	return &r, nil
}

// Decode parses a revision's configuration.
func (r *Revision) Decode() (*policy.Config, error) {
	return policy.Decode(bytes.NewReader(r.Config))
}

// Propose validates cfg and stores it as a new revision based on base.
// base must equal the confirmed revision (optimistic concurrency).
func (s *Store) Propose(cfg *policy.Config, base int, author, msg string) (*Revision, error) {
	if err := policy.Validate(cfg); err != nil {
		return nil, err
	}
	raw, err := cfg.Canonical()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if base != s.st.Confirmed {
		return nil, fmt.Errorf("%w (base %d, confirmed %d)", ErrConflict, base, s.st.Confirmed)
	}
	if s.st.Testing != nil {
		return nil, ErrBusy
	}
	next := s.st
	next.LastRevision++
	r := &Revision{Number: next.LastRevision, BaseRevision: base, Author: author, Message: msg, CreatedAt: s.now().UTC(), Config: raw}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(s.revPath(r.Number), b, 0o600); err != nil {
		return nil, err
	}
	if err := s.commit(next); err != nil {
		return nil, err
	}
	s.audit(Event{Action: "propose", Revision: r.Number, Author: author, Result: "ok"})
	return r, nil
}

// BeginTest marks rev as under test until deadline. It is persisted
// before the caller touches the system, so a crash during apply is
// recovered by rolling back.
func (s *Store) BeginTest(rev int, deadline time.Time, author string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Testing != nil {
		return ErrBusy
	}
	if _, err := os.Stat(s.revPath(rev)); err != nil {
		return fmt.Errorf("revision %d: %w", rev, err)
	}
	next := s.st
	next.Testing = &Testing{Revision: rev, StartedAt: s.now().UTC(), Deadline: deadline.UTC(), Author: author}
	if err := s.commit(next); err != nil {
		return err
	}
	s.audit(Event{Action: "apply", Revision: rev, Author: author, Result: "testing until " + deadline.UTC().Format(time.RFC3339)})
	return nil
}

// SetCheckpoint records the NetworkManager checkpoint of the revision under test.
func (s *Store) SetCheckpoint(rev int, cp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Testing == nil || s.st.Testing.Revision != rev {
		return ErrNotTesting
	}
	next := s.st
	t := *s.st.Testing
	t.Checkpoint = cp
	next.Testing = &t
	return s.commit(next)
}

// Confirm makes the revision under test the confirmed one.
func (s *Store) Confirm(rev int, author string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Testing == nil || s.st.Testing.Revision != rev {
		return ErrNotTesting
	}
	next := s.st
	next.Confirmed = rev
	next.Testing = nil
	if err := s.commit(next); err != nil {
		return err
	}
	s.audit(Event{Action: "confirm", Revision: rev, Author: author, Result: "ok"})
	return nil
}

// EndTest clears the revision under test without confirming it (rollback,
// failed apply or recovery). It is a no-op when nothing is under test.
func (s *Store) EndTest(action, author, reason string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Testing == nil {
		return 0, nil
	}
	rev := s.st.Testing.Revision
	next := s.st
	next.Testing = nil
	if err := s.commit(next); err != nil {
		return 0, err
	}
	s.audit(Event{Action: action, Revision: rev, Author: author, Result: reason})
	return rev, nil
}

// Audit appends an event (used by callers for apply results).
func (s *Store) Audit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit(e)
}

// History returns up to limit most recent events, newest last.
func (s *Store) History(limit int) ([]Event, error) {
	f, err := os.Open(filepath.Join(s.dir, "history.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil { // skip a torn last line
			all = append(all, e)
		}
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, sc.Err()
}

func (s *Store) commit(next State) error {
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, "state.json"), b, 0o600); err != nil {
		return err
	}
	s.st = next
	return nil
}

// audit is best effort: a failing audit write must not block a rollback.
func (s *Store) audit(e Event) {
	if e.Time.IsZero() {
		e.Time = s.now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "history.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err == nil {
		_ = f.Sync()
	}
}

func (s *Store) revPath(n int) string {
	return filepath.Join(s.dir, "revisions", strconv.Itoa(n)+".json")
}

// writeAtomic replaces path with data: temp file in the same directory,
// fsync, rename, fsync of the directory.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
