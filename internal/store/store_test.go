package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

func cfg(t *testing.T) *policy.Config {
	t.Helper()
	b, err := os.ReadFile("../policy/testdata/edge.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLifecycleAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := s.Propose(cfg(t), 0, "alice", "initial")
	if err != nil || r1.Number != 1 {
		t.Fatalf("propose: %v %+v", err, r1)
	}
	if _, err := s.Propose(cfg(t), 0, "bob", ""); err != nil {
		t.Fatalf("second draft on same base is allowed: %v", err)
	}
	dl := time.Now().Add(time.Minute)
	if err := s.BeginTest(1, dl, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTest(2, dl, "bob"); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	if _, err := s.Propose(cfg(t), 0, "bob", ""); !errors.Is(err, ErrBusy) {
		t.Fatalf("propose while testing: %v", err)
	}
	if err := s.Confirm(2, "bob"); !errors.Is(err, ErrNotTesting) {
		t.Fatalf("confirm wrong rev: %v", err)
	}
	if err := s.Confirm(1, "alice"); err != nil {
		t.Fatal(err)
	}
	// stale base now conflicts
	if _, err := s.Propose(cfg(t), 0, "bob", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	st := s2.State()
	if st.Confirmed != 1 || st.Testing != nil || st.LastRevision != 2 {
		t.Fatalf("state after reopen: %+v", st)
	}
	r, err := s2.Get(1)
	if err != nil || r.Author != "alice" {
		t.Fatalf("get: %v %+v", err, r)
	}
	if _, err := r.Decode(); err != nil {
		t.Fatal(err)
	}
	h, _ := s2.History(0)
	var acts []string
	for _, e := range h {
		acts = append(acts, e.Action)
	}
	if strings.Join(acts, ",") != "propose,propose,apply,confirm" {
		t.Fatalf("history %v", acts)
	}
}

func TestTestingSurvivesReopenAndEndTest(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Propose(cfg(t), 0, "a", "")
	s.BeginTest(1, time.Now().Add(time.Hour), "a")
	s.Close() // simulates a crash while testing
	s2, _ := Open(dir)
	defer s2.Close()
	st := s2.State()
	if st.Testing == nil || st.Testing.Revision != 1 {
		t.Fatalf("testing lost: %+v", st)
	}
	rev, err := s2.EndTest("recover", "agent", "agent restarted during test")
	if err != nil || rev != 1 || s2.State().Testing != nil || s2.State().Confirmed != 0 {
		t.Fatalf("endtest: %d %v %+v", rev, err, s2.State())
	}
	if rev, _ := s2.EndTest("rollback", "x", ""); rev != 0 {
		t.Fatal("EndTest without testing must be a no-op")
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	c := cfg(t)
	c.Admin.Interfaces = nil
	if _, err := s.Propose(c, 0, "a", ""); err == nil {
		t.Fatal("invalid config stored")
	}
	if s.State().LastRevision != 0 {
		t.Fatal("revision counter advanced on invalid config")
	}
}

func TestExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open: %v", err)
	}
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	s2.Close()
}

func TestPermissionsAndNoTempLeftovers(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.Propose(cfg(t), 0, "a", "")
	s.Close()
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	for _, p := range []string{"state.json", "revisions/1.json", "history.jsonl"} {
		fi, err := os.Stat(filepath.Join(dir, p))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, err, fi)
		}
	}
	m, _ := filepath.Glob(filepath.Join(dir, "*", ".*tmp-*"))
	m2, _ := filepath.Glob(filepath.Join(dir, ".*tmp-*"))
	if len(m)+len(m2) > 0 {
		t.Fatalf("temp files left: %v %v", m, m2)
	}
}

func TestCorruptStateIsAnErrorNotAReset(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "state.json"), []byte("{trunc"), 0o600)
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt state must not be silently reset: %v", err)
	}
}

func TestTornHistoryLineIgnored(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	defer s.Close()
	s.Propose(cfg(t), 0, "a", "")
	f, _ := os.OpenFile(filepath.Join(dir, "history.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"time":"2026`)
	f.Close()
	h, err := s.History(10)
	if err != nil || len(h) != 1 {
		t.Fatalf("%v %v", h, err)
	}
}
