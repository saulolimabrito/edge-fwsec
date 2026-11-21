package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/store"
)

type fakeNFT struct {
	mu      sync.Mutex
	scripts []string
	failOn  string // substring that makes Apply fail
}

func (f *fakeNFT) Apply(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && strings.Contains(s, f.failOn) {
		return errors.New("nft: simulated failure")
	}
	f.scripts = append(f.scripts, s)
	return nil
}

func (f *fakeNFT) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scripts) == 0 {
		return ""
	}
	return f.scripts[len(f.scripts)-1]
}

func edge(t *testing.T) json.RawMessage {
	b, err := os.ReadFile("../policy/testdata/edge.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newAgent(t *testing.T, dir string) (*Agent, *fakeNFT) {
	t.Helper()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f := &fakeNFT{}
	a := &Agent{Store: s, NFT: f, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MinTimeout: 10 * time.Millisecond, MaxTimeout: time.Minute, DefaultTimeout: time.Minute}
	return a, f
}

func intp(i int) *int { return &i }

func apply(a *Agent, cfg json.RawMessage, base int, timeout time.Duration) Response {
	return a.Handle(context.Background(), &Request{Op: OpApply, Config: cfg, BaseRevision: intp(base),
		TimeoutSeconds: int(timeout / time.Second)}, "test")
}

func TestApplyConfirm(t *testing.T) {
	a, f := newAgent(t, t.TempDir())
	if err := a.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.last(), "delete table inet efw_filter") || strings.Contains(f.last(), "chain") {
		t.Fatal("startup without confirmed revision must remove the project's tables only")
	}
	r := apply(a, edge(t), 0, 30*time.Second)
	if !r.OK || r.Revision != 1 || r.Deadline == nil || r.Status.Testing == nil {
		t.Fatalf("%+v %+v", r, r.Error)
	}
	if !strings.Contains(f.last(), "efw:rule:lan-out") {
		t.Fatal("ruleset not applied")
	}
	r = a.Handle(context.Background(), &Request{Op: OpConfirm, Revision: 1}, "test")
	if !r.OK || r.Status.Confirmed != 1 || r.Status.Testing != nil {
		t.Fatalf("%+v", r)
	}
	// stale base
	r = apply(a, edge(t), 0, 30*time.Second)
	if r.OK || r.Error.Code != CodeConflict {
		t.Fatalf("want conflict: %+v", r.Error)
	}
}

func TestDeadlineRollsBack(t *testing.T) {
	a, f := newAgent(t, t.TempDir())
	a.MinTimeout = 0
	a.Recover(context.Background())
	r := a.Handle(context.Background(), &Request{Op: OpApply, Config: edge(t), BaseRevision: intp(0)}, "t")
	if !r.OK {
		t.Fatal(r.Error)
	}
	a.mu.Lock()
	a.armLocked(r.Revision, 50*time.Millisecond) // shorten the window for the test
	a.mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	st := a.Store.State()
	if st.Testing != nil || st.Confirmed != 0 {
		t.Fatalf("deadline did not roll back: %+v", st)
	}
	if strings.Contains(f.last(), "chain") {
		t.Fatal("rollback must restore the confirmed (empty) policy")
	}
	h, _ := a.Store.History(0)
	found := false
	for _, e := range h {
		if e.Action == "rollback" && strings.Contains(e.Result, "deadline") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rollback not audited: %+v", h)
	}
}

func TestConfirmAfterDeadlineFails(t *testing.T) {
	a, _ := newAgent(t, t.TempDir())
	a.Recover(context.Background())
	r := apply(a, edge(t), 0, 30*time.Second)
	a.mu.Lock()
	a.rollbackLocked(context.Background(), "t", "deadline expired")
	a.mu.Unlock()
	r = a.Handle(context.Background(), &Request{Op: OpConfirm, Revision: r.Revision}, "t")
	if r.OK || r.Error.Code != CodeNotTesting {
		t.Fatalf("%+v", r)
	}
}

func TestFailedApplyRollsBack(t *testing.T) {
	a, f := newAgent(t, t.TempDir())
	a.Recover(context.Background())
	f.failOn = "efw:rule:lan-out"
	r := apply(a, edge(t), 0, 30*time.Second)
	if r.OK || r.Error.Code != CodeApply {
		t.Fatalf("%+v", r)
	}
	if st := a.Store.State(); st.Testing != nil {
		t.Fatalf("testing left set: %+v", st)
	}
}

func TestRestartDuringTestRecoversConfirmed(t *testing.T) {
	dir := t.TempDir()
	a, _ := newAgent(t, dir)
	a.Recover(context.Background())
	apply(a, edge(t), 0, 30*time.Second)
	a.Handle(context.Background(), &Request{Op: OpConfirm, Revision: 1}, "t")
	// second change under test, then the process "dies"
	var cfg map[string]any
	json.Unmarshal(edge(t), &cfg)
	fw := cfg["firewall"].(map[string]any)
	fw["rules"] = fw["rules"].([]any)[:1]
	b, _ := json.Marshal(cfg)
	if r := apply(a, b, 1, 30*time.Second); !r.OK {
		t.Fatal(r.Error)
	}
	a.mu.Lock()
	a.disarmLocked()
	a.mu.Unlock()
	a.Store.Close()

	a2, f2 := newAgent(t, dir)
	if err := a2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := a2.Store.State()
	if st.Testing != nil || st.Confirmed != 1 {
		t.Fatalf("%+v", st)
	}
	if !strings.Contains(f2.last(), "efw:rule:lan-out") {
		t.Fatal("confirmed revision 1 was not reapplied on startup")
	}
}

func TestShutdownRollsBack(t *testing.T) {
	a, _ := newAgent(t, t.TempDir())
	a.Recover(context.Background())
	apply(a, edge(t), 0, 30*time.Second)
	a.Shutdown(context.Background())
	if a.Store.State().Testing != nil {
		t.Fatal("shutdown left a revision under test")
	}
}

func TestInvalidConfigProblems(t *testing.T) {
	a, _ := newAgent(t, t.TempDir())
	bad := []byte(strings.Replace(string(edge(t)), `"id": 30`, `"id": 5000`, 1))
	r := a.Handle(context.Background(), &Request{Op: OpValidate, Config: bad}, "t")
	if r.OK || r.Error.Code != CodeInvalid || len(r.Error.Problems) == 0 || r.Error.Problems[0].Path != "interfaces[2].vlan.id" {
		t.Fatalf("%+v", r.Error)
	}
	r = apply(a, bad, 0, 30*time.Second)
	if r.OK || a.Store.State().LastRevision != 0 {
		t.Fatal("invalid config must not create a revision")
	}
}

func TestTimeoutBounds(t *testing.T) {
	a, _ := newAgent(t, t.TempDir())
	a.MinTimeout, a.MaxTimeout = 30*time.Second, time.Minute
	if r := apply(a, edge(t), 0, 5*time.Second); r.OK {
		t.Fatal("timeout below minimum accepted")
	}
	if r := apply(a, edge(t), 0, 2*time.Minute); r.OK {
		t.Fatal("timeout above maximum accepted")
	}
}

func TestDiff(t *testing.T) {
	a, _ := newAgent(t, t.TempDir())
	r := a.Handle(context.Background(), &Request{Op: OpDiff, Config: edge(t)}, "t")
	if !r.OK || r.Diff == nil || !strings.Contains(*r.Diff, "+ \t\tiifname \"lan0\" oifname \"wan0\"") {
		t.Fatalf("%+v", r)
	}
}

func TestDecodeRequestStrict(t *testing.T) {
	cases := map[string]string{
		`{"op":"status","config":{}}`:      "not accepted",
		`{"op":"reboot"}`:                  "unknown op",
		`{"op":"apply","config":{}}`:       "required",
		`{"op":"confirm"}`:                 "revision",
		`{"op":"status","shell":"id"}`:     "unknown field",
		`{"op":"rollback","author":"a b"}`: "author",
		`{"op":"status"}{"op":"status"}`:   "trailing",
		`{"op":"history","limit":5000}`:    "limit",
	}
	for in, want := range cases {
		_, err := DecodeRequest(strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v want %q", in, err, want)
		}
	}
	big := `{"op":"validate","config":"` + strings.Repeat("x", MaxRequestBytes) + `"}`
	if _, err := DecodeRequest(strings.NewReader(big)); err == nil {
		t.Error("oversized request accepted")
	}
	if _, err := DecodeRequest(strings.NewReader(`{"op":"status"}`)); err != nil {
		t.Error(err)
	}
}

func TestSocketRoundTripAndPermissions(t *testing.T) {
	dir, err := os.MkdirTemp("", "efw") // short path: sun_path is limited to 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	a, _ := newAgent(t, filepath.Join(dir, "state"))
	sock := filepath.Join(dir, "run", "agent.sock")
	ln, err := Listen(sock, "")
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(sock)
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx, ln)
	r, err := Call(ctx, sock, &Request{Op: OpStatus})
	if err != nil || !r.OK || r.Status == nil {
		t.Fatalf("%v %+v", err, r)
	}
	r, err = Call(ctx, sock, &Request{Op: OpConfirm})
	if err != nil || r.OK || r.Error.Code != CodeBadRequest {
		t.Fatalf("invalid request over socket: %v %+v", err, r)
	}
	// A regular file at the socket path is never deleted.
	reg := filepath.Join(dir, "regular")
	os.WriteFile(reg, []byte("x"), 0o600)
	if _, err := Listen(reg, ""); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
}
