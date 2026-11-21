package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/agent"
	"github.com/saulolimabrito/edge-fwsec/internal/auth"
	"github.com/saulolimabrito/edge-fwsec/internal/store"
)

type nopNFT struct{}

func (nopNFT) Apply(context.Context, string) error { return nil }

// inProcAgent calls a real agent state machine without a socket.
type inProcAgent struct{ a *agent.Agent }

func (i inProcAgent) Call(ctx context.Context, req *agent.Request) (*agent.Response, error) {
	r := i.a.Handle(ctx, req, "uid=990,pid=1")
	return &r, nil
}

type denyAll struct{}

func (denyAll) Allowed(*http.Request) bool { return false }

type env struct {
	ts    *httptest.Server
	c     *http.Client
	token string
	csrf  string
	srv   *Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	acc, err := auth.OpenAccounts(dir + "/web")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := auth.NewBootstrapToken(dir+"/web", time.Hour, time.Now())
	st, err := store.Open(dir + "/agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ag := &agent.Agent{Store: st, NFT: nopNFT{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MinTimeout: time.Second}
	ag.Recover(context.Background())
	s := &Server{
		UI: fstest.MapFS{
			"index.html":    {Data: []byte("<!doctype html><title>efw</title>")},
			"assets/app.js": {Data: []byte("console.log(1)")},
		},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
		Accounts: acc, Sessions: &auth.Sessions{}, Limiter: &auth.Limiter{PerIP: 1000, FreeFailures: 3},
		Agent: inProcAgent{ag},
	}
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	return &env{ts: ts, c: c, token: tok, srv: s}
}

func (e *env) do(t *testing.T, method, path string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if b, ok := body.([]byte); ok {
		rd = bytes.NewReader(b)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if e.csrf != "" {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	if m == nil {
		m = map[string]any{"_raw": string(raw), "_disposition": res.Header.Get("Content-Disposition")}
	}
	return res.StatusCode, m
}

func (e *env) bootstrap(t *testing.T) {
	t.Helper()
	code, m := e.do(t, "POST", "/api/v1/bootstrap", map[string]string{"token": e.token, "username": "admin", "password": "a long enough passphrase"}, nil)
	if code != 200 {
		t.Fatalf("bootstrap %d %v", code, m)
	}
	e.csrf = m["csrf"].(string)
}

func edgeConfig(t *testing.T) json.RawMessage {
	b, err := os.ReadFile("../policy/testdata/edge.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAuthFlow(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.do(t, "GET", "/api/v1/interfaces", nil, nil); code != 401 {
		t.Fatalf("unauthenticated read: %d", code)
	}
	_, m := e.do(t, "GET", "/api/v1/session", nil, nil)
	if m["needs_bootstrap"] != true || m["bootstrap_pending"] != true || m["authenticated"] != false {
		t.Fatalf("session %v", m)
	}
	if code, _ := e.do(t, "POST", "/api/v1/bootstrap", map[string]string{"token": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", "username": "admin", "password": "a long enough passphrase"}, nil); code != 401 {
		t.Fatal("wrong bootstrap token accepted")
	}
	if code, _ := e.do(t, "POST", "/api/v1/bootstrap", map[string]string{"token": e.token, "username": "admin", "password": "short"}, nil); code != 401 {
		t.Fatal("weak password accepted")
	}
	e.bootstrap(t)
	if code, _ := e.do(t, "GET", "/api/v1/interfaces", nil, nil); code != 200 {
		t.Fatal("authenticated read failed")
	}
	if code, _ := e.do(t, "POST", "/api/v1/bootstrap", map[string]string{"token": e.token, "username": "evil", "password": "a long enough passphrase"}, nil); code != 401 {
		t.Fatal("bootstrap token reused")
	}
	// CSRF
	if code, _ := e.do(t, "POST", "/api/v1/policy/validate", map[string]any{"config": edgeConfig(t)}, map[string]string{"X-CSRF-Token": ""}); code != 403 {
		t.Fatal("mutation without CSRF accepted")
	}
	if code, _ := e.do(t, "POST", "/api/v1/policy/validate", map[string]any{"config": edgeConfig(t)}, map[string]string{"Origin": "https://evil.example"}); code != 403 {
		t.Fatal("cross-origin mutation accepted")
	}
	if code, _ := e.do(t, "POST", "/api/v1/policy/validate", map[string]any{"config": edgeConfig(t)}, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Fatal("cross-site mutation accepted")
	}
	if code, m := e.do(t, "POST", "/api/v1/policy/validate", map[string]any{"config": edgeConfig(t)}, nil); code != 200 {
		t.Fatalf("validate %d %v", code, m)
	}
	// logout invalidates the session
	e.do(t, "POST", "/api/v1/logout", nil, nil)
	if code, _ := e.do(t, "GET", "/api/v1/interfaces", nil, nil); code != 401 {
		t.Fatal("session survived logout")
	}
	// login
	if code, _ := e.do(t, "POST", "/api/v1/login", map[string]string{"username": "admin", "password": "wrong wrong wrong"}, nil); code != 401 {
		t.Fatal("bad login")
	}
	code, m := e.do(t, "POST", "/api/v1/login", map[string]string{"username": "admin", "password": "a long enough passphrase"}, nil)
	if code != 200 {
		t.Fatalf("login %d %v", code, m)
	}
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	var last int
	for i := 0; i < 5; i++ {
		last, _ = e.do(t, "POST", "/api/v1/login", map[string]string{"username": "admin", "password": "wrong wrong wrong"}, nil)
	}
	if last != 429 {
		t.Fatalf("no lockout after repeated failures: %d", last)
	}
	if code, _ := e.do(t, "POST", "/api/v1/login", map[string]string{"username": "admin", "password": "a long enough passphrase"}, nil); code != 429 {
		t.Fatal("correct password accepted during lockout")
	}
}

func TestPolicyLifecycleThroughAPI(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	_, m := e.do(t, "GET", "/api/v1/policy/config", nil, nil)
	if m["revision"].(float64) != 0 || m["config"] != nil {
		t.Fatalf("fresh config %v", m)
	}
	if code, m := e.do(t, "GET", "/api/v1/backup", nil, nil); code != 404 {
		t.Fatalf("backup without config: %d %v", code, m)
	}
	code, m := e.do(t, "POST", "/api/v1/policy/diff", map[string]any{"config": edgeConfig(t)}, nil)
	if code != 200 || !strings.Contains(m["diff"].(string), "efw:rule:lan-out") {
		t.Fatalf("diff %d", code)
	}
	code, m = e.do(t, "POST", "/api/v1/policy/apply", map[string]any{"config": edgeConfig(t), "base_revision": 0, "timeout_seconds": 60, "message": "first"}, nil)
	if code != 200 || m["revision"].(float64) != 1 {
		t.Fatalf("apply %d %v", code, m)
	}
	code, m = e.do(t, "POST", "/api/v1/policy/apply", map[string]any{"config": edgeConfig(t), "base_revision": 0}, nil)
	if code != 409 {
		t.Fatalf("second apply while testing must conflict: %d %v", code, m)
	}
	if code, _ := e.do(t, "POST", "/api/v1/policy/confirm", map[string]int{"revision": 1}, nil); code != 200 {
		t.Fatal("confirm")
	}
	_, m = e.do(t, "GET", "/api/v1/policy/history", nil, nil)
	hist, _ := json.Marshal(m)
	if !strings.Contains(string(hist), `"author":"admin via uid=990,pid=1"`) {
		t.Fatalf("author not recorded: %s", hist)
	}
	bad := bytes.Replace(edgeConfig(t), []byte(`"id": 30`), []byte(`"id": 5000`), 1)
	code, m = e.do(t, "POST", "/api/v1/policy/apply", map[string]any{"config": json.RawMessage(bad), "base_revision": 1}, nil)
	if code != 422 || !strings.Contains(mustJSON(m), "interfaces[2].vlan.id") {
		t.Fatalf("invalid apply %d %v", code, m)
	}
	// backup and restore preview
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/v1/backup", nil)
	res, err := e.c.Do(req)
	if err != nil || res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Disposition"), "edge-fwsec-rev1-") {
		t.Fatalf("backup %v %v", err, res.Header)
	}
	bk, _ := io.ReadAll(res.Body)
	res.Body.Close()
	code, m = e.do(t, "POST", "/api/v1/restore/preview", bk, nil)
	if code != 200 || m["diff"] != "" || m["info"].(map[string]any)["revision"].(float64) != 1 {
		t.Fatalf("restore preview %d %v", code, m)
	}
	newer := bytes.Replace(bk, []byte(`"schema_version": 1,`), []byte(`"schema_version": 9,`), 1)
	if code, m := e.do(t, "POST", "/api/v1/restore/preview", newer, nil); code != 422 || !strings.Contains(mustJSON(m), "newer than this build") {
		t.Fatalf("newer backup %d %v", code, m)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestAccessRestriction(t *testing.T) {
	e := newEnv(t)
	e.srv.Access = denyAll{}
	for _, p := range []string{"/", "/api/v1/session", "/assets/app.js"} {
		if code, _ := e.do(t, "GET", p, nil, nil); code != 403 {
			t.Errorf("%s served outside the management network: %d", p, code)
		}
	}
	if code, _ := e.do(t, "GET", "/healthz", nil, nil); code != 200 {
		t.Error("healthz must stay available for local probes")
	}
}

func TestHeadersSPAAndMethods(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.ts.URL+"/interfaces", nil)
	res, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "<title>efw</title>") {
		t.Fatal("spa fallback")
	}
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security"} {
		if res.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	if code, _ := e.do(t, "GET", "/api/v1/nope", nil, nil); code != 404 {
		t.Error("unknown api path")
	}
	if code, _ := e.do(t, "PUT", "/api/v1/interfaces", nil, nil); code != 405 {
		t.Error("wrong method")
	}
}
