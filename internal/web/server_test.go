package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func newTestServer() *httptest.Server {
	s := &Server{
		UI: fstest.MapFS{
			"index.html":    {Data: []byte("<!doctype html><title>efw</title>")},
			"assets/app.js": {Data: []byte("console.log(1)")},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
	}
	return httptest.NewServer(s.Handler())
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestInterfacesEndpoint(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	res, body := get(t, ts.URL+"/api/v1/interfaces")
	if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d headers %v", res.StatusCode, res.Header)
	}
	var v struct {
		Interfaces []map[string]any `json:"interfaces"`
		ObservedAt string           `json:"observed_at"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Interfaces) == 0 || v.ObservedAt != "2026-11-21T12:00:00Z" {
		t.Fatalf("%+v", v)
	}
}

func TestSecurityHeadersAndSPAFallback(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	res, body := get(t, ts.URL+"/interfaces")
	if res.StatusCode != 200 || !strings.Contains(body, "<title>efw</title>") {
		t.Fatalf("spa fallback: %d %q", res.StatusCode, body)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if res.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	res, _ = get(t, ts.URL+"/assets/app.js")
	if !strings.Contains(res.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("assets should be immutable-cached")
	}
}

func TestUnknownAPIAndMethods(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	res, body := get(t, ts.URL+"/api/v1/nope")
	if res.StatusCode != 404 || !strings.Contains(body, "not_found") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	r, err := http.Post(ts.URL+"/api/v1/interfaces", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST on read-only endpoint: %d", r.StatusCode)
	}
	r, _ = http.Post(ts.URL+"/", "text/plain", nil)
	r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST on static: %d", r.StatusCode)
	}
}
