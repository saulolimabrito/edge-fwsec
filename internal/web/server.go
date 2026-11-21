// Package web is the unprivileged HTTP front end. It never changes system
// state directly; in later stages mutations go to efw-agent over a Unix
// socket with a typed protocol.
package web

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
	"github.com/saulolimabrito/edge-fwsec/internal/version"
)

// Server wires API handlers and the embedded UI.
type Server struct {
	UI     fs.FS
	Reader sysinfo.Reader
	EtcDir string
	Log    *slog.Logger
	Now    func() time.Time
}

// Handler returns the root handler with security headers applied.
func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	mux.HandleFunc("GET /api/v1/system", s.handleSystem)
	mux.HandleFunc("GET /api/v1/interfaces", s.handleInterfaces)
	// Unmatched /api/ paths (and wrong methods on known ones) must not fall
	// through to the SPA; the API is read-only in stage 1.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	})
	mux.Handle("/", s.spa())
	return securityHeaders(mux)
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": version.Version, "commit": version.Commit, "date": version.Date,
	})
}

func (s *Server) handleSystem(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"system":      s.Reader.SystemInfo(s.EtcDir),
		"version":     version.Version,
		"observed_at": s.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, _ *http.Request) {
	ifs, err := s.Reader.Interfaces()
	if err != nil {
		s.Log.Error("read interfaces", "err", err)
		writeError(w, http.StatusInternalServerError, "interfaces_unavailable", "could not read interfaces")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"interfaces":  ifs,
		"observed_at": s.Now().UTC().Format(time.RFC3339),
	})
}

// spa serves static files and falls back to index.html for client routes.
func (s *Server) spa() http.Handler {
	files := http.FileServerFS(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" {
			if st, err := fs.Stat(s.UI, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		idx, err := fs.ReadFile(s.UI, "index.html")
		if err != nil {
			http.Error(w, "UI not built: run `make ui`", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(idx)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": kind, "message": msg}})
}
