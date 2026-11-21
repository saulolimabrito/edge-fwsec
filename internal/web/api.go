package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/saulolimabrito/edge-fwsec/internal/agent"
	"github.com/saulolimabrito/edge-fwsec/internal/auth"
	"github.com/saulolimabrito/edge-fwsec/internal/backup"
	"github.com/saulolimabrito/edge-fwsec/internal/policy"
	"github.com/saulolimabrito/edge-fwsec/internal/version"
)

const maxBody = 2 << 20

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

type ctxKey struct{}

// sessionOf returns the authenticated session stored by requireAuth.
func sessionOf(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(ctxKey{}).(*auth.Session)
	return s
}

func clientIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return r.RemoteAddr
}

// requireAuth checks the session cookie; mutations additionally need the
// CSRF header and a same-origin request.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.CookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		ss, ok := s.Sessions.Get(c.Value)
		if !ok {
			auth.ClearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "session expired")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) || !auth.CheckCSRF(ss, r.Header.Get("X-CSRF-Token")) {
				writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
				return
			}
		}
		next(w, r.WithContext(contextWith(r, ss)))
	}
}

// sameOrigin rejects cross-site requests using Sec-Fetch-Site and Origin
// when the browser sends them.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host {
		return false
	}
	return true
}

// decode reads a strict JSON body.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/session", s.handleSession)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /api/v1/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("POST /api/v1/password", s.requireAuth(s.handlePassword))

	mux.HandleFunc("GET /api/v1/version", s.requireAuth(s.handleVersion))
	mux.HandleFunc("GET /api/v1/system", s.requireAuth(s.handleSystem))
	mux.HandleFunc("GET /api/v1/interfaces", s.requireAuth(s.handleInterfaces))

	mux.HandleFunc("GET /api/v1/policy/status", s.requireAuth(s.proxy(func(*http.Request) (*agent.Request, error) {
		return &agent.Request{Op: agent.OpStatus}, nil
	})))
	mux.HandleFunc("GET /api/v1/policy/history", s.requireAuth(s.proxy(func(r *http.Request) (*agent.Request, error) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if n <= 0 || n > 1000 {
			n = 100
		}
		return &agent.Request{Op: agent.OpHistory, Limit: n}, nil
	})))
	mux.HandleFunc("GET /api/v1/policy/revisions/{n}", s.requireAuth(s.proxy(func(r *http.Request) (*agent.Request, error) {
		n, err := strconv.Atoi(r.PathValue("n"))
		if err != nil || n <= 0 {
			return nil, errors.New("revision must be a positive number")
		}
		return &agent.Request{Op: agent.OpGet, Revision: n}, nil
	})))
	mux.HandleFunc("GET /api/v1/policy/config", s.requireAuth(s.handleConfig))
	mux.HandleFunc("POST /api/v1/policy/validate", s.requireAuth(s.configOp(agent.OpValidate)))
	mux.HandleFunc("POST /api/v1/policy/diff", s.requireAuth(s.configOp(agent.OpDiff)))
	mux.HandleFunc("POST /api/v1/policy/apply", s.requireAuth(s.handleApply))
	mux.HandleFunc("POST /api/v1/policy/confirm", s.requireAuth(s.proxy(func(r *http.Request) (*agent.Request, error) {
		var body struct {
			Revision int `json:"revision"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			return nil, err
		}
		return &agent.Request{Op: agent.OpConfirm, Revision: body.Revision, Author: sessionOf(r).User}, nil
	})))
	mux.HandleFunc("POST /api/v1/policy/rollback", s.requireAuth(s.proxy(func(r *http.Request) (*agent.Request, error) {
		return &agent.Request{Op: agent.OpRollback, Author: sessionOf(r).User}, nil
	})))

	mux.HandleFunc("GET /api/v1/backup", s.requireAuth(s.handleBackup))
	mux.HandleFunc("POST /api/v1/restore/preview", s.requireAuth(s.handleRestorePreview))

	mux.HandleFunc("GET /api/v1/tls", s.requireAuth(s.handleTLSInfo))
	mux.HandleFunc("POST /api/v1/tls", s.requireAuth(s.handleTLSUpload))
	mux.HandleFunc("DELETE /api/v1/tls", s.requireAuth(s.handleTLSRemove))
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	has, err := s.Accounts.HasUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "account store unavailable")
		return
	}
	out := map[string]any{
		"authenticated":     false,
		"needs_bootstrap":   !has,
		"bootstrap_pending": s.Accounts.BootstrapPending(),
	}
	if c, err := r.Cookie(auth.CookieName); err == nil {
		if ss, ok := s.Sessions.Get(c.Value); ok {
			out["authenticated"], out["user"], out["csrf"] = true, ss.User, ss.CSRF
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) limited(w http.ResponseWriter, r *http.Request, user string) bool {
	if d := s.Limiter.Allow(clientIP(r), user); d > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("too many attempts; retry in %ds", int(d.Seconds())+1))
		return true
	}
	return false
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user string) {
	ss := s.Sessions.Create(user, clientIP(r))
	s.Sessions.SetCookie(w, ss)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": user, "csrf": ss.CSRF})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "csrf", "cross-site login refused")
		return
	}
	var c credentials
	if !decode(w, r, &c) {
		return
	}
	if s.limited(w, r, c.Username) {
		return
	}
	if err := s.Accounts.Authenticate(c.Username, c.Password); err != nil {
		s.Limiter.Failure(c.Username)
		s.Log.Warn("login failed", "user", c.Username, "ip", clientIP(r))
		writeError(w, http.StatusUnauthorized, "bad_credentials", "invalid username or password")
		return
	}
	s.Limiter.Success(c.Username)
	s.Log.Info("login", "user", c.Username, "ip", clientIP(r))
	s.startSession(w, r, c.Username)
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	var body struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if s.limited(w, r, "bootstrap") {
		return
	}
	if err := s.Accounts.ConsumeBootstrap(body.Token, body.Username, body.Password); err != nil {
		s.Limiter.Failure("bootstrap")
		s.Log.Warn("bootstrap refused", "ip", clientIP(r), "err", err)
		writeError(w, http.StatusUnauthorized, "bootstrap_refused", err.Error())
		return
	}
	s.Limiter.Success("bootstrap")
	s.Sessions.DeleteUser(body.Username)
	s.Log.Info("administrator set through bootstrap credential", "user", body.Username, "ip", clientIP(r))
	s.startSession(w, r, body.Username)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.Sessions.Delete(sessionOf(r).ID)
	auth.ClearCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	user := sessionOf(r).User
	if s.limited(w, r, user) {
		return
	}
	if err := s.Accounts.Authenticate(user, body.Current); err != nil {
		s.Limiter.Failure(user)
		writeError(w, http.StatusUnauthorized, "bad_credentials", "current password is wrong")
		return
	}
	if err := s.Accounts.SetPassword(user, body.New); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "weak_password", err.Error())
		return
	}
	s.Sessions.DeleteUser(user)
	s.startSession(w, r, user)
}

var agentHTTP = map[string]int{
	agent.CodeBadRequest: http.StatusBadRequest,
	agent.CodeInvalid:    http.StatusUnprocessableEntity,
	agent.CodeConflict:   http.StatusConflict,
	agent.CodeBusy:       http.StatusConflict,
	agent.CodeNotTesting: http.StatusConflict,
	agent.CodeNotFound:   http.StatusNotFound,
	agent.CodeApply:      http.StatusBadGateway,
}

func (s *Server) callAgent(w http.ResponseWriter, r *http.Request, req *agent.Request) (*agent.Response, bool) {
	resp, err := s.Agent.Call(r.Context(), req)
	if err != nil {
		s.Log.Error("agent unreachable", "err", err)
		writeError(w, http.StatusServiceUnavailable, "agent_unavailable", "efw-agent is not reachable; use efwctl on the local console")
		return nil, false
	}
	if !resp.OK {
		code := agentHTTP[resp.Error.Code]
		if code == 0 {
			code = http.StatusInternalServerError
		}
		writeJSON(w, code, map[string]any{"error": resp.Error})
		return resp, false
	}
	return resp, true
}

func (s *Server) proxy(build func(*http.Request) (*agent.Request, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := build(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		if resp, ok := s.callAgent(w, r, req); ok {
			writeJSON(w, http.StatusOK, resp)
		}
	}
}

func (s *Server) configOp(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Config json.RawMessage `json:"config"`
		}
		if !decode(w, r, &body) {
			return
		}
		if resp, ok := s.callAgent(w, r, &agent.Request{Op: op, Config: body.Config}); ok {
			writeJSON(w, http.StatusOK, resp)
		}
	}
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config         json.RawMessage `json:"config"`
		BaseRevision   *int            `json:"base_revision"`
		TimeoutSeconds int             `json:"timeout_seconds"`
		Message        string          `json:"message"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.BaseRevision == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "base_revision is required")
		return
	}
	req := &agent.Request{Op: agent.OpApply, Config: body.Config, BaseRevision: body.BaseRevision,
		TimeoutSeconds: body.TimeoutSeconds, Message: body.Message, Author: sessionOf(r).User}
	if resp, ok := s.callAgent(w, r, req); ok {
		writeJSON(w, http.StatusOK, resp)
	}
}

// confirmed returns the confirmed revision number and configuration (nil
// before the first confirmation).
func (s *Server) confirmed(w http.ResponseWriter, r *http.Request) (int, *policy.Config, bool) {
	st, ok := s.callAgent(w, r, &agent.Request{Op: agent.OpStatus})
	if !ok {
		return 0, nil, false
	}
	n := st.Status.Confirmed
	if n == 0 {
		return 0, nil, true
	}
	g, ok := s.callAgent(w, r, &agent.Request{Op: agent.OpGet, Revision: n})
	if !ok {
		return 0, nil, false
	}
	c, err := policy.Decode(bytesReader(g.Config))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return 0, nil, false
	}
	return n, c, true
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	n, c, ok := s.confirmed(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": n, "config": c})
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	n, c, ok := s.confirmed(w, r)
	if !ok {
		return
	}
	if c == nil {
		writeError(w, http.StatusNotFound, "no_configuration", "there is no confirmed configuration to back up")
		return
	}
	b, err := backup.Export(c, n, sessionOf(r).User, version.Version, s.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	name := fmt.Sprintf("edge-fwsec-rev%d-%s.json", n, s.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(b)
}

func (s *Server) handleRestorePreview(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, backup.MaxBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "backup is larger than 1 MiB")
		return
	}
	c, info, err := backup.Import(b)
	if err != nil {
		var ps policy.Problems
		if errors.As(err, &ps) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{"code": "invalid_config", "message": "backup configuration is invalid", "problems": ps}})
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "invalid_backup", err.Error())
		return
	}
	raw, _ := c.Canonical()
	d, ok := s.callAgent(w, r, &agent.Request{Op: agent.OpDiff, Config: raw})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"info": info, "config": c, "diff": d.Diff})
}

func (s *Server) handleTLSInfo(w http.ResponseWriter, _ *http.Request) {
	if s.TLS == nil {
		writeError(w, http.StatusNotFound, "no_tls", "TLS is not managed by this server")
		return
	}
	writeJSON(w, http.StatusOK, s.TLS.Info())
}

func (s *Server) handleTLSUpload(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Certificate string `json:"certificate_pem"`
		Key         string `json:"key_pem"`
	}
	if !decode(w, r, &body) {
		return
	}
	if s.TLS == nil {
		writeError(w, http.StatusNotFound, "no_tls", "TLS is not managed by this server")
		return
	}
	if err := s.TLS.SetCustom([]byte(body.Certificate), []byte(body.Key)); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_certificate", err.Error())
		return
	}
	s.Log.Info("custom TLS certificate installed", "user", sessionOf(r).User)
	writeJSON(w, http.StatusOK, s.TLS.Info())
}

func (s *Server) handleTLSRemove(w http.ResponseWriter, r *http.Request) {
	if s.TLS == nil {
		writeError(w, http.StatusNotFound, "no_tls", "TLS is not managed by this server")
		return
	}
	if err := s.TLS.RemoveCustom(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.TLS.Info())
}
