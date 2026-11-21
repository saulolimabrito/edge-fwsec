package auth

import (
	"crypto/subtle"
	"net/http"
	"sync"
	"time"
)

// CookieName uses the __Host- prefix: Secure, Path=/, no Domain, so the
// cookie is bound to the exact origin the administrator connected to.
const CookieName = "__Host-efw_session"

// Session is one authenticated administrator session.
type Session struct {
	ID       string
	User     string
	CSRF     string
	Created  time.Time
	LastSeen time.Time
	RemoteIP string
}

// Sessions keeps sessions in memory: a web restart logs everyone out,
// which is acceptable for an appliance console.
type Sessions struct {
	Idle     time.Duration // default 15m
	Absolute time.Duration // default 8h
	Now      func() time.Time

	mu sync.Mutex
	m  map[string]*Session
}

func (s *Sessions) init() {
	if s.m == nil {
		s.m = map[string]*Session{}
	}
	if s.Idle == 0 {
		s.Idle = 15 * time.Minute
	}
	if s.Absolute == 0 {
		s.Absolute = 8 * time.Hour
	}
	if s.Now == nil {
		s.Now = time.Now
	}
}

// Create starts a session and returns it.
func (s *Sessions) Create(user, ip string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	now := s.Now()
	ss := &Session{ID: RandomToken(32), User: user, CSRF: RandomToken(32), Created: now, LastSeen: now, RemoteIP: ip}
	s.m[ss.ID] = ss
	s.gcLocked(now)
	return ss
}

// Get returns a live session and refreshes its idle timer.
func (s *Sessions) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	ss, ok := s.m[id]
	if !ok {
		return nil, false
	}
	now := s.Now()
	if now.Sub(ss.LastSeen) > s.Idle || now.Sub(ss.Created) > s.Absolute {
		delete(s.m, id)
		return nil, false
	}
	ss.LastSeen = now
	cp := *ss
	return &cp, true
}

// Delete ends a session.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	delete(s.m, id)
}

// DeleteUser ends every session of a user (password change/recovery).
func (s *Sessions) DeleteUser(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	for id, ss := range s.m {
		if ss.User == user {
			delete(s.m, id)
		}
	}
}

func (s *Sessions) gcLocked(now time.Time) {
	for id, ss := range s.m {
		if now.Sub(ss.LastSeen) > s.Idle || now.Sub(ss.Created) > s.Absolute {
			delete(s.m, id)
		}
	}
}

// SetCookie writes the session cookie.
func (s *Sessions) SetCookie(w http.ResponseWriter, ss *Session) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: ss.ID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.Absolute / time.Second)})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// CheckCSRF compares the request token with the session's in constant time.
func CheckCSRF(ss *Session, token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(ss.CSRF), []byte(token)) == 1
}
