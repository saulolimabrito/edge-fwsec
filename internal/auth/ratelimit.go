package auth

import (
	"sync"
	"time"
)

// Limiter throttles login attempts per client address and per username.
//
// Per address: at most PerIP attempts in Window. Per username: after
// FreeFailures consecutive failures, a lockout that doubles each further
// failure (30s, 60s, ...) up to MaxLockout. A success resets the user.
type Limiter struct {
	PerIP        int           // default 10
	Window       time.Duration // default 5m
	FreeFailures int           // default 5
	MaxLockout   time.Duration // default 15m
	Now          func() time.Time

	mu    sync.Mutex
	ips   map[string][]time.Time
	users map[string]*userState
}

type userState struct {
	failures int
	until    time.Time
}

func (l *Limiter) init() {
	if l.ips == nil {
		l.ips, l.users = map[string][]time.Time{}, map[string]*userState{}
	}
	if l.PerIP == 0 {
		l.PerIP = 10
	}
	if l.Window == 0 {
		l.Window = 5 * time.Minute
	}
	if l.FreeFailures == 0 {
		l.FreeFailures = 5
	}
	if l.MaxLockout == 0 {
		l.MaxLockout = 15 * time.Minute
	}
	if l.Now == nil {
		l.Now = time.Now
	}
}

// Allow records an attempt and returns how long the caller must wait
// (0 = allowed).
func (l *Limiter) Allow(ip, user string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	now := l.Now()
	var recent []time.Time
	for _, t := range l.ips[ip] {
		if now.Sub(t) < l.Window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.PerIP {
		l.ips[ip] = recent
		return recent[0].Add(l.Window).Sub(now)
	}
	if u := l.users[user]; u != nil && now.Before(u.until) {
		return u.until.Sub(now)
	}
	l.ips[ip] = append(recent, now)
	return 0
}

// Failure records a failed login for user.
func (l *Limiter) Failure(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	u := l.users[user]
	if u == nil {
		u = &userState{}
		l.users[user] = u
	}
	u.failures++
	if over := u.failures - l.FreeFailures; over >= 0 {
		d := 30 * time.Second << min(over, 10)
		u.until = l.Now().Add(min(d, l.MaxLockout))
	}
}

// Success clears the user's failure history.
func (l *Limiter) Success(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	delete(l.users, user)
}
