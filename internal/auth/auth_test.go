package auth

import (
	"strings"
	"testing"
	"time"
)

func TestHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected format %s", h)
	}
	if ok, _ := VerifyPassword(h, "correct horse battery"); !ok {
		t.Fatal("good password rejected")
	}
	if ok, _ := VerifyPassword(h, "wrong"); ok {
		t.Fatal("bad password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$a$b", "$argon2id$v=19$m=99999999,t=2,p=1$AA$AA"} {
		if _, err := VerifyPassword(bad, "x"); err == nil {
			t.Errorf("accepted malformed hash %q", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("admin", "short") == nil {
		t.Error("short password accepted")
	}
	if CheckPasswordPolicy("operator", "myoperatorpassword") == nil {
		t.Error("password containing username accepted")
	}
	if err := CheckPasswordPolicy("admin", "a long enough passphrase"); err != nil {
		t.Error(err)
	}
}

func TestBootstrapIsSingleUseAndExpires(t *testing.T) {
	dir := t.TempDir()
	a, _ := OpenAccounts(dir)
	now := time.Now()
	tok, err := NewBootstrapToken(dir, time.Hour, now)
	if err != nil || len(tok) != 29 {
		t.Fatalf("token %q %v", tok, err)
	}
	if !a.BootstrapPending() {
		t.Fatal("pending")
	}
	if err := a.ConsumeBootstrap("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", "admin", "a long enough passphrase"); err == nil {
		t.Fatal("wrong token accepted")
	}
	// lower case and without dashes is accepted (typing on a console)
	if err := a.ConsumeBootstrap(strings.ToLower(strings.ReplaceAll(tok, "-", "")), "admin", "a long enough passphrase"); err != nil {
		t.Fatal(err)
	}
	if a.BootstrapPending() {
		t.Fatal("token must be single use")
	}
	if err := a.ConsumeBootstrap(tok, "admin2", "a long enough passphrase"); err == nil {
		t.Fatal("reused token accepted")
	}
	if err := a.Authenticate("admin", "a long enough passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate("admin", "nope nope nope"); err != ErrBadCredentials {
		t.Fatal("bad password")
	}
	if err := a.Authenticate("ghost", "a long enough passphrase"); err != ErrBadCredentials {
		t.Fatal("unknown user must look like a bad password")
	}
	tok2, _ := NewBootstrapToken(dir, time.Hour, now.Add(-2*time.Hour))
	if a.BootstrapPending() || a.ConsumeBootstrap(tok2, "admin", "a long enough passphrase") == nil {
		t.Fatal("expired token accepted")
	}
}

func TestSessionsExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &Sessions{Idle: time.Minute, Absolute: time.Hour, Now: func() time.Time { return now }}
	ss := s.Create("admin", "10.0.0.1")
	if len(ss.ID) < 40 || ss.CSRF == ss.ID {
		t.Fatal("weak ids")
	}
	now = now.Add(50 * time.Second)
	if _, ok := s.Get(ss.ID); !ok {
		t.Fatal("active session dropped")
	}
	now = now.Add(61 * time.Second)
	if _, ok := s.Get(ss.ID); ok {
		t.Fatal("idle session kept")
	}
	ss = s.Create("admin", "x")
	for i := 0; i < 70; i++ {
		now = now.Add(55 * time.Second)
		s.Get(ss.ID)
	}
	if _, ok := s.Get(ss.ID); ok {
		t.Fatal("absolute lifetime ignored")
	}
	ss = s.Create("admin", "x")
	if !CheckCSRF(ss, ss.CSRF) || CheckCSRF(ss, "") || CheckCSRF(ss, "x") {
		t.Fatal("csrf check")
	}
	s.DeleteUser("admin")
	if _, ok := s.Get(ss.ID); ok {
		t.Fatal("DeleteUser")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := &Limiter{PerIP: 3, Window: time.Minute, FreeFailures: 2, MaxLockout: 2 * time.Minute, Now: func() time.Time { return now }}
	for i := 0; i < 3; i++ {
		if l.Allow("1.1.1.1", "u"+string(rune('a'+i))) != 0 {
			t.Fatal("early block")
		}
	}
	if l.Allow("1.1.1.1", "x") == 0 {
		t.Fatal("per-IP limit not enforced")
	}
	now = now.Add(61 * time.Second)
	if l.Allow("1.1.1.1", "x") != 0 {
		t.Fatal("window did not slide")
	}
	l.Failure("bob")
	l.Failure("bob")
	if d := l.Allow("2.2.2.2", "bob"); d != 30*time.Second {
		t.Fatalf("lockout %v", d)
	}
	now = now.Add(31 * time.Second)
	l.Failure("bob")
	if d := l.Allow("3.3.3.3", "bob"); d != time.Minute {
		t.Fatalf("lockout must double: %v", d)
	}
	for i := 0; i < 10; i++ {
		l.Failure("bob")
	}
	if d := l.Allow("4.4.4.4", "bob"); d != 2*time.Minute {
		t.Fatalf("lockout must cap: %v", d)
	}
	l.Success("bob")
	if l.Allow("5.5.5.5", "bob") != 0 {
		t.Fatal("success must reset")
	}
}
