package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/fsutil"
)

var reUser = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,31}$`)

// ErrBadCredentials is returned for any login failure (no user enumeration).
var ErrBadCredentials = errors.New("invalid username or password")

// User is one administrator account.
type User struct {
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type usersFile struct {
	Users []User `json:"users"`
}

type bootstrapFile struct {
	TokenSHA256 string    `json:"token_sha256"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Accounts stores administrators and the bootstrap credential in the
// web state directory (0700, owned by the efw-web user).
type Accounts struct {
	dir   string
	mu    sync.Mutex
	now   func() time.Time
	dummy string // hash used to equalize timing for unknown users
}

// OpenAccounts prepares the state directory.
func OpenAccounts(dir string) (*Accounts, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	d, err := HashPassword(RandomToken(16))
	if err != nil {
		return nil, err
	}
	return &Accounts{dir: dir, now: time.Now, dummy: d}, nil
}

func (a *Accounts) load() (usersFile, error) {
	var u usersFile
	b, err := os.ReadFile(filepath.Join(a.dir, "users.json"))
	if errors.Is(err, os.ErrNotExist) {
		return u, nil
	}
	if err != nil {
		return u, err
	}
	if err := json.Unmarshal(b, &u); err != nil {
		return u, fmt.Errorf("users.json is corrupt: %w", err)
	}
	return u, nil
}

func (a *Accounts) save(u usersFile) error {
	b, _ := json.MarshalIndent(u, "", "  ")
	return fsutil.WriteAtomic(filepath.Join(a.dir, "users.json"), b, 0o600)
}

// HasUsers reports whether any administrator exists.
func (a *Accounts) HasUsers() (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, err := a.load()
	return len(u.Users) > 0, err
}

// Authenticate verifies credentials in roughly constant time whether or
// not the user exists.
func (a *Accounts) Authenticate(name, pw string) error {
	a.mu.Lock()
	u, err := a.load()
	a.mu.Unlock()
	if err != nil {
		return err
	}
	hash := a.dummy
	found := false
	for _, x := range u.Users {
		if x.Name == name {
			hash, found = x.Hash, true
		}
	}
	ok, err := VerifyPassword(hash, pw)
	if err != nil {
		return err
	}
	if !ok || !found {
		return ErrBadCredentials
	}
	return nil
}

// SetPassword creates or updates an administrator.
func (a *Accounts) SetPassword(name, pw string) error {
	if !reUser.MatchString(name) {
		return fmt.Errorf("username must match %s", reUser)
	}
	if err := CheckPasswordPolicy(name, pw); err != nil {
		return err
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	u, err := a.load()
	if err != nil {
		return err
	}
	now := a.now().UTC()
	for i := range u.Users {
		if u.Users[i].Name == name {
			u.Users[i].Hash, u.Users[i].UpdatedAt = h, now
			return a.save(u)
		}
	}
	u.Users = append(u.Users, User{Name: name, Hash: h, CreatedAt: now, UpdatedAt: now})
	return a.save(u)
}

// NewBootstrapToken writes a one-time credential valid for ttl and returns
// it for display on the local console. Grouped base32 for easy typing.
func NewBootstrapToken(dir string, ttl time.Duration, now time.Time) (string, error) {
	raw := make([]byte, 15) // 120 bits → exactly 24 base32 characters
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	var groups []string
	for i := 0; i < len(tok); i += 4 {
		groups = append(groups, tok[i:i+4])
	}
	token := strings.Join(groups, "-")
	sum := sha256.Sum256([]byte(normalizeToken(token)))
	b, _ := json.MarshalIndent(bootstrapFile{TokenSHA256: hex.EncodeToString(sum[:]), ExpiresAt: now.Add(ttl).UTC()}, "", "  ")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := fsutil.WriteAtomic(filepath.Join(dir, "bootstrap.json"), b, 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func normalizeToken(t string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(t))
}

// BootstrapPending reports whether an unexpired bootstrap credential exists.
func (a *Accounts) BootstrapPending() bool {
	_, err := a.readBootstrap()
	return err == nil
}

func (a *Accounts) readBootstrap() (bootstrapFile, error) {
	var bf bootstrapFile
	b, err := os.ReadFile(filepath.Join(a.dir, "bootstrap.json"))
	if err != nil {
		return bf, err
	}
	if err := json.Unmarshal(b, &bf); err != nil {
		return bf, err
	}
	if a.now().After(bf.ExpiresAt) {
		return bf, errors.New("bootstrap credential expired")
	}
	return bf, nil
}

// ConsumeBootstrap checks the one-time credential and, if valid, deletes
// it and sets the administrator's password. Used for first access and for
// console-initiated password recovery.
func (a *Accounts) ConsumeBootstrap(token, name, pw string) error {
	if !reUser.MatchString(name) {
		return fmt.Errorf("username must match %s", reUser)
	}
	if err := CheckPasswordPolicy(name, pw); err != nil {
		return err
	}
	a.mu.Lock()
	bf, err := a.readBootstrap()
	if err != nil {
		a.mu.Unlock()
		return errors.New("no valid bootstrap credential; run `efwctl bootstrap` on the local console")
	}
	sum := sha256.Sum256([]byte(normalizeToken(token)))
	want, _ := hex.DecodeString(bf.TokenSHA256)
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		a.mu.Unlock()
		return errors.New("bootstrap credential does not match")
	}
	// Single use: remove before creating the account.
	if err := os.Remove(filepath.Join(a.dir, "bootstrap.json")); err != nil {
		a.mu.Unlock()
		return err
	}
	a.mu.Unlock()
	return a.SetPassword(name, pw)
}
