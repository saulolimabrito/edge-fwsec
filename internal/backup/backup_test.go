package backup

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

func fixture(t *testing.T) *policy.Config {
	b, _ := os.ReadFile("../policy/testdata/edge.json")
	c, err := policy.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	c := fixture(t)
	b, err := Export(c, 7, "admin", "1.0.0", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"argon2", "PRIVATE KEY", "password", "csrf"} {
		if strings.Contains(strings.ToLower(string(b)), strings.ToLower(secret)) {
			t.Fatalf("backup contains %q", secret)
		}
	}
	got, info, err := Import(b)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.Canonical()
	g, _ := got.Canonical()
	if !bytes.Equal(a, g) || info.Revision != 7 || info.MigratedFrom != 0 {
		t.Fatal("round trip changed the configuration")
	}
}

// TestSchema1BackupStaysReadable pins a backup produced by schema 1. When
// the schema changes, this file must keep importing (through migrations).
func TestSchema1BackupStaysReadable(t *testing.T) {
	b, err := os.ReadFile("testdata/schema1-backup.json")
	if err != nil {
		t.Fatal(err)
	}
	c, info, err := Import(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.Revision != 3 || len(c.Firewall.Rules) == 0 {
		t.Fatalf("%+v", info)
	}
}

func TestRejects(t *testing.T) {
	good, _ := Export(fixture(t), 1, "a", "x", time.Now())
	mut := func(f func(m map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal(good, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := map[string][]byte{
		"newer schema":   mut(func(m map[string]any) { m["schema_version"] = 99 }),
		"format":         mut(func(m map[string]any) { m["format"] = "other" }),
		"format version": mut(func(m map[string]any) { m["format_version"] = 2 }),
		"unknown field":  mut(func(m map[string]any) { m["secrets"] = "x" }),
		"invalid config": mut(func(m map[string]any) {
			m["config"].(map[string]any)["admin"].(map[string]any)["interfaces"] = []any{}
		}),
		"too large": bytes.Repeat([]byte(" "), MaxBytes+1),
		"garbage":   []byte("{"),
	}
	for name, b := range cases {
		if _, _, err := Import(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	_, _, err := Import(cases["newer schema"])
	if err == nil || !strings.Contains(err.Error(), "upgrade Edge FWSec first") {
		t.Errorf("newer schema message: %v", err)
	}
}
