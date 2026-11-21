package nft

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

func fixture(t *testing.T) *policy.Config {
	t.Helper()
	b, err := os.ReadFile("../policy/testdata/edge.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGoldenEdge(t *testing.T) {
	got, err := Render(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/edge.nft"
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("render differs from %s (run go test ./internal/nft -update and review the diff)\n%s", golden, got)
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, _ := Render(fixture(t))
	b, _ := Render(fixture(t))
	if a != b {
		t.Fatal("render is not deterministic")
	}
}

func TestRenderRefusesInvalid(t *testing.T) {
	c := fixture(t)
	c.Firewall.Rules[0].Service = "nope"
	if _, err := Render(c); err == nil {
		t.Fatal("invalid config must not render")
	}
}

func TestOnlyOwnedTables(t *testing.T) {
	s, _ := Render(fixture(t))
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "flush ruleset") {
			t.Fatal("must never flush the whole ruleset")
		}
		if strings.HasPrefix(l, "table ") || strings.HasPrefix(l, "delete table ") {
			if !strings.Contains(l, " "+FilterTable) && !strings.Contains(l, " "+NATTable) {
				t.Fatalf("touches a table the project does not own: %q", l)
			}
		}
	}
}

func TestDisabledAndDefaultReject(t *testing.T) {
	c := fixture(t)
	c.Firewall.Rules[2].Disabled = true
	c.NAT.PortForwards[0].Disabled = true
	c.Firewall.DefaultForward = "reject"
	c.Firewall.LogDefault = false
	s, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"efw:rule:lan-out", "efw:pf:web-in", "efw:default-log"} {
		if strings.Contains(s, bad) {
			t.Errorf("unexpected %s", bad)
		}
	}
	if !strings.Contains(s, `reject with icmpx admin-prohibited comment "efw:default-reject"`) {
		t.Error("missing default reject")
	}
}

func TestPrefixAndPortSets(t *testing.T) {
	ps := []string{"10.0.0.0/8", "10.1.0.0/16", "192.0.2.7/32", "2001:db8::/32"}
	pp := mustPrefixes(t, ps)
	if got := prefixSet(pp, "ipv4"); got != "{ 10.0.0.0/8, 192.0.2.7 }" {
		t.Errorf("v4 set %q", got)
	}
	if got := prefixSet(pp, "ipv6"); got != "2001:db8::/32" {
		t.Errorf("v6 set %q", got)
	}
	got := portSet([]policy.PortRange{{From: 443, To: 443}, {From: 80, To: 80}, {From: 8000, To: 8010}, {From: 8005, To: 8020}, {From: 81, To: 81}})
	if got != "{ 80-81, 443, 8000-8020 }" {
		t.Errorf("ports %q", got)
	}
}
