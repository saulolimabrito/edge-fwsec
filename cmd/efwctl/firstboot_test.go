package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
)

func iface(name, kind string, cidrs ...string) sysinfo.Interface {
	it := sysinfo.Interface{Name: name, Kind: kind}
	for _, c := range cidrs {
		fam, scope := "ipv4", "global"
		if strings.Contains(c, ":") {
			fam = "ipv6"
			if strings.HasPrefix(c, "fe80") {
				scope = "link"
			}
		}
		it.Addresses = append(it.Addresses, sysinfo.Address{Family: fam, CIDR: c, Scope: scope})
	}
	return it
}

func TestChooseMgmt(t *testing.T) {
	ifs := []sysinfo.Interface{
		iface("lo", "loopback", "127.0.0.1/8"),
		iface("enp2s0", "physical"),
		iface("enp1s0", "physical", "fe80::1/64", "192.0.2.10/24"),
		iface("enp3s0", "physical", "2001:db8::5/64"),
	}
	cases := []struct{ want, def, dev, addr string }{
		{"", "enp1s0", "enp1s0", "192.0.2.10"},
		{"", "", "enp1s0", "192.0.2.10"},              // first physical with a global address
		{"enp3s0", "enp1s0", "enp3s0", "2001:db8::5"}, // explicit wins
		{"", "missing0", "enp1s0", "192.0.2.10"},
	}
	for _, c := range cases {
		dev, addr, err := chooseMgmt(ifs, c.want, c.def)
		if err != nil || dev != c.dev || addr.String() != c.addr {
			t.Errorf("%+v: got %s %s %v", c, dev, addr, err)
		}
	}
	if _, _, err := chooseMgmt(ifs, "nope0", ""); err == nil {
		t.Error("unknown explicit interface accepted")
	}
	dev, addr, err := chooseMgmt([]sysinfo.Interface{iface("enp9s0", "physical")}, "", "")
	if err != nil || dev != "enp9s0" || addr.IsValid() {
		t.Errorf("no-address fallback: %s %s %v", dev, addr, err)
	}
	if _, _, err := chooseMgmt([]sysinfo.Interface{iface("lo", "loopback")}, "", ""); err == nil {
		t.Error("loopback-only system must fail")
	}
}

func TestFirstbootWritesOnceAndIssuesCredential(t *testing.T) {
	etc, web := t.TempDir(), t.TempDir()
	t.Setenv("EFW_WEB_STATE_DIR", web)
	live, err := sysinfo.Reader{}.Interfaces()
	if err != nil || len(live) == 0 {
		t.Skip("no interfaces")
	}
	dev := live[0].Name // any existing device (lo on Linux, lo0 on macOS)
	if rc := firstbootCmd([]string{"--etc-dir", etc, "--mgmt-interface", dev}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	b, err := os.ReadFile(filepath.Join(etc, "edge-fwsec", "web.env"))
	if err != nil || !strings.Contains(string(b), "EFW_BOOTSTRAP_INTERFACES="+dev+"\n") {
		t.Fatalf("web.env: %q %v", b, err)
	}
	issue, err := os.ReadFile(filepath.Join(etc, "issue.d", "50-edge-fwsec.issue"))
	if err != nil || !strings.Contains(string(issue), "One-time administrator credential") {
		t.Fatalf("issue: %q %v", issue, err)
	}
	fi, _ := os.Stat(filepath.Join(etc, "issue.d", "50-edge-fwsec.issue"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("issue file mode %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(web, "bootstrap.json")); err != nil {
		t.Fatal("no bootstrap credential stored")
	}
	// Second run: keeps the existing preparation.
	os.WriteFile(filepath.Join(etc, "edge-fwsec", "web.env"), []byte("EFW_BOOTSTRAP_INTERFACES=keep0\n"), 0o644)
	if rc := firstbootCmd([]string{"--etc-dir", etc, "--mgmt-interface", dev}); rc != 0 {
		t.Fatal(rc)
	}
	b, _ = os.ReadFile(filepath.Join(etc, "edge-fwsec", "web.env"))
	if !strings.Contains(string(b), "keep0") {
		t.Fatal("existing web.env overwritten")
	}
}
