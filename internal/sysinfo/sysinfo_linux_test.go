//go:build linux

package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichFromFakeSysfs(t *testing.T) {
	root := t.TempDir()
	sys, proc := filepath.Join(root, "sys"), filepath.Join(root, "proc")
	base := filepath.Join(sys, "class", "net", "eth0.20")
	write(t, filepath.Join(base, "operstate"), "up\n")
	write(t, filepath.Join(base, "uevent"), "DEVTYPE=vlan\nINTERFACE=eth0.20\n")
	write(t, filepath.Join(base, "statistics", "rx_bytes"), "1234\n")
	write(t, filepath.Join(base, "statistics", "tx_bytes"), "garbage\n")
	write(t, filepath.Join(proc, "net", "vlan", "eth0.20"),
		"eth0.20  VID: 20\t REORDER_HDR: 1  dev->priv_flags: 1021\nDevice: eth0\n")

	it := Interface{Name: "eth0.20"}
	Reader{SysRoot: sys, ProcRoot: proc}.enrich(&it)

	if it.OperState != "up" || it.Kind != "vlan" {
		t.Fatalf("state/kind = %q/%q", it.OperState, it.Kind)
	}
	if it.VLANID == nil || *it.VLANID != 20 || it.Parent != "eth0" {
		t.Fatalf("vlan = %v parent=%q", it.VLANID, it.Parent)
	}
	if it.Counters.RxBytes == nil || *it.Counters.RxBytes != 1234 {
		t.Fatalf("rx_bytes = %v", it.Counters.RxBytes)
	}
	if it.Counters.TxBytes != nil {
		t.Fatalf("unparseable counter must be nil, got %v", *it.Counters.TxBytes)
	}
	if it.Counters.RxPackets != nil {
		t.Fatal("missing counter must be nil")
	}
	if it.SpeedMbps != nil {
		t.Fatal("missing speed must be nil")
	}
}

func TestPhysicalDetection(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "class", "net", "enp1s0")
	write(t, filepath.Join(base, "device", "vendor"), "0x1af4\n")
	write(t, filepath.Join(base, "speed"), "-1\n")
	it := Interface{Name: "enp1s0"}
	Reader{SysRoot: root, ProcRoot: t.TempDir()}.enrich(&it)
	if it.Kind != "physical" {
		t.Fatalf("kind = %q", it.Kind)
	}
	if it.SpeedMbps != nil {
		t.Fatal("negative speed (unknown) must be nil")
	}
}

func TestParseAttrsRejectsMalformed(t *testing.T) {
	// length 2 (< header) must stop parsing, not loop or panic
	if got := parseAttrs([]byte{2, 0, 1, 0, 9, 9}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	// length beyond buffer
	if got := parseAttrs([]byte{40, 0, 1, 0}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	// valid "vlan\0" kind attribute (len 9, padded to 12)
	b := []byte{9, 0, 1, 0, 'v', 'l', 'a', 'n', 0, 0, 0, 0}
	got := parseAttrs(b)
	if len(got) != 1 || cstring(got[0].val) != "vlan" {
		t.Fatalf("got %v", got)
	}
}

func TestApplyLinksVLAN(t *testing.T) {
	ifs := []Interface{{Name: "eth0", Index: 2, Kind: "physical"}, {Name: "eth0.20", Index: 7, Kind: "virtual"}, {Name: "d0", Index: 8, Kind: "virtual"}}
	applyLinks(ifs, map[int]linkInfo{
		2: {vlanID: -1},
		7: {kind: "vlan", vlanID: 20, parentIndex: 2},
		8: {kind: "dummy", vlanID: -1},
	})
	if ifs[0].Kind != "physical" || ifs[1].Kind != "vlan" || *ifs[1].VLANID != 20 || ifs[1].Parent != "eth0" || ifs[2].Kind != "dummy" {
		t.Fatalf("%+v", ifs)
	}
}

func TestNetlinkLiveLoopback(t *testing.T) {
	links, err := netlinkLinks()
	if err != nil {
		t.Skipf("netlink unavailable: %v", err)
	}
	if len(links) == 0 {
		t.Fatal("rtnetlink returned no links")
	}
}
