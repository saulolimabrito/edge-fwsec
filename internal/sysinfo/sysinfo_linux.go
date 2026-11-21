//go:build linux

package sysinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (r Reader) sys() string {
	if r.SysRoot == "" {
		return "/sys"
	}
	return r.SysRoot
}

func (r Reader) proc() string {
	if r.ProcRoot == "" {
		return "/proc"
	}
	return r.ProcRoot
}

// enrich fills kernel-only details from sysfs and /proc/net/vlan.
func (r Reader) enrich(it *Interface) {
	r.enrichFromSys(it)
}

// applyLinks overlays rtnetlink kind/VLAN data, which is authoritative and
// readable without privileges, onto the sysfs-derived view.
func applyLinks(ifs []Interface, links map[int]linkInfo) {
	names := make(map[int]string, len(ifs))
	for _, it := range ifs {
		names[it.Index] = it.Name
	}
	for i := range ifs {
		li, ok := links[ifs[i].Index]
		if !ok {
			continue
		}
		switch li.kind {
		case "":
			// physical NICs and loopback carry no IFLA_INFO_KIND; keep sysfs view
		case "vlan":
			ifs[i].Kind = "vlan"
			if li.vlanID >= 0 {
				id := li.vlanID
				ifs[i].VLANID = &id
			}
			if p, ok := names[li.parentIndex]; ok {
				ifs[i].Parent = p
			}
		default:
			ifs[i].Kind = li.kind
		}
	}
}

func (r Reader) overlay(ifs []Interface) {
	if r.SysRoot != "" { // tests using a fake sysfs must not mix in the host
		return
	}
	if links, err := netlinkLinks(); err == nil {
		applyLinks(ifs, links)
	}
}

func (r Reader) enrichFromSys(it *Interface) {
	base := filepath.Join(r.sys(), "class", "net", it.Name)
	if s, ok := readString(filepath.Join(base, "operstate")); ok {
		it.OperState = s
	}
	if v, ok := readInt(filepath.Join(base, "speed")); ok && v > 0 {
		it.SpeedMbps = &v
	}
	it.Kind = r.kind(base, it)
	st := filepath.Join(base, "statistics")
	it.Counters = Counters{
		RxBytes:   readU64(filepath.Join(st, "rx_bytes")),
		TxBytes:   readU64(filepath.Join(st, "tx_bytes")),
		RxPackets: readU64(filepath.Join(st, "rx_packets")),
		TxPackets: readU64(filepath.Join(st, "tx_packets")),
		RxErrors:  readU64(filepath.Join(st, "rx_errors")),
		TxErrors:  readU64(filepath.Join(st, "tx_errors")),
		RxDropped: readU64(filepath.Join(st, "rx_dropped")),
		TxDropped: readU64(filepath.Join(st, "tx_dropped")),
	}
	if it.Kind == "vlan" {
		if id, parent, ok := r.vlanInfo(it.Name); ok {
			it.VLANID = &id
			it.Parent = parent
		}
	}
}

func (r Reader) kind(base string, it *Interface) string {
	if it.Kind == "loopback" {
		return "loopback"
	}
	if s, ok := readString(filepath.Join(base, "uevent")); ok {
		for _, line := range strings.Split(s, "\n") {
			if v, found := strings.CutPrefix(line, "DEVTYPE="); found {
				switch v {
				case "vlan", "bridge", "bond", "wlan":
					return v
				}
			}
		}
	}
	if _, err := os.Stat(filepath.Join(base, "device")); err == nil {
		return "physical"
	}
	return "virtual"
}

// vlanInfo parses /proc/net/vlan/<name>: "<name>  VID: <id>  REORDER_HDR: ..."
// and "Device: <parent>".
func (r Reader) vlanInfo(name string) (int, string, bool) {
	s, ok := readString(filepath.Join(r.proc(), "net", "vlan", name))
	if !ok {
		return 0, "", false
	}
	var id = -1
	var parent string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "VID:":
				if v, err := strconv.Atoi(f[i+1]); err == nil {
					id = v
				}
			case "Device:":
				parent = f[i+1]
			}
		}
	}
	return id, parent, id >= 0
}

func readString(p string) (string, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func readInt(p string) (int64, bool) {
	s, ok := readString(p)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

func readU64(p string) *uint64 {
	s, ok := readString(p)
	if !ok {
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}
