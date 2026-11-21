// Package sysinfo reads real interface state from the running kernel.
//
// It never fabricates values: a counter that cannot be read is reported as
// absent (nil) so the UI can show "unavailable" instead of a made-up zero.
package sysinfo

import (
	"net"
	"sort"
)

// Address is a single IP address assigned to an interface.
type Address struct {
	Family string `json:"family"` // "ipv4" | "ipv6"
	CIDR   string `json:"cidr"`
	Scope  string `json:"scope"` // "global" | "link" | "host"
}

// Counters are kernel interface statistics. Fields are pointers so a value
// the platform does not expose is serialised as null.
type Counters struct {
	RxBytes   *uint64 `json:"rx_bytes"`
	TxBytes   *uint64 `json:"tx_bytes"`
	RxPackets *uint64 `json:"rx_packets"`
	TxPackets *uint64 `json:"tx_packets"`
	RxErrors  *uint64 `json:"rx_errors"`
	TxErrors  *uint64 `json:"tx_errors"`
	RxDropped *uint64 `json:"rx_dropped"`
	TxDropped *uint64 `json:"tx_dropped"`
}

// Interface describes one network interface as seen by the kernel.
type Interface struct {
	Name      string    `json:"name"`
	Index     int       `json:"index"`
	MAC       string    `json:"mac"`
	MTU       int       `json:"mtu"`
	AdminUp   bool      `json:"admin_up"`
	OperState string    `json:"oper_state"` // up, down, dormant, unknown, ...
	Kind      string    `json:"kind"`       // physical, vlan, loopback, virtual, bridge, unknown
	VLANID    *int      `json:"vlan_id"`
	Parent    string    `json:"parent,omitempty"`
	SpeedMbps *int64    `json:"speed_mbps"`
	Addresses []Address `json:"addresses"`
	Counters  Counters  `json:"counters"`
}

// Reader collects interface information. Root allows tests to point the
// Linux implementation at a fake sysfs/procfs tree.
type Reader struct {
	SysRoot  string // default "/sys"
	ProcRoot string // default "/proc"
}

// Interfaces returns every interface sorted by kernel index.
func (r Reader) Interfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, ni := range ifs {
		it := Interface{
			Name:      ni.Name,
			Index:     ni.Index,
			MAC:       ni.HardwareAddr.String(),
			MTU:       ni.MTU,
			AdminUp:   ni.Flags&net.FlagUp != 0,
			OperState: "unknown",
			Kind:      "unknown",
			Addresses: []Address{},
		}
		if ni.Flags&net.FlagLoopback != 0 {
			it.Kind = "loopback"
		}
		if addrs, err := ni.Addrs(); err == nil {
			it.Addresses = convertAddrs(addrs)
		}
		r.enrich(&it)
		out = append(out, it)
	}
	r.overlay(out)
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func convertAddrs(addrs []net.Addr) []Address {
	res := make([]Address, 0, len(addrs))
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		fam := "ipv6"
		if ipn.IP.To4() != nil {
			fam = "ipv4"
		}
		res = append(res, Address{Family: fam, CIDR: ipn.String(), Scope: scopeOf(ipn.IP)})
	}
	return res
}

func scopeOf(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "host"
	case ip.IsLinkLocalUnicast():
		return "link"
	default:
		return "global"
	}
}
