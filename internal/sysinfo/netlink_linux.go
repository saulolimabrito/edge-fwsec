//go:build linux

package sysinfo

import (
	"encoding/binary"
	"syscall"
)

// linkInfo is what rtnetlink reports about an interface's driver kind.
// Unlike /proc/net/vlan (mode 0600), RTM_GETLINK works unprivileged.
type linkInfo struct {
	kind        string // IFLA_INFO_KIND, e.g. "vlan", "dummy", "bridge"
	vlanID      int    // -1 when not a VLAN
	parentIndex int    // IFLA_LINK, 0 when absent
}

const (
	iflaLink      = 5
	iflaLinkinfo  = 18
	iflaInfoKind  = 1
	iflaInfoData  = 2
	iflaVlanID    = 1
	nlaTypeMask   = 0x3fff
	nlaHeaderSize = 4
)

func netlinkLinks() (map[int]linkInfo, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	out := map[int]linkInfo{}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWLINK || len(m.Data) < syscall.SizeofIfInfomsg {
			continue
		}
		idx := int(int32(binary.NativeEndian.Uint32(m.Data[4:8])))
		li := linkInfo{vlanID: -1}
		for _, a := range parseAttrs(m.Data[syscall.SizeofIfInfomsg:]) {
			switch a.typ {
			case iflaLink:
				if len(a.val) >= 4 {
					li.parentIndex = int(binary.NativeEndian.Uint32(a.val))
				}
			case iflaLinkinfo:
				for _, n := range parseAttrs(a.val) {
					switch n.typ {
					case iflaInfoKind:
						li.kind = cstring(n.val)
					case iflaInfoData:
						for _, d := range parseAttrs(n.val) {
							if d.typ == iflaVlanID && len(d.val) >= 2 {
								li.vlanID = int(binary.NativeEndian.Uint16(d.val))
							}
						}
					}
				}
			}
		}
		if li.kind != "vlan" {
			li.vlanID = -1
		}
		out[idx] = li
	}
	return out, nil
}

type attr struct {
	typ uint16
	val []byte
}

// parseAttrs decodes a run of netlink attributes, stopping at the first
// malformed header instead of panicking.
func parseAttrs(b []byte) []attr {
	var res []attr
	for len(b) >= nlaHeaderSize {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		t := binary.NativeEndian.Uint16(b[2:4]) & nlaTypeMask
		if l < nlaHeaderSize || l > len(b) {
			break
		}
		res = append(res, attr{typ: t, val: b[nlaHeaderSize:l]})
		adv := (l + 3) &^ 3
		if adv > len(b) {
			break
		}
		b = b[adv:]
	}
	return res
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
