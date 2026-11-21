// Package nm turns the policy model into NetworkManager connection profiles
// and applies them with checkpoints, over D-Bus.
//
// Ownership: a profile belongs to Edge FWSec when its id starts with
// "efw-" and its UUID is the name-based UUID derived from that id (see
// ProfileUUID). Other profiles are never modified or deleted.
package nm

import (
	"crypto/sha1"
	"fmt"
	"net/netip"
	"strings"

	"github.com/godbus/dbus/v5"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

// IDPrefix marks Edge FWSec profiles.
const IDPrefix = "efw-"

// namespace for name-based (v5) UUIDs of Edge FWSec profiles.
var namespace = [16]byte{0x5c, 0x1e, 0x0f, 0x4a, 0x9b, 0x22, 0x4d, 0x77, 0x8e, 0x31, 0x6a, 0x10, 0xe7, 0x2f, 0xc4, 0x58}

// ProfileUUID is the RFC 4122 version-5 UUID of a profile id.
func ProfileUUID(id string) string {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write([]byte(id))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Owned reports whether a profile id/uuid pair belongs to Edge FWSec.
func Owned(id, uuid string) bool {
	return strings.HasPrefix(id, IDPrefix) && uuid == ProfileUUID(id)
}

// Settings is NetworkManager's a{sa{sv}} connection dictionary.
type Settings map[string]map[string]dbus.Variant

// Profile is one NetworkManager connection derived from an interface.
type Profile struct {
	ID       string
	UUID     string
	Device   string
	Parent   string // VLAN parent device, "" otherwise
	Settings Settings
}

// Profiles builds one profile per interface. c must be valid.
func Profiles(c *policy.Config) ([]Profile, error) {
	if err := policy.Validate(c); err != nil {
		return nil, err
	}
	var out []Profile
	for _, it := range c.Interfaces {
		id := IDPrefix + it.Name
		p := Profile{ID: id, UUID: ProfileUUID(id), Device: it.Device}
		conn := map[string]dbus.Variant{
			"id":                   dbus.MakeVariant(id),
			"uuid":                 dbus.MakeVariant(p.UUID),
			"interface-name":       dbus.MakeVariant(it.Device),
			"autoconnect":          dbus.MakeVariant(true),
			"autoconnect-priority": dbus.MakeVariant(int32(50)),
		}
		s := Settings{"connection": conn}
		if it.VLAN != nil {
			p.Parent = it.VLAN.Parent
			conn["type"] = dbus.MakeVariant("vlan")
			s["vlan"] = map[string]dbus.Variant{
				"parent": dbus.MakeVariant(it.VLAN.Parent),
				"id":     dbus.MakeVariant(uint32(it.VLAN.ID)),
			}
		} else {
			conn["type"] = dbus.MakeVariant("802-3-ethernet")
			s["802-3-ethernet"] = map[string]dbus.Variant{}
		}
		s["ipv4"] = ipSettings(c, it, true)
		s["ipv6"] = ipSettings(c, it, false)
		p.Settings = s
		out = append(out, p)
	}
	return out, nil
}

func ipSettings(c *policy.Config, it policy.Interface, v4 bool) map[string]dbus.Variant {
	mode, addrs := it.IPv6.Mode, it.IPv6.Addresses
	if v4 {
		mode, addrs = it.IPv4.Mode, it.IPv4.Addresses
	}
	m := map[string]dbus.Variant{}
	switch mode {
	case "static":
		m["method"] = dbus.MakeVariant("manual")
	case "dhcp", "slaac":
		m["method"] = dbus.MakeVariant("auto")
	case "dhcp6":
		m["method"] = dbus.MakeVariant("dhcp")
	default:
		m["method"] = dbus.MakeVariant("disabled")
	}
	ad := []map[string]dbus.Variant{}
	for _, a := range addrs {
		ad = append(ad, map[string]dbus.Variant{
			"address": dbus.MakeVariant(a.Addr().String()),
			"prefix":  dbus.MakeVariant(uint32(a.Bits())),
		})
	}
	if len(ad) > 0 {
		m["address-data"] = dbus.MakeVariant(ad)
	}
	rd := []map[string]dbus.Variant{}
	for _, r := range c.Routes {
		if r.Destination.Addr().Is4() != v4 || policy.RouteInterface(c, r) != it.Name {
			continue
		}
		if r.Destination.Bits() == 0 {
			m["gateway"] = dbus.MakeVariant(r.Gateway.String())
			if r.Metric > 0 {
				m["route-metric"] = dbus.MakeVariant(int64(r.Metric))
			}
			continue
		}
		e := map[string]dbus.Variant{
			"dest":     dbus.MakeVariant(r.Destination.Addr().String()),
			"prefix":   dbus.MakeVariant(uint32(r.Destination.Bits())),
			"next-hop": dbus.MakeVariant(r.Gateway.String()),
		}
		if r.Metric > 0 {
			e["metric"] = dbus.MakeVariant(uint32(r.Metric))
		}
		rd = append(rd, e)
	}
	if len(rd) > 0 {
		m["route-data"] = dbus.MakeVariant(rd)
	}
	// Only the WAN may install a default route learned from DHCP/RA.
	if it.Role != policy.RoleWAN && (mode == "dhcp" || mode == "slaac" || mode == "dhcp6") {
		m["never-default"] = dbus.MakeVariant(true)
	}
	return m
}

// prefixOf is a small helper for tests and diagnostics.
func prefixOf(addr string, bits uint32) netip.Prefix {
	return netip.PrefixFrom(netip.MustParseAddr(addr), int(bits))
}
