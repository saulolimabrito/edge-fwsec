package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Problem is one validation failure, addressed by a JSON-like path so the
// UI can attach it to the offending field.
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Problems is returned by Validate; it is an error when non-empty.
type Problems []Problem

func (p Problems) Error() string {
	var b strings.Builder
	for i, x := range p {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s: %s", x.Path, x.Message)
	}
	return b.String()
}

var (
	// Identifiers end up in nftables comments and log prefixes; keep them to
	// a charset that needs no quoting or escaping anywhere.
	reIdent = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	// Linux IFNAMSIZ is 16 including NUL.
	reDevice = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
)

type validator struct {
	c        *Config
	out      Problems
	ifByName map[string]*Interface
	nets     map[string]*Network
	svcs     map[string]*Service
}

func (v *validator) add(path, format string, a ...any) {
	v.out = append(v.out, Problem{Path: path, Message: fmt.Sprintf(format, a...)})
}

// Validate checks the whole configuration and returns every problem found.
func Validate(c *Config) error {
	v := &validator{c: c, ifByName: map[string]*Interface{}, nets: map[string]*Network{}, svcs: map[string]*Service{}}
	if c.SchemaVersion != SchemaVersion {
		v.add("schema_version", "unsupported schema version %d (this build reads %d)", c.SchemaVersion, SchemaVersion)
		return v.out
	}
	v.interfaces()
	v.objects()
	v.routes()
	v.admin()
	v.firewall()
	v.nat()
	if len(v.out) == 0 {
		return nil
	}
	return v.out
}

func (v *validator) interfaces() {
	devices := map[string]string{}
	var owned []struct {
		p    netip.Prefix
		path string
	}
	for i := range v.c.Interfaces {
		it := &v.c.Interfaces[i]
		p := fmt.Sprintf("interfaces[%d]", i)
		if !reIdent.MatchString(it.Name) {
			v.add(p+".name", "must match %s", reIdent)
		} else if _, dup := v.ifByName[it.Name]; dup {
			v.add(p+".name", "duplicate interface name %q", it.Name)
		} else {
			v.ifByName[it.Name] = it
		}
		switch it.Role {
		case RoleWAN, RoleLAN, RoleMgmt, RoleOpt:
		default:
			v.add(p+".role", "must be wan, lan, mgmt or opt")
		}
		if !reDevice.MatchString(it.Device) {
			v.add(p+".device", "invalid kernel device name")
		} else if other, dup := devices[it.Device]; dup {
			v.add(p+".device", "device %q already used by interface %q", it.Device, other)
		} else {
			devices[it.Device] = it.Name
		}
		if it.VLAN != nil {
			if it.VLAN.ID < 1 || it.VLAN.ID > 4094 {
				v.add(p+".vlan.id", "VLAN id must be 1..4094")
			}
			if !reDevice.MatchString(it.VLAN.Parent) || it.VLAN.Parent == it.Device {
				v.add(p+".vlan.parent", "invalid parent device")
			}
		}
		switch it.IPv4.Mode {
		case "none", "dhcp":
			if len(it.IPv4.Addresses) > 0 {
				v.add(p+".ipv4.addresses", "addresses are only allowed in static mode")
			}
		case "static":
			if len(it.IPv4.Addresses) == 0 {
				v.add(p+".ipv4.addresses", "static mode needs at least one address")
			}
		default:
			v.add(p+".ipv4.mode", "must be none, static or dhcp")
		}
		switch it.IPv6.Mode {
		case "none", "slaac", "dhcp6":
			if len(it.IPv6.Addresses) > 0 {
				v.add(p+".ipv6.addresses", "addresses are only allowed in static mode")
			}
		case "static":
			if len(it.IPv6.Addresses) == 0 {
				v.add(p+".ipv6.addresses", "static mode needs at least one address")
			}
		default:
			v.add(p+".ipv6.mode", "must be none, static, slaac or dhcp6")
		}
		check := func(list []netip.Prefix, want4 bool, fam string) {
			for j, a := range list {
				ap := fmt.Sprintf("%s.%s.addresses[%d]", p, fam, j)
				switch {
				case !a.IsValid():
					v.add(ap, "invalid prefix")
					continue
				case a.Addr().Is4() != want4 || a.Addr().Is4In6():
					v.add(ap, "address family does not match %s", fam)
					continue
				case a.Addr().IsLoopback() || a.Addr().IsMulticast() || a.Addr().IsUnspecified():
					v.add(ap, "loopback, multicast and unspecified addresses are not assignable")
					continue
				case a.Addr().IsLinkLocalUnicast():
					v.add(ap, "link-local addresses are managed by the kernel")
					continue
				case want4 && a.Bits() < 31 && a.Addr() == a.Masked().Addr():
					v.add(ap, "address is the network address of its prefix")
					continue
				}
				for _, o := range owned {
					if o.p.Overlaps(a) {
						v.add(ap, "prefix overlaps %s (%s)", o.path, o.p)
					}
				}
				owned = append(owned, struct {
					p    netip.Prefix
					path string
				}{a, ap})
			}
		}
		check(it.IPv4.Addresses, true, "ipv4")
		check(it.IPv6.Addresses, false, "ipv6")
	}
	wans := 0
	for _, it := range v.c.Interfaces {
		if it.Role == RoleWAN {
			wans++
		}
	}
	if wans > 1 {
		v.add("interfaces", "only one WAN is supported in v1 (multi-WAN is on the roadmap)")
	}
}

func (v *validator) objects() {
	for i := range v.c.Networks {
		n := &v.c.Networks[i]
		p := fmt.Sprintf("networks[%d]", i)
		v.uniqueObject(p, n.Name)
		v.nets[n.Name] = n
		if len(n.Prefixes) == 0 {
			v.add(p+".prefixes", "a network object needs at least one prefix")
		}
		for j, pr := range n.Prefixes {
			if !pr.IsValid() || pr.Addr().Is4In6() {
				v.add(fmt.Sprintf("%s.prefixes[%d]", p, j), "invalid prefix")
			} else if pr != pr.Masked() {
				v.add(fmt.Sprintf("%s.prefixes[%d]", p, j), "host bits set; did you mean %s?", pr.Masked())
			}
		}
	}
	for i := range v.c.Services {
		s := &v.c.Services[i]
		p := fmt.Sprintf("services[%d]", i)
		v.uniqueObject(p, s.Name)
		v.svcs[s.Name] = s
		if len(s.Entries) == 0 {
			v.add(p+".entries", "a service needs at least one entry")
		}
		for j, e := range s.Entries {
			ep := fmt.Sprintf("%s.entries[%d]", p, j)
			switch e.Protocol {
			case "tcp", "udp":
				for k, r := range e.Ports {
					v.portRange(fmt.Sprintf("%s.ports[%d]", ep, k), r)
				}
			case "icmp", "icmpv6":
				if len(e.Ports) > 0 {
					v.add(ep+".ports", "%s has no ports", e.Protocol)
				}
			default:
				v.add(ep+".protocol", "must be tcp, udp, icmp or icmpv6")
			}
		}
	}
}

func (v *validator) uniqueObject(path, name string) {
	if !reIdent.MatchString(name) {
		v.add(path+".name", "must match %s", reIdent)
		return
	}
	if _, ok := v.nets[name]; ok {
		v.add(path+".name", "object name %q already used", name)
	}
	if _, ok := v.svcs[name]; ok {
		v.add(path+".name", "object name %q already used", name)
	}
}

func (v *validator) portRange(path string, r PortRange) {
	if r.From < 1 || r.To > 65535 || r.From > r.To {
		v.add(path, "port range must satisfy 1 <= from <= to <= 65535")
	}
}

func (v *validator) routes() {
	for i, r := range v.c.Routes {
		p := fmt.Sprintf("routes[%d]", i)
		if !r.Destination.IsValid() || r.Destination != r.Destination.Masked() {
			v.add(p+".destination", "must be a network prefix without host bits")
			continue
		}
		if !r.Gateway.IsValid() {
			v.add(p+".gateway", "gateway address is required")
			continue
		}
		if r.Gateway.Is4() != r.Destination.Addr().Is4() {
			v.add(p+".gateway", "gateway family differs from destination family")
		}
		if r.Interface != "" {
			if _, ok := v.ifByName[r.Interface]; !ok {
				v.add(p+".interface", "unknown interface %q", r.Interface)
			}
		} else if RouteInterface(v.c, r) == "" {
			v.add(p+".interface", "gateway %s is not inside any static prefix; name the interface (required for DHCP/SLAAC links)", r.Gateway)
		}
		if r.Metric < 0 {
			v.add(p+".metric", "metric must be >= 0")
		}
	}
}

func (v *validator) admin() {
	a := v.c.Admin
	if a.Port < 1 || a.Port > 65535 {
		v.add("admin.port", "invalid port")
	}
	if len(a.Interfaces) == 0 {
		v.add("admin.interfaces", "at least one interface must allow management access, or the console becomes unreachable")
	}
	for i, n := range a.Interfaces {
		it, ok := v.ifByName[n]
		switch {
		case !ok:
			v.add(fmt.Sprintf("admin.interfaces[%d]", i), "unknown interface %q", n)
		case it.Role == RoleWAN:
			v.add(fmt.Sprintf("admin.interfaces[%d]", i), "management access on the WAN is not allowed in v1")
		}
	}
	v.addrRefs("admin.sources", a.Sources, "any")
}

// addrRefs validates references to network objects or literal prefixes.
// fam restricts allowed families ("any", "ipv4", "ipv6").
func (v *validator) addrRefs(path string, refs []string, fam string) {
	for i, ref := range refs {
		p := fmt.Sprintf("%s[%d]", path, i)
		pfx, err := v.resolveRef(ref)
		if err != nil {
			v.add(p, "%v", err)
			continue
		}
		// Mixed objects are fine under a family restriction (only matching
		// prefixes are used); a reference with none of them is an error.
		if fam == "ipv4" || fam == "ipv6" {
			if len(filterFamily(pfx, fam)) == 0 {
				v.add(p, "%q has no %s prefix", ref, map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[fam])
			}
		}
	}
}

func (v *validator) resolveRef(ref string) ([]netip.Prefix, error) {
	if n, ok := v.nets[ref]; ok {
		return n.Prefixes, nil
	}
	return parseLiteral(ref)
}

func (v *validator) firewall() {
	f := v.c.Firewall
	switch f.DefaultInput {
	case "drop", "reject":
	default:
		v.add("firewall.default_input", "must be drop or reject (an accepting input policy would expose the appliance)")
	}
	switch f.DefaultForward {
	case "drop", "reject", "accept":
	default:
		v.add("firewall.default_forward", "must be drop, reject or accept")
	}
	ids := map[string]bool{}
	for i, r := range f.Rules {
		p := fmt.Sprintf("firewall.rules[%d]", i)
		v.id(p, r.ID, ids)
		switch r.Direction {
		case "input":
			if r.Out != "" {
				v.add(p+".out", "input rules have no outgoing interface")
			}
		case "forward":
		default:
			v.add(p+".direction", "must be input or forward")
		}
		v.ifRef(p+".in", r.In)
		v.ifRef(p+".out", r.Out)
		if r.In != "" && r.In == r.Out {
			v.add(p+".out", "in and out are the same interface")
		}
		switch r.Action {
		case "accept", "drop", "reject":
		default:
			v.add(p+".action", "must be accept, drop or reject")
		}
		if len(r.Description) > 200 {
			v.add(p+".description", "at most 200 characters")
		}
		switch r.Family {
		case "any", "ipv4", "ipv6":
		default:
			v.add(p+".family", "must be any, ipv4 or ipv6")
		}
		v.addrRefs(p+".source", r.Source, r.Family)
		v.addrRefs(p+".destination", r.Destination, r.Family)
		if r.Service != "" {
			if _, ok := v.svcs[r.Service]; !ok {
				v.add(p+".service", "unknown service %q", r.Service)
			}
		}
		if len(v.out) == 0 {
			if _, err := Families(v.c, r); err != nil {
				v.add(p, "%v", err)
			}
		}
	}
}

func (v *validator) id(path, id string, seen map[string]bool) {
	if !reIdent.MatchString(id) {
		v.add(path+".id", "must match %s", reIdent)
		return
	}
	if seen[id] {
		v.add(path+".id", "duplicate id %q", id)
	}
	seen[id] = true
}

func (v *validator) ifRef(path, name string) {
	if name == "" {
		return
	}
	if _, ok := v.ifByName[name]; !ok {
		v.add(path, "unknown interface %q", name)
	}
}

type pfKey struct {
	in, proto string
	addr      netip.Addr
}

func (v *validator) nat() {
	ids := map[string]bool{}
	for i, s := range v.c.NAT.Source {
		p := fmt.Sprintf("nat.source[%d]", i)
		v.id(p, s.ID, ids)
		v.ifRef(p+".out", s.Out)
		if s.Out == "" {
			v.add(p+".out", "outgoing interface is required")
		}
		v.addrRefs(p+".source", s.Source, "ipv4")
		switch s.Mode {
		case "masquerade":
			if s.ToAddress.IsValid() {
				v.add(p+".to_address", "masquerade uses the interface address; remove to_address or use snat")
			}
		case "snat":
			if !s.ToAddress.IsValid() || !s.ToAddress.Is4() {
				v.add(p+".to_address", "snat needs an IPv4 to_address")
			}
		default:
			v.add(p+".mode", "must be masquerade or snat")
		}
	}

	seen := map[pfKey][]struct {
		r    PortRange
		path string
	}{}
	for i, f := range v.c.NAT.PortForwards {
		p := fmt.Sprintf("nat.port_forwards[%d]", i)
		v.id(p, f.ID, ids)
		v.ifRef(p+".in", f.In)
		if f.In == "" {
			v.add(p+".in", "incoming interface is required")
		}
		if f.Protocol != "tcp" && f.Protocol != "udp" {
			v.add(p+".protocol", "must be tcp or udp")
		}
		v.portRange(p+".external_ports", f.ExternalPorts)
		if f.ExternalAddress.IsValid() && !f.ExternalAddress.Is4() {
			v.add(p+".external_address", "port forwards are IPv4 only in v1")
		}
		if !f.Target.IsValid() || !f.Target.Is4() {
			v.add(p+".target", "an IPv4 target address is required (IPv6: use a forward rule)")
		} else if f.Target.IsLoopback() || f.Target.IsUnspecified() || f.Target.IsMulticast() {
			v.add(p+".target", "target must be a unicast host")
		}
		if f.TargetPort != 0 {
			if f.TargetPort < 1 || f.TargetPort > 65535 {
				v.add(p+".target_port", "invalid port")
			}
			if f.ExternalPorts.From != f.ExternalPorts.To {
				v.add(p+".target_port", "a port range is forwarded unchanged; target_port is only allowed with a single external port")
			}
		}
		v.addrRefs(p+".allow_from", f.AllowFrom, "ipv4")
		if f.Disabled {
			continue
		}
		// Conflicts: overlapping external ports on the same interface,
		// protocol and address (an unset address matches every address).
		for k, list := range seen {
			if k.in != f.In || k.proto != f.Protocol {
				continue
			}
			if k.addr.IsValid() && f.ExternalAddress.IsValid() && k.addr != f.ExternalAddress {
				continue
			}
			for _, o := range list {
				if o.r.From <= f.ExternalPorts.To && f.ExternalPorts.From <= o.r.To {
					v.add(p+".external_ports", "overlaps %s on %s/%s", o.path, f.In, f.Protocol)
				}
			}
		}
		k := pfKey{f.In, f.Protocol, f.ExternalAddress}
		seen[k] = append(seen[k], struct {
			r    PortRange
			path string
		}{f.ExternalPorts, p})
		// The console port on a management interface must not be shadowed.
		if f.Protocol == "tcp" && f.ExternalPorts.From <= v.c.Admin.Port && v.c.Admin.Port <= f.ExternalPorts.To {
			for _, a := range v.c.Admin.Interfaces {
				if a == f.In {
					v.add(p+".external_ports", "would shadow the management console port %d on %s", v.c.Admin.Port, f.In)
				}
			}
		}
	}
}

// parseLiteral accepts a prefix ("192.0.2.0/24") or a bare address,
// which becomes a host prefix.
func parseLiteral(s string) ([]netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4In6() {
			return nil, fmt.Errorf("%q is neither a network object nor a valid prefix", s)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("%q has host bits set; did you mean %s?", s, p.Masked())
		}
		return []netip.Prefix{p}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4In6() || a.Zone() != "" {
		return nil, fmt.Errorf("%q is neither a network object nor a valid address", s)
	}
	return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, nil
}

// Resolve expands network names and literals into prefixes.
func Resolve(c *Config, refs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, r := range refs {
		found := false
		for _, n := range c.Networks {
			if n.Name == r {
				out = append(out, n.Prefixes...)
				found = true
				break
			}
		}
		if found {
			continue
		}
		p, err := parseLiteral(r)
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	return out, nil
}

// Families reports which IP families a rule produces. A rule whose source
// is only IPv4 and destination only IPv6 can never match and is an error.
func Families(c *Config, r Rule) ([]string, error) {
	want := map[string]bool{"ipv4": r.Family != "ipv6", "ipv6": r.Family != "ipv4"}
	for _, refs := range [][]string{r.Source, r.Destination} {
		if len(refs) == 0 {
			continue
		}
		p, err := Resolve(c, refs)
		if err != nil {
			return nil, err
		}
		has4, has6 := false, false
		for _, x := range p {
			if x.Addr().Is4() {
				has4 = true
			} else {
				has6 = true
			}
		}
		want["ipv4"] = want["ipv4"] && has4
		want["ipv6"] = want["ipv6"] && has6
	}
	if r.Service != "" {
		for _, s := range c.Services {
			if s.Name != r.Service {
				continue
			}
			only := ""
			for _, e := range s.Entries {
				switch e.Protocol {
				case "icmp":
					only += "4"
				case "icmpv6":
					only += "6"
				default:
					only += "*"
				}
			}
			if !strings.Contains(only, "*") {
				want["ipv4"] = want["ipv4"] && strings.Contains(only, "4")
				want["ipv6"] = want["ipv6"] && strings.Contains(only, "6")
			}
		}
	}
	var fams []string
	for _, f := range []string{"ipv4", "ipv6"} {
		if want[f] {
			fams = append(fams, f)
		}
	}
	if len(fams) == 0 {
		return nil, fmt.Errorf("source, destination, service and family select no common IP family; the rule can never match")
	}
	return fams, nil
}

// filterFamily keeps the prefixes of one family ("ipv4" or "ipv6").
func filterFamily(in []netip.Prefix, fam string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range in {
		if p.Addr().Is4() == (fam == "ipv4") {
			out = append(out, p)
		}
	}
	return out
}

// RouteInterface returns the logical interface that carries r: the one
// named in the route, or the one whose static prefix contains the gateway.
func RouteInterface(c *Config, r Route) string {
	if r.Interface != "" {
		return r.Interface
	}
	for _, it := range c.Interfaces {
		for _, p := range append(append([]netip.Prefix{}, it.IPv4.Addresses...), it.IPv6.Addresses...) {
			if p.Masked().Contains(r.Gateway) {
				return it.Name
			}
		}
	}
	return ""
}
