// Package policy defines the versioned appliance configuration model and
// its validation. Nothing in this package touches the system: the agent
// renders a validated Config into nftables/NetworkManager changes.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
)

// SchemaVersion is the configuration schema this build reads and writes.
// Bumping it requires a migration in migrate.go and a compatibility test.
//
//	1: initial schema
//	2: admin.ssh / admin.ssh_port (SSH on management interfaces)
const SchemaVersion = 2

// Config is the whole appliance configuration (one revision).
type Config struct {
	SchemaVersion int         `json:"schema_version"`
	Interfaces    []Interface `json:"interfaces"`
	Routes        []Route     `json:"routes"`
	Networks      []Network   `json:"networks"`
	Services      []Service   `json:"services"`
	Admin         Admin       `json:"admin"`
	Firewall      Firewall    `json:"firewall"`
	NAT           NAT         `json:"nat"`
}

// Role classifies an interface for defaults (WAN never gets admin access).
type Role string

const (
	RoleWAN  Role = "wan"
	RoleLAN  Role = "lan"
	RoleMgmt Role = "mgmt"
	RoleOpt  Role = "opt"
)

// Interface is a logical interface bound to a kernel device.
type Interface struct {
	Name   string `json:"name"`   // logical name used by rules, e.g. "lan"
	Role   Role   `json:"role"`   // wan | lan | mgmt | opt
	Device string `json:"device"` // kernel name, e.g. "enp1s0" or "enp1s0.30"
	VLAN   *VLAN  `json:"vlan,omitempty"`
	IPv4   IPv4   `json:"ipv4"`
	IPv6   IPv6   `json:"ipv6"`
}

// VLAN marks the device as an 802.1Q sub-interface of Parent.
type VLAN struct {
	Parent string `json:"parent"` // kernel device of the trunk
	ID     int    `json:"id"`     // 1..4094
}

// IPv4 addressing. Mode: none | static | dhcp.
type IPv4 struct {
	Mode      string         `json:"mode"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
}

// IPv6 addressing. Mode: none | static | slaac | dhcp6.
type IPv6 struct {
	Mode      string         `json:"mode"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
}

// Route is a static route; the family follows Destination.
type Route struct {
	Destination netip.Prefix `json:"destination"`
	Gateway     netip.Addr   `json:"gateway"`
	Interface   string       `json:"interface,omitempty"` // logical name
	Metric      int          `json:"metric,omitempty"`
}

// Network is a reusable address object (IPv4 and/or IPv6 prefixes).
type Network struct {
	Name     string         `json:"name"`
	Prefixes []netip.Prefix `json:"prefixes"`
}

// Service is a reusable protocol/port object.
type Service struct {
	Name    string         `json:"name"`
	Entries []ServiceEntry `json:"entries"`
}

// ServiceEntry: protocol tcp | udp | icmp | icmpv6. Ports only for tcp/udp;
// empty Ports means any port of that protocol.
type ServiceEntry struct {
	Protocol string      `json:"protocol"`
	Ports    []PortRange `json:"ports,omitempty"`
}

// PortRange is inclusive; a single port has From == To.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Admin controls who may reach the management console on the appliance.
type Admin struct {
	Port       int      `json:"port"`       // HTTPS port, default 443
	SSH        bool     `json:"ssh"`        // also allow SSH on the same interfaces/sources
	SSHPort    int      `json:"ssh_port"`   // default 22
	Interfaces []string `json:"interfaces"` // logical interfaces allowed; never a WAN
	Sources    []string `json:"sources"`    // network objects or literal prefixes; empty = any on those interfaces
}

// Firewall holds default policies and ordered rules. Order in Rules is the
// evaluation order within each direction.
type Firewall struct {
	DefaultInput   string `json:"default_input"`   // drop | reject (accept is refused)
	DefaultForward string `json:"default_forward"` // drop | reject | accept
	LogDefault     bool   `json:"log_default"`     // log packets hitting the default policy
	Rules          []Rule `json:"rules"`
}

// Rule is one ordered filter rule.
type Rule struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	Direction   string   `json:"direction"`             // input | forward
	In          string   `json:"in,omitempty"`          // logical interface; "" = any
	Out         string   `json:"out,omitempty"`         // forward only
	Family      string   `json:"family,omitempty"`      // any (default) | ipv4 | ipv6
	Source      []string `json:"source,omitempty"`      // network names or literal prefixes; empty = any
	Destination []string `json:"destination,omitempty"` // idem
	Service     string   `json:"service,omitempty"`     // service name; "" = any
	Action      string   `json:"action"`                // accept | drop | reject
	Log         bool     `json:"log,omitempty"`
}

// NAT holds IPv4 source NAT and port forwards (DNAT). IPv6 NAT is out of
// scope for v1 (see docs/support-matrix.md).
type NAT struct {
	Source       []SourceNAT   `json:"source"`
	PortForwards []PortForward `json:"port_forwards"`
}

// SourceNAT rewrites IPv4 sources leaving through Out.
type SourceNAT struct {
	ID        string     `json:"id"`
	Disabled  bool       `json:"disabled,omitempty"`
	Out       string     `json:"out"`              // logical interface
	Source    []string   `json:"source,omitempty"` // IPv4 networks; empty = any
	Mode      string     `json:"mode"`             // masquerade | snat
	ToAddress netip.Addr `json:"to_address,omitzero"`
}

// PortForward publishes an internal IPv4 service. It implies an accept
// rule in the forward chain, generated and shown alongside it.
type PortForward struct {
	ID              string     `json:"id"`
	Description     string     `json:"description,omitempty"`
	Disabled        bool       `json:"disabled,omitempty"`
	In              string     `json:"in"`       // logical interface (usually the WAN)
	Protocol        string     `json:"protocol"` // tcp | udp
	ExternalAddress netip.Addr `json:"external_address,omitzero"`
	ExternalPorts   PortRange  `json:"external_ports"`
	Target          netip.Addr `json:"target"`
	TargetPort      int        `json:"target_port,omitempty"` // 0 = same as external (range kept)
	AllowFrom       []string   `json:"allow_from,omitempty"`  // IPv4 networks; empty = any
	Log             bool       `json:"log,omitempty"`
}

// Decode reads a Config strictly: unknown fields and trailing data are
// errors, so typos cannot silently drop a rule. Documents written by an
// older schema are upgraded first (see migrate.go); newer ones are refused.
func Decode(r io.Reader) (*Config, error) {
	c, _, err := DecodeVersioned(r)
	return c, err
}

// DecodeVersioned is Decode that also reports the schema the document was
// written with (equal to SchemaVersion when no migration ran).
func DecodeVersioned(r io.Reader) (*Config, int, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return nil, 0, err
	}
	raw, from, err := Upgrade(raw)
	if err != nil {
		return nil, 0, err
	}
	c, err := decodeCurrent(bytes.NewReader(raw))
	return c, from, err
}

func decodeCurrent(r io.Reader) (*Config, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode config: trailing data after JSON document")
	}
	c.applyDefaults()
	return &c, nil
}

// Canonical returns the deterministic JSON encoding used for storage,
// hashing and diffs.
func (c *Config) Canonical() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Config) applyDefaults() {
	if c.Admin.Port == 0 {
		c.Admin.Port = 443
	}
	if c.Admin.SSHPort == 0 {
		c.Admin.SSHPort = 22
	}
	if c.Firewall.DefaultInput == "" {
		c.Firewall.DefaultInput = "drop"
	}
	if c.Firewall.DefaultForward == "" {
		c.Firewall.DefaultForward = "drop"
	}
	for i := range c.Interfaces {
		if c.Interfaces[i].IPv4.Mode == "" {
			c.Interfaces[i].IPv4.Mode = "none"
		}
		if c.Interfaces[i].IPv6.Mode == "" {
			c.Interfaces[i].IPv6.Mode = "none"
		}
	}
	for i := range c.Firewall.Rules {
		if c.Firewall.Rules[i].Family == "" {
			c.Firewall.Rules[i].Family = "any"
		}
	}
}
