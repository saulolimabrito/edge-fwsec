package policy

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func loadFixture(t *testing.T) *Config {
	t.Helper()
	b, err := os.ReadFile("testdata/edge.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFixtureIsValid(t *testing.T) {
	if err := Validate(loadFixture(t)); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeStrict(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{"schema_version":1,"firewal":{}}`)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
	if _, err := Decode(strings.NewReader(`{"schema_version":1} {}`)); err == nil {
		t.Fatal("trailing document must be rejected")
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	c := loadFixture(t)
	a, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Decode(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c2.Canonical()
	if !bytes.Equal(a, b) {
		t.Fatal("canonical encoding is not stable across a round trip")
	}
}

// expectProblem mutates the fixture and asserts a problem at path containing msg.
func expectProblem(t *testing.T, name, path, msg string, mutate func(c *Config)) {
	t.Run(name, func(t *testing.T) {
		c := loadFixture(t)
		mutate(c)
		err := Validate(c)
		if err == nil {
			t.Fatalf("expected problem at %s", path)
		}
		for _, p := range err.(Problems) {
			if p.Path == path && strings.Contains(p.Message, msg) {
				return
			}
		}
		t.Fatalf("no problem %q at %s; got %v", msg, path, err)
	})
}

func TestValidationProblems(t *testing.T) {
	expectProblem(t, "schema", "schema_version", "unsupported", func(c *Config) { c.SchemaVersion = 2 })
	expectProblem(t, "dup iface", "interfaces[1].name", "duplicate", func(c *Config) { c.Interfaces[1].Name = "wan" })
	expectProblem(t, "bad device", "interfaces[0].device", "invalid", func(c *Config) { c.Interfaces[0].Device = "eth0;rm" })
	expectProblem(t, "long device", "interfaces[0].device", "invalid", func(c *Config) { c.Interfaces[0].Device = "abcdefghijklmnop" })
	expectProblem(t, "vlan id", "interfaces[2].vlan.id", "1..4094", func(c *Config) { c.Interfaces[2].VLAN.ID = 4095 })
	expectProblem(t, "v4 family", "interfaces[1].ipv4.addresses[0]", "family", func(c *Config) {
		c.Interfaces[1].IPv4.Addresses[0] = c.Interfaces[1].IPv6.Addresses[0]
	})
	expectProblem(t, "overlap", "interfaces[2].ipv4.addresses[0]", "overlaps", func(c *Config) {
		c.Interfaces[2].IPv4.Addresses[0] = c.Interfaces[1].IPv4.Addresses[0]
	})
	expectProblem(t, "dhcp with addr", "interfaces[0].ipv4.addresses", "static mode", func(c *Config) { c.Interfaces[0].IPv4.Mode = "dhcp" })
	expectProblem(t, "two wans", "interfaces", "one WAN", func(c *Config) { c.Interfaces[1].Role = RoleWAN })
	expectProblem(t, "route family", "routes[1].gateway", "family", func(c *Config) { c.Routes[1].Gateway = c.Routes[0].Gateway })
	expectProblem(t, "route off-link", "routes[0].interface", "not inside any static prefix", func(c *Config) {
		c.Routes[0].Interface = ""
		c.Routes[0].Gateway = mustAddr("198.51.100.1")
	})
	expectProblem(t, "host bits", "networks[0].prefixes[0]", "host bits", func(c *Config) {
		c.Networks[0].Prefixes[0] = c.Interfaces[1].IPv4.Addresses[0]
	})
	expectProblem(t, "port range", "services[0].entries[0].ports[0]", "1 <= from", func(c *Config) {
		c.Services[0].Entries[0].Ports[0] = PortRange{From: 90, To: 80}
	})
	expectProblem(t, "icmp ports", "services[2].entries[0].ports", "no ports", func(c *Config) {
		c.Services[2].Entries[0].Ports = []PortRange{{1, 1}}
	})
	expectProblem(t, "no admin", "admin.interfaces", "unreachable", func(c *Config) { c.Admin.Interfaces = nil })
	expectProblem(t, "admin wan", "admin.interfaces[0]", "WAN", func(c *Config) { c.Admin.Interfaces = []string{"wan"} })
	expectProblem(t, "accept input", "firewall.default_input", "expose", func(c *Config) { c.Firewall.DefaultInput = "accept" })
	expectProblem(t, "unknown ref", "firewall.rules[2].source[0]", "neither", func(c *Config) { c.Firewall.Rules[2].Source = []string{"nope"} })
	expectProblem(t, "unknown svc", "firewall.rules[3].service", "unknown", func(c *Config) { c.Firewall.Rules[3].Service = "nope" })
	expectProblem(t, "unknown iface", "firewall.rules[3].out", "unknown", func(c *Config) { c.Firewall.Rules[3].Out = "dmz" })
	expectProblem(t, "dup rule id", "firewall.rules[1].id", "duplicate", func(c *Config) { c.Firewall.Rules[1].ID = "lan-ping-fw" })
	expectProblem(t, "bad id", "firewall.rules[0].id", "must match", func(c *Config) { c.Firewall.Rules[0].ID = `x" accept` })
	expectProblem(t, "input with out", "firewall.rules[0].out", "no outgoing", func(c *Config) { c.Firewall.Rules[0].Out = "wan" })
	expectProblem(t, "family mismatch", "firewall.rules[2].source[0]", "no IPv6 prefix", func(c *Config) {
		c.Firewall.Rules[2].Family = "ipv6"
		c.Firewall.Rules[2].Source = []string{"192.168.10.0/24"}
	})
	expectProblem(t, "never matches", "firewall.rules[2]", "never match", func(c *Config) {
		c.Firewall.Rules[2].Source = []string{"192.168.10.0/24"}
		c.Firewall.Rules[2].Destination = []string{"2001:db8::/32"}
	})
	expectProblem(t, "icmp v6 only", "firewall.rules[0]", "never match", func(c *Config) {
		c.Firewall.Rules[0].Family = "ipv6"
		c.Services[2].Entries = c.Services[2].Entries[:1] // icmp (v4) only
	})
	expectProblem(t, "nat v6 source", "nat.source[0].source[0]", "no IPv4 prefix", func(c *Config) { c.NAT.Source[0].Source = []string{"2001:db8:10::/64"} })
	expectProblem(t, "snat no addr", "nat.source[0].to_address", "IPv4 to_address", func(c *Config) { c.NAT.Source[0].Mode = "snat" })
	expectProblem(t, "pf v6 target", "nat.port_forwards[0].target", "IPv4", func(c *Config) {
		c.NAT.PortForwards[0].Target = c.Interfaces[1].IPv6.Addresses[0].Addr()
	})
	expectProblem(t, "pf conflict", "nat.port_forwards[1].external_ports", "overlaps nat.port_forwards[0]", func(c *Config) {
		pf := c.NAT.PortForwards[0]
		pf.ID = "web-in-2"
		pf.ExternalPorts = PortRange{8000, 8100}
		c.NAT.PortForwards = append(c.NAT.PortForwards, pf)
	})
	expectProblem(t, "pf shadows admin", "nat.port_forwards[0].external_ports", "management console", func(c *Config) {
		c.NAT.PortForwards[0].In = "mgmt"
		c.NAT.PortForwards[0].ExternalPorts = PortRange{443, 443}
	})
	expectProblem(t, "pf range remap", "nat.port_forwards[0].target_port", "single external port", func(c *Config) {
		c.NAT.PortForwards[0].ExternalPorts = PortRange{8080, 8090}
	})
	expectProblem(t, "id shared across nat", "nat.port_forwards[0].id", "duplicate", func(c *Config) { c.NAT.PortForwards[0].ID = "lan-masq" })
}

func TestPortForwardDistinctAddressesDoNotConflict(t *testing.T) {
	c := loadFixture(t)
	c.Interfaces[0].IPv4.Addresses = append(c.Interfaces[0].IPv4.Addresses, mustPrefix("203.0.113.3/24"))
	c.Interfaces[0].IPv4.Addresses = c.Interfaces[0].IPv4.Addresses[1:] // keep a single prefix (overlap check)
	a := c.NAT.PortForwards[0]
	a.ExternalAddress = mustAddr("203.0.113.2")
	b := a
	b.ID = "web-in-b"
	b.ExternalAddress = mustAddr("203.0.113.3")
	c.NAT.PortForwards = []PortForward{a, b}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}

func TestFamilies(t *testing.T) {
	c := loadFixture(t)
	cases := map[string]string{
		"lan-ping-fw": "ipv4,ipv6", "guest-no-lan": "ipv4,ipv6", "lan-out": "ipv4,ipv6", "web6-in": "ipv6",
	}
	for _, r := range c.Firewall.Rules {
		want, ok := cases[r.ID]
		if !ok {
			continue
		}
		got, err := Families(c, r)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%s: got %v %v want %s", r.ID, got, err, want)
		}
	}
}
