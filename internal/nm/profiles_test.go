package nm

import (
	"bytes"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

func fixture(t *testing.T) *policy.Config {
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

func get[T any](t *testing.T, v dbus.Variant) T {
	t.Helper()
	x, ok := v.Value().(T)
	if !ok {
		t.Fatalf("variant %v is %T", v, v.Value())
	}
	return x
}

func TestUUIDIsStableV5AndOwned(t *testing.T) {
	u := ProfileUUID("efw-lan")
	if u != ProfileUUID("efw-lan") || u == ProfileUUID("efw-wan") {
		t.Fatal("uuid must be deterministic and distinct")
	}
	if len(u) != 36 || u[14] != '5' || !bytes.ContainsAny([]byte{u[19]}, "89ab") {
		t.Fatalf("not an RFC 4122 v5 uuid: %s", u)
	}
	if !Owned("efw-lan", u) || Owned("efw-lan", "1dd9a779-d327-56e1-8454-c65e2556c12c") || Owned("cloud-init eth0", u) {
		t.Fatal("ownership check wrong")
	}
}

func TestProfilesFromFixture(t *testing.T) {
	ps, err := Profiles(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 4 {
		t.Fatalf("%d profiles", len(ps))
	}
	byID := map[string]Profile{}
	for _, p := range ps {
		byID[p.ID] = p
	}
	wan := byID["efw-wan"]
	if get[string](t, wan.Settings["connection"]["type"]) != "802-3-ethernet" ||
		get[string](t, wan.Settings["connection"]["interface-name"]) != "wan0" {
		t.Fatal("wan connection settings")
	}
	if get[string](t, wan.Settings["ipv4"]["gateway"]) != "203.0.113.1" || get[string](t, wan.Settings["ipv6"]["gateway"]) != "2001:db8:ffff::1" {
		t.Fatal("default routes must become gateways on the WAN")
	}
	ad := get[[]map[string]dbus.Variant](t, wan.Settings["ipv4"]["address-data"])
	if get[string](t, ad[0]["address"]) != "203.0.113.2" || get[uint32](t, ad[0]["prefix"]) != 24 {
		t.Fatal("address-data")
	}
	if _, ok := byID["efw-lan"].Settings["ipv4"]["gateway"]; ok {
		t.Fatal("lan must not get a gateway")
	}
	g := byID["efw-guest"]
	if g.Parent != "lan0" || get[string](t, g.Settings["connection"]["type"]) != "vlan" ||
		get[uint32](t, g.Settings["vlan"]["id"]) != 30 || get[string](t, g.Settings["vlan"]["parent"]) != "lan0" {
		t.Fatal("vlan profile")
	}
}

func TestMethodsAndRoutes(t *testing.T) {
	c := fixture(t)
	c.Interfaces[1].IPv4 = policy.IPv4{Mode: "dhcp"}
	c.Interfaces[1].IPv6 = policy.IPv6{Mode: "slaac"}
	c.Interfaces[3].IPv6 = policy.IPv6{Mode: "none"}
	c.Routes = append(c.Routes, policy.Route{Destination: prefixOf("10.50.0.0", 16), Gateway: prefixOf("10.99.0.254", 32).Addr(), Metric: 20})
	ps, err := Profiles(c)
	if err != nil {
		t.Fatal(err)
	}
	lan, mgmt := ps[1], ps[3]
	if get[string](t, lan.Settings["ipv4"]["method"]) != "auto" || get[string](t, lan.Settings["ipv6"]["method"]) != "auto" {
		t.Fatal("dhcp/slaac methods")
	}
	if !get[bool](t, lan.Settings["ipv4"]["never-default"]) {
		t.Fatal("non-WAN dynamic links must not take the default route")
	}
	if get[string](t, mgmt.Settings["ipv6"]["method"]) != "disabled" {
		t.Fatal("ipv6 none")
	}
	rd := get[[]map[string]dbus.Variant](t, mgmt.Settings["ipv4"]["route-data"])
	if len(rd) != 1 || get[string](t, rd[0]["dest"]) != "10.50.0.0" || get[string](t, rd[0]["next-hop"]) != "10.99.0.254" || get[uint32](t, rd[0]["metric"]) != 20 {
		t.Fatalf("route-data %v", rd)
	}
}
