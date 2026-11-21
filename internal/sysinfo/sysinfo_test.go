package sysinfo

import (
	"net"
	"testing"
)

func TestConvertAddrsFamiliesAndScopes(t *testing.T) {
	mk := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	got := convertAddrs([]net.Addr{mk("192.0.2.1/24"), mk("fe80::1/64"), mk("2001:db8::1/64"), mk("::1/128")})
	want := []Address{
		{"ipv4", "192.0.2.1/24", "global"},
		{"ipv6", "fe80::1/64", "link"},
		{"ipv6", "2001:db8::1/64", "global"},
		{"ipv6", "::1/128", "host"},
	}
	if len(got) != len(want) {
		t.Fatalf("len %d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestInterfacesLiveSmoke(t *testing.T) {
	ifs, err := Reader{}.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifs) == 0 {
		t.Fatal("expected at least a loopback interface")
	}
	for i := 1; i < len(ifs); i++ {
		if ifs[i-1].Index > ifs[i].Index {
			t.Fatal("not sorted by index")
		}
	}
}
