package web

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/saulolimabrito/edge-fwsec/internal/agent"
	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
)

func reqAt(local, remote string) *http.Request {
	r, _ := http.NewRequest("GET", "https://x/", nil)
	la, _ := net.ResolveTCPAddr("tcp", local)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, la))
	r.RemoteAddr = remote
	return r
}

func fakeIfaces() ([]sysinfo.Interface, error) {
	return []sysinfo.Interface{
		{Name: "wan0", Addresses: []sysinfo.Address{{Family: "ipv4", CIDR: "203.0.113.2/24"}}},
		{Name: "mgmt0", Addresses: []sysinfo.Address{{Family: "ipv4", CIDR: "10.99.0.1/24"}, {Family: "ipv6", CIDR: "fd00:99::1/64"}}},
	}, nil
}

func TestMgmtAccessBeforeAndAfterConfig(t *testing.T) {
	e := newEnv(t)
	ag := e.srv.Agent
	m := &MgmtAccess{Agent: ag, Ifaces: fakeIfaces, TTL: 1}
	if !m.Allowed(reqAt("127.0.0.1:443", "127.0.0.1:5000")) || !m.Allowed(reqAt("[::1]:443", "[::1]:5000")) {
		t.Fatal("loopback must always be allowed")
	}
	if m.Allowed(reqAt("10.99.0.1:443", "10.99.0.10:5000")) {
		t.Fatal("no confirmed config and no bootstrap interface: only loopback")
	}
	m2 := &MgmtAccess{Agent: ag, Ifaces: fakeIfaces, Bootstrap: []string{"mgmt0"}, TTL: 1}
	if !m2.Allowed(reqAt("10.99.0.1:443", "10.99.0.10:5000")) || m2.Allowed(reqAt("203.0.113.2:443", "198.51.100.10:5000")) {
		t.Fatal("bootstrap interface policy")
	}
	// confirm the reference config: admin on "mgmt" (device mgmt0)
	base := 0
	r, _ := ag.Call(context.Background(), &agent.Request{Op: agent.OpApply, Config: edgeConfig(t), BaseRevision: &base, TimeoutSeconds: 60})
	if !r.OK {
		t.Fatal(r.Error)
	}
	ag.Call(context.Background(), &agent.Request{Op: agent.OpConfirm, Revision: 1})
	m3 := &MgmtAccess{Agent: ag, Ifaces: fakeIfaces, TTL: 1}
	if !m3.Allowed(reqAt("10.99.0.1:443", "10.99.0.10:5000")) || !m3.Allowed(reqAt("[fd00:99::1]:443", "[fd00:99::10]:5000")) {
		t.Fatal("management interface refused")
	}
	if m3.Allowed(reqAt("203.0.113.2:443", "198.51.100.10:5000")) {
		t.Fatal("WAN address allowed")
	}
}
