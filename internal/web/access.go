package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/agent"
	"github.com/saulolimabrito/edge-fwsec/internal/policy"
	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
)

// AgentCaller sends one request to efw-agent.
type AgentCaller interface {
	Call(ctx context.Context, req *agent.Request) (*agent.Response, error)
}

// SocketAgent calls efw-agent over its Unix socket.
type SocketAgent struct{ Path string }

// Call implements AgentCaller.
func (s SocketAgent) Call(ctx context.Context, req *agent.Request) (*agent.Response, error) {
	return agent.Call(ctx, s.Path, req)
}

// MgmtAccess decides, server side, whether a connection may use the
// console: it must arrive on a local address of a management interface of
// the confirmed configuration (or of the bootstrap interfaces before any
// configuration is confirmed), from an authorized source. Loopback is
// always allowed (SSH tunnel / local console). This mirrors the nftables
// rule so that a missing or wrong ruleset does not expose the console.
type MgmtAccess struct {
	Agent     AgentCaller
	Ifaces    func() ([]sysinfo.Interface, error) // default: sysinfo.Reader{}.Interfaces
	Bootstrap []string                            // kernel devices allowed before the first confirmed revision
	TTL       time.Duration

	mu      sync.Mutex
	at      time.Time
	locals  []netip.Addr
	sources []netip.Prefix // empty = any
}

func (m *MgmtAccess) refresh(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ttl := m.TTL
	if ttl == 0 {
		ttl = 10 * time.Second
	}
	if time.Since(m.at) < ttl && !m.at.IsZero() {
		return
	}
	devs := slices.Clone(m.Bootstrap)
	var sources []netip.Prefix
	if m.Agent != nil {
		if st, err := m.Agent.Call(ctx, &agent.Request{Op: agent.OpStatus}); err == nil && st.OK && st.Status.Confirmed > 0 {
			if r, err := m.Agent.Call(ctx, &agent.Request{Op: agent.OpGet, Revision: st.Status.Confirmed}); err == nil && r.OK {
				if c, err := policy.Decode(bytesReader(r.Config)); err == nil {
					devs = nil
					for _, name := range c.Admin.Interfaces {
						for _, it := range c.Interfaces {
							if it.Name == name {
								devs = append(devs, it.Device)
							}
						}
					}
					sources, _ = policy.Resolve(c, c.Admin.Sources)
				}
			}
		} else if err != nil && !m.at.IsZero() {
			return // agent unreachable: keep the last known set
		}
	}
	var locals []netip.Addr
	read := m.Ifaces
	if read == nil {
		read = sysinfo.Reader{}.Interfaces
	}
	if ifs, err := read(); err == nil {
		for _, it := range ifs {
			if !slices.Contains(devs, it.Name) {
				continue
			}
			for _, a := range it.Addresses {
				if p, err := netip.ParsePrefix(a.CIDR); err == nil {
					locals = append(locals, p.Addr())
				}
			}
		}
	}
	m.locals, m.sources, m.at = locals, sources, time.Now()
}

// Allowed reports whether a request may be served.
func (m *MgmtAccess) Allowed(r *http.Request) bool {
	la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	local := addrOf(la)
	if local.IsLoopback() {
		return true
	}
	m.refresh(r.Context())
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Contains(m.locals, local) {
		return false
	}
	if len(m.sources) == 0 {
		return true
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ra := remote.Addr().Unmap()
	for _, p := range m.sources {
		if p.Contains(ra) {
			return true
		}
	}
	return false
}

func addrOf(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
