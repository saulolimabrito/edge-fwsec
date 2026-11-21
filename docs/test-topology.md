# Test topology

Implementation: `tests/topology/netns.sh`. Runs only in a disposable VM or a
CI runner, with `EFW_TEST_VM=1` and root. Every object uses the `efw-`
prefix and lives in its own namespace.

```
 efw-inet ── efw-wanr ══ wan0 ── efw-fw ── lan0 (trunk) ══ efw-lan (untagged)
 ("internet" host)  (ISP router)    │ (DUT)                  └─ eth0.30 ── efw-guest (VLAN 30)
                                   mgmt0
                                     ║
                                  efw-mgmt (administrator workstation)
```

| Segment | IPv4 | IPv6 | DUT | Peer |
|---|---|---|---|---|
| WAN | 203.0.113.0/24 | 2001:db8:ffff::/64 | .2 / ::2 | `efw-wanr` .1 / ::1 |
| "Internet" | 198.51.100.0/24 | 2001:db8:100::/64 | — | `efw-inet` .10 / ::10 |
| LAN | 192.168.10.0/24 | 2001:db8:10::/64 | .1 / ::1 | `efw-lan` .10 / ::10 |
| VLAN 30 (on lan0) | 192.168.30.0/24 | 2001:db8:30::/64 | .1 / ::1 | `efw-guest` eth0.30 .10 / ::10 |
| Management | 10.99.0.0/24 | fd00:99::/64 | .1 / ::1 | `efw-mgmt` .10 / ::10 |

In the base topology the ISP router has return routes to the LAN/VLAN,
so both plain routing and NAT can be tested (when the policy applies
masquerade, return traffic uses 203.0.113.2). IPv6 is routed without NAT, as
scoped for v1.

The client's VLAN device is moved into the `efw-guest` namespace (its parent
stays in `efw-lan`), so guest traffic really leaves tagged on VLAN 30.

## Base checks (`verify`)

IPv4/IPv6 reachability of the DUT from the LAN, VLAN 30 and management;
LAN → internet IPv4/IPv6 routed; internet → LAN IPv4 (no policy yet: PASS
expected); NDP neighbour on the DUT.

## Policy scenarios (`tests/policy/scenarios.sh`)

Applies the ruleset rendered from `internal/policy/testdata/edge.json` in
`efw-fw` and tests with real traffic (server `tests/policy/httpd.py`, client
`curl`, `ping`): LAN egress over IPv4 with masquerade and over IPv6 routed
without NAT; stateful return traffic; new WAN connections blocked; IPv6
publication by rule; port forward preserving the client source; console only
from the management network (v4/v6) and unreachable from the WAN; guest VLAN
with reject vs drop distinguished; kernel log; ICMP; ND under a drop policy;
Packet Too Big forwarded (PMTU 1280 learned); foreign table preserved;
idempotent re-apply; broken batch refused without changing the ruleset.

## Agent lifecycle (`tests/agent/lifecycle.sh`)

Runs `efw-agent` inside `efw-fw` and checks with traffic: confirm, deadline
expiry restoring LAN egress, losing management access undone by the
deadline, invalid change refused, `kill -9` during a test and restart,
simulated reboot (empty ruleset), `SIGTERM` during a test, `efwctl recover`
with the agent down, socket and state-directory permissions.

## NetworkManager checkpoints (`tests/nm/checkpoint.sh`)

NetworkManager does not manage other namespaces, so this test runs in the
VM's root namespace on veth devices named `eth90`–`eth92` (Rocky's udev
rules leave veth unmanaged unless named `eth<digit>…`); peers live in
`efwn-*` namespaces. nftables is disabled for this test (`-nft /bin/true`):
a drop policy in the VM's root namespace would cut the harness off.

## Notes on the environment

- `python3 -m http.server` calls `getfqdn()` and hangs in namespaces without
  DNS, hence the small dedicated server.
- Netfilter logging from non-initial namespaces needs
  `net.netfilter.nf_log_all_netns=1` (tests only; the appliance runs in the
  initial namespace).

## Recorded results

- 2026-11-21, Lima VM `efw-dev`, Rocky Linux 10.3 aarch64, kernel
  6.12.0-264.16.1.el10_3: 3 consecutive `up` + `verify` runs, 10/10 PASS each;
  `down` removes every namespace; host interfaces unchanged. The first
  attempt with `ping -c1 -W1` failed LAN → internet IPv6 because of ND
  resolution across two hops; checks now use 3 packets and 2 s.
- 2026-11-21, same VM, nftables 1.1.5: `scenarios.sh` 36/36 PASS in 3
  consecutive runs; no namespaces or tables left afterwards.
- 2026-11-21, same VM: `lifecycle.sh` 38/38 PASS in 3 consecutive runs;
  `checkpoint.sh` 46/46 PASS with NetworkManager 1.58.0.
