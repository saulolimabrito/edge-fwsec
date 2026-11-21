# Support matrix (draft)

Only items with evidence recorded in `docs/release-checklist.md` count as
"supported". Until v1.0.0 this matrix describes the intended scope.

## Platforms

| Platform | Installer | ISO | Boot tested | Evidence |
|---|---|---|---|---|
| Rocky Linux 10, x86_64 (x86-64-v3), VM | intended | intended | UEFI (to test) | — |
| Rocky Linux 10, aarch64, VM | intended | intended | UEFI (to test) | — |
| Physical hardware | per model, only with evidence from that model | | | — |

Legacy BIOS will only be announced if tested. x86_64 CPUs without
x86-64-v3 are not supported (a Rocky/RHEL 10 requirement).

## Network features

| Feature | IPv4 | IPv6 | Notes |
|---|---|---|---|
| Static address | yes | yes | |
| DHCP client / SLAAC | DHCP | SLAAC + DHCPv6 client (to confirm with traffic) | WAN; non-WAN dynamic links never take the default route |
| 802.1Q VLAN | yes | yes | VID 1–4094 |
| Static routes | yes | yes | gateway must be on-link with a static prefix or the interface must be named |
| Stateful firewall, ordered rules | yes | yes | explicit default policy per direction |
| Essential ICMPv6 (ND, RA, PMTU/Packet Too Big, errors) | — | yes | always allowed, restricted per RFC 4890 |
| Masquerade / SNAT | yes | **no** | NAT66/NPTv6 out of scope for v1 |
| DNAT / port forward | yes | **no** | IPv6: allow with a forward rule; a port range is forwarded without remapping |
| Hairpin NAT (LAN → public WAN address) | **no** | — | out of scope for v1 |
| Filtering of the appliance's own output | **no** | **no** | `output` chain open in v1 |
| Multi-WAN, VPN, IDS/IPS, HA, BGP | no | no | post-v1 roadmap |
