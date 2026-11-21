# Architecture — Edge FWSec v1

Status: stages 1 (read-only console), 2 (policy engine) and the agent part of
stage 3 (revisions, apply/confirm/rollback, NetworkManager checkpoints) are
implemented. Sections marked **[planned]** are the contract for the next
stages; changing them requires updating this file and the threat model.

## v1 scope

Single-node appliance: stateful firewall, static routing, IPv4 NAT, 802.1Q
VLANs, web administration and a recovery CLI. Out of scope for v1
(roadmap): HA, BGP/OSPF, IDS/IPS, VPN, multi-WAN, plugins, NAT66/NPTv6.

## Processes

```
 browser ──HTTPS──▶ efw-web (user efw-web, unprivileged)
                       │  JSON API /api/v1, embedded console (go:embed)
                       │  Unix socket /run/efw/agent.sock (0660 root:efw)
                       ▼  typed protocol, one operation per message
                    efw-agent (root with restricted capabilities)
                       ├─ revision store  /var/lib/efw/
                       ├─ nftables (generated script → `nft --check -f -` → `nft -f -`, stdin, no shell)
                       └─ NetworkManager (D-Bus: Settings, Checkpoint*)
 local console ──▶ efwctl (talks to the agent; reads the store directly when the agent is down; root)
```

| Component | State | Privilege | Responsibility |
|---|---|---|---|
| `efw-web` | read-only API | none | API, sessions, CSRF, embedded UI. Never changes the system. |
| `efw-agent` | implemented (nftables, NetworkManager, store, deadline, recovery) | root, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW` + D-Bus | Validates, applies, times and rolls back changes. Owns the confirmation deadline. |
| `efwctl` | implemented | root for recovery | Diagnostics, apply/confirm/rollback from the console, `recover` with the agent down. Planned: reissue the bootstrap credential. |

### Reading state (implemented)

`internal/sysinfo` reads `net.Interfaces`, `/sys/class/net/*/statistics`,
`operstate`, `uevent`, and rtnetlink `RTM_GETLINK` (`IFLA_LINKINFO`) for the
link kind and VLAN ID. `/proc/net/vlan/*` is `0600 root` on Rocky 10, so the
unprivileged process does not use it (verified in the VM). Missing values
are `null`.

### Web API (implemented, read-only)

| Method | Path | Response |
|---|---|---|
| GET | `/healthz` | `{"status":"ok"}` |
| GET | `/api/v1/version` | version, commit, build date |
| GET | `/api/v1/system` | hostname, os-release, kernel, architecture, uptime |
| GET | `/api/v1/interfaces` | interfaces, IPv4/IPv6 addresses, counters, `observed_at` |

Any other method under `/api/` → 405; unknown path → JSON 404. Headers:
CSP `default-src 'self'` without inline, `X-Frame-Options: DENY`,
`nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on the API.

## Configuration model (implemented: `internal/policy`)

One document with `schema_version: 1`, read with a strict `Decode` (unknown
field or trailing data = error) and written with `Canonical` (deterministic
JSON). Full example: `internal/policy/testdata/edge.json`.

| Section | Content |
|---|---|
| `interfaces[]` | logical name, role `wan/lan/mgmt/opt`, kernel device, `vlan {parent,id}`, `ipv4 {mode: none/static/dhcp}`, `ipv6 {mode: none/static/slaac/dhcp6}` |
| `routes[]` | destination, gateway (same family), logical interface, metric |
| `networks[]` | network object with IPv4 and/or IPv6 prefixes |
| `services[]` | service object: `tcp/udp` entries (port ranges) or `icmp/icmpv6` |
| `admin` | HTTPS port, authorized logical interfaces (never the WAN), optional sources |
| `firewall` | `default_input` (drop/reject), `default_forward` (drop/reject/accept), `log_default`, ordered `rules[]` |
| `nat` | `source[]` (masquerade/snat, IPv4 only), `port_forwards[]` (IPv4 DNAT) |

Rules: `id`, `direction` (input/forward), `in`, `out`, `family`
(any/ipv4/ipv6), `source`/`destination` (object names or literals),
`service`, `action` (accept/drop/reject), `log`, `disabled`. The position in
the list is the evaluation order within the direction.

Validation (`Validate`) returns every problem with a path
(`firewall.rules[2].source[0]`). Main checks: identifiers
`^[a-z][a-z0-9_-]{0,31}$` and devices compatible with IFNAMSIZ (nothing that
needs escaping in nftables); VID 1–4094; address families; overlapping
prefixes between interfaces; a single WAN; gateway in the same family and
either on-link with a static prefix or bound to a named interface; objects
without host bits; port ranges; existing references; a rule whose
source/destination/service/family combination can never match;
`default_input: accept` refused; management access with no interface or on
the WAN refused; NAT IPv4 only; port-forward conflicts (same interface,
protocol, address and overlapping ports); a port forward that shadows the
console port; remapping a port range onto a single port refused.

## nftables generation (implemented: `internal/nft`)

`Render` revalidates and generates a script using the atomic replacement
idiom, verified on nftables 1.1.5 (Rocky 10.3):

```
table inet efw_filter
delete table inet efw_filter
table ip efw_nat
delete table ip efw_nat
table inet efw_filter { ... }
table ip efw_nat { ... }
```

Chain order:

- `input` (policy drop): `ct state` vmap → `lo` → essential ICMPv6 →
  DHCP/DHCPv6 client on interfaces that use it → console access on the
  management interfaces → user rules → default log (limited to 10/s) →
  `reject` when the policy is reject.
- `forward` (policy drop or accept): `ct state` → ICMPv6 errors → implicit
  port-forward accepts (`ct status dnat`, evaluated before user rules) → user
  rules → default log → reject.
- `ip efw_nat`: `prerouting` with DNAT and `postrouting` with masquerade/SNAT.

ICMPv6 follows RFC 4890: errors (including Packet Too Big) always; ND only
with hop limit 255; MLD only from link-local; redirects are not accepted.
Rules use `iifname`/`oifname` (`iif` needs the interface to exist at load
time). Prefix and port sets are normalized (nftables refuses overlapping
intervals). `Runner.Apply` runs `nft --check -f -` and then `nft -f -` via
`exec`, without a shell. Reference output: `internal/nft/testdata/edge.nft`
(golden test).

v1 limits: no NAT66/NPTv6, no hairpin NAT (LAN client reaching the WAN
address), no output filtering (`output` stays open).

## NetworkManager profiles (implemented: `internal/nm`)

One profile per interface: id `efw-<logical name>`, UUID v5 derived from the
id (ownership = prefix + derived UUID), type `802-3-ethernet` or `vlan`
(`vlan.parent`, `vlan.id`), `interface-name` = device, `ipv4`/`ipv6` method
(`manual`, `auto` for DHCP/SLAAC, `dhcp` for DHCPv6, `disabled`),
`address-data`, `route-data`, and the default route as `gateway`. Dynamic
non-WAN links get `never-default`. Profiles are persisted to disk
(`AddConnection2`/`Update2` with `TO_DISK`); stale owned profiles are deleted;
foreign profiles are never touched.

Checkpoints (`CheckpointCreate`, flags `DELETE_NEW_CONNECTIONS`) cover the
devices of the new profiles, their VLAN parents and the devices of existing
owned profiles — never an empty list, which would mean every device on the
host. NetworkManager's own `rollback_timeout` is the agent deadline + 30 s as
a second safety net. Verified on NM 1.58.0: `DISCONNECT_NEW_DEVICES` is
rejected with an explicit device list; checkpoints do not survive a
NetworkManager restart (the agent then rewrites the confirmed profiles).

## Store and agent (implemented: `internal/store`, `internal/agent`, `cmd/efw-agent`)

Store in `/var/lib/efw` (0700): `lock` (exclusive flock: single writer),
`state.json` (`confirmed`, `testing{revision, deadline, author,
checkpoint}`, `last_revision`), `revisions/<n>.json` (immutable, 0600),
`history.jsonl` (audit log; a torn last line is ignored). Atomic writes:
temp file + `fsync` + `rename` + directory `fsync`. A corrupt `state.json` is
an error, never a silent reset.

Socket protocol (`/run/efw/agent.sock`, 0660 root:efw): one JSON object per
connection in each direction, 1 MiB max, strict decoding, each operation
accepts only its own fields.

| op | fields | effect |
|---|---|---|
| `status` | — | confirmed revision, revision under test, seconds left |
| `validate` | `config` | problems with paths |
| `diff` | `config` | ruleset diff against the confirmed revision + new ruleset |
| `apply` | `config`, `base_revision`, `timeout_seconds`, `author`, `message` | store revision, mark testing, apply network + firewall, arm the deadline |
| `confirm` | `revision`, `author` | release the checkpoint, mark confirmed, disarm |
| `rollback` | `author` | abandon the test; restore network, then the confirmed ruleset |
| `history` | `limit` | audit log |
| `get` | `revision` | stored configuration |

The recorded author is `<author> via uid=<uid>,pid=<pid>` (SO_PEERCRED).
Deadline: 30 s to 10 min (default 2 min). With no confirmed revision,
"confirmed" means removing the project's tables and profiles.

## Change flow (implemented in the agent; UI planned)

1. **Validate** (web and agent): schema, references, prefix overlap,
   NAT/port-forward conflicts.
2. **Diff**: generated ruleset against the confirmed revision (model-level
   diff for the UI is planned).
3. **Apply with deadline**: the agent persists `testing` + `deadline`
   **before** touching the system; network profiles are applied under a
   checkpoint (recorded in the test state); then the ruleset is checked with
   `nft --check` and loaded in one transaction.
4. **Confirm**: `CheckpointDestroy`, then `confirmed`. If the checkpoint
   cannot be released the change is rolled back and confirmation refused.
5. **Roll back** (deadline, explicit request or failure): network first
   (`CheckpointRollback`, or rewrite the confirmed profiles if the checkpoint
   is gone), then the confirmed ruleset.
6. **Recovery**: at startup, before the socket opens, any pending test is
   abandoned (checkpoint rolled back) and the confirmed ruleset is applied —
   covers crash, `kill -9`, service restart and reboot. `SIGTERM` during a
   test rolls back before exiting. `efwctl recover` uses the agent when it
   answers; otherwise it opens the store and reapplies the confirmed ruleset.

A change that alters the management IP, VLAN or route **[planned UI]**: the
UI shows the new address, the deadline and how to reconnect and confirm from
it; the agent accepts confirmation from any network authorized by the
revision under test.

## Ownership of system resources

- nftables: tables `inet efw_filter` and `ip efw_nat` (reserved names). The
  agent never runs `flush ruleset`. Foreign tables are preserved.
- NetworkManager: profiles `efw-<name>` with the derived UUID. Foreign
  profiles are not edited; initial setup adopts an existing profile only with
  explicit confirmation **[planned]**.
- firewalld **[planned]**: the transition is explicit — the installer
  detects it, shows its state, asks for confirmation, stops and masks
  firewalld and keeps a snapshot (`nft -j list ruleset`, zones) to revert with
  `efwctl firewalld restore`. Presence on Rocky 10 Minimal is still to be
  verified (checklist).

## Build and distribution

`make linux` builds static binaries (`CGO_ENABLED=0`) for `linux/amd64` with
`GOAMD64=v3` and `linux/arm64`, with hashes in `dist/SHA256SUMS`; `make repro`
proves reproducibility. Stage 4 **[planned]**: RPM `edge-fwsec` (Requires:
nftables, NetworkManager, selinux-policy; systemd units; SELinux module),
idempotent DNF installer `install.sh`, and one ISO per architecture via
`mkksiso` over verified official media, both converging on the same RPM and
the same `efwctl bootstrap`.
