# Release checklist — Edge FWSec v1.0.0

Rule: an item is only checked with evidence (command, environment, date,
result). The `v1.0.0` tag is created only when every acceptance criterion is
checked.

## ▶ Next concrete step

Stage 4, first increment: systemd units (`efw-agent.service` before
`network-online.target`, `efw-web.service` as a dedicated user with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, both with `ProtectSystem=strict`,
`NoNewPrivileges` and explicit `ReadWritePaths`), `/etc/sysctl.d` for
forwarding, and an RPM spec that installs binaries, units, users and state
directories. Before applying a policy on an installed VM, add SSH access on
management interfaces to the model (schema 2, with a migration from schema 1
and a test using the pinned schema-1 backup) so an installed appliance stays
reachable for recovery. Then install the RPM on a fresh disposable Rocky 10
VM (not `efw-dev`'s root namespace) and run the full flow through the UI,
including a real reboot during a pending change.

## External items / blockers

| Item | Command | Result | What is missing |
|---|---|---|---|
| License ([#5](https://github.com/saulolimabrito/edge-fwsec/issues/5)) | — | not chosen; the repository is already public | Maintainer decision (e.g. GPL-3.0, Apache-2.0). |
| Rocky 10 Minimal: is firewalld installed by default? ([#6](https://github.com/saulolimabrito/edge-fwsec/issues/6)) | — | not verified (current VM is GenericCloud, without firewalld or nftables) | Install from the official Minimal ISO in a VM and record `rpm -q firewalld nftables`. |
| x86_64 VM ([#7](https://github.com/saulolimabrito/edge-fwsec/issues/7)) | — | not available locally (Apple Silicon host) | x86_64 host or runner with KVM for installer/ISO tests and UEFI boot. |

Repository: https://github.com/saulolimabrito/edge-fwsec (public, created
2026-11-21). Per-stage tracking in issues #1–#4.

## Stage 1 — Runnable base ✅ (2026-11-21)

- [x] Go + Svelte: `efw-web` serves the compiled UI via `go:embed`; read API
  `/api/v1/{version,system,interfaces}` with real kernel data.
  Evidence: `make check` on macOS → gofmt/vet OK, `go test` 3 packages OK,
  `svelte-check` 0 errors/0 warnings, vitest 6/6.
- [x] Linux tests on Rocky 10.3 aarch64 (`efw-dev` VM): cross-built test
  binaries `sysinfo`, `web`, `efw-web` → PASS (8 tests in sysinfo, including
  a real rtnetlink read).
- [x] VLAN detected without privileges: `efw-web` as uid 501 reports
  `efwdum0.20 vlan 20 on efwdum0`. Defect found and fixed:
  `/proc/net/vlan/*` is `0600 root`; it now uses `RTM_GETLINK`.
- [x] Safety guard: `efw-web -listen 0.0.0.0:8080` → refused, exit 2
  (verified in the VM).
- [x] Reproducible build: `make repro` → two builds with a rebuilt UI,
  identical `SHA256SUMS` for `linux-x86_64` (GOAMD64=v3) and `linux-aarch64`;
  static ELF binaries checked with `file`.
- [x] Console reviewed in a browser against the VM: overview, interfaces,
  rate derived from two samples, "API unreachable" state that keeps stale
  data with a warning, `1`/`2`/`r` shortcuts, visible focus, 375 px layout.
  Defects fixed: collapsed spaces in "vid"/"link"; mobile grid splitting the
  viewport height.
- [x] `efwctl version|system|interfaces [--json]` verified in the VM.
- [x] WAN/LAN/VLAN/MGMT topology defined and verified
  (`docs/test-topology.md`): 3×10/10 PASS in the VM.
- [x] GitHub CI green (run 44934235705): `check` (make check + make repro +
  netns topology 10/10) on ubuntu-24.04 x86_64 and ubuntu-24.04-arm; Go tests
  in a Rocky Linux 10.3 container on both architectures. The first run failed
  because the `rockylinux:10` container declares no PATH and `setup-go`
  replaced it; fixed by pinning PATH in the container.

Open from stage 1: the light theme was not reviewed visually (dark only).

## Stage 2 — Policy engine ✅ (2026-11-21)

Environment: `efw-dev` VM (Rocky 10.3 aarch64, kernel 6.12.0-264, nftables
1.1.5). Command: `EFW_TEST_VM=1 tests/policy/scenarios.sh` → 36/36 PASS in 3
consecutive runs; no namespaces or tables left behind.

- [x] Versioned model (`schema_version: 1`) + validation:
  `go test ./internal/policy` (valid fixture, strict decoding, canonical
  round trip, 32+ error cases with paths, rule families).
- [x] Generator with golden test (`internal/nft/testdata/edge.nft`),
  determinism, refusal of invalid configs, owned tables only, set
  normalization.
- [x] nftables 1.1.5 semantics verified in the VM: the
  declare/`delete table`/redefine idiom works whether the table exists or
  not and swaps the chain policy; a failing batch leaves the previous table
  intact; `nft -c` catches semantic errors; `iif` needs an existing device
  (hence `iifname`). Official docs: `nft -f` applies in one atomic operation
  (nftables wiki, "Atomic rule replacement").
- [x] `efwctl policy validate|render|check`.
- [x] Stateful allow/deny for IPv4 and IPv6 with real traffic.
- [x] Masquerade (destination sees 203.0.113.2) and IPv4 port forward with
  the client source preserved and the associated forward rule; IPv6 routed
  without NAT.
- [x] Essential ICMPv6 under a drop policy: ND after flushing neighbours and
  Packet Too Big forwarded (client learns PMTU 1280).
- [x] Console port: 443 accepted only from the management network (v4/v6),
  blocked from the WAN and the LAN.
- [x] VLAN 30 (guests) with reject distinguished from drop, and kernel log.
- [x] Foreign table preserved; idempotent re-apply; broken batch refused
  without changing the ruleset.
- [x] Scenarios in CI: run 44935781368, `scenarios.sh` 36/36 on ubuntu-24.04
  (x86_64) and ubuntu-24.04-arm (Ubuntu kernel and nftables; Rocky 10 is
  covered by the VM).

Defects found and fixed: a mixed IPv4/IPv6 object was refused in a
single-family rule (it is now filtered); default-policy log had no limit (now
10/s); the VLAN client had no namespace of its own in the topology; the test
server hung in `getfqdn()`.

Open (not blocking stage 3): SNAT to a fixed address and DHCP/DHCPv6 client
rules are only verified by rendering and `nft --check`, not with traffic;
hairpin NAT is out of scope for v1 (support matrix).

## Stage 3 — Full operation (in progress)

- [x] `efw-agent` + typed protocol on the Unix socket (0660, SO_PEERCRED),
  strict per-operation decoding; validation repeated in the agent.
  `go test ./internal/agent` (16 tests, including a real socket) + `make test-race`.
- [x] Revision store (testing/confirmed, immutable revisions), atomic
  writes, single-writer flock, optimistic concurrency on `base_revision`.
  `go test ./internal/store`.
- [x] Apply with deadline, confirm, rollback (nftables). `efw-dev` VM:
  `tests/agent/lifecycle.sh` 38/38 in 3 consecutive runs (2026-11-21); CI
  run 44936826705 38/38 on x86_64 and arm64.
  Follow-up (2026-11-21): run 44939988977 failed on both runners when the
  agent tried to connect to NetworkManager. The topology configures its
  interfaces and routes directly, so the lifecycle test now starts the
  agent with `-network none`. `tests/agent/lifecycle.sh` passed 38/38 on
  Rocky Linux 10.3 aarch64 with SELinux enforcing, real nftables traffic
  and the system D-Bus socket unavailable inside the test environment.
  NetworkManager checkpoints are covered by `tests/nm/checkpoint.sh`.
- [x] Invalid change refused with the field named and state untouched.
- [x] Connectivity loss: a rule that cuts the LAN and a change that moves the
  console off the management network are undone by the deadline; access
  restored (tested with traffic).
- [x] `kill -9` during a test → restart recovers the confirmed revision;
  simulated reboot (empty ruleset) → agent reapplies the confirmed revision;
  `SIGTERM` during a test rolls back; `efwctl recover` with the agent down.
- [x] NetworkManager checkpoints for interfaces/VLANs/routes, coordinated
  with the firewall (network first on apply, network restored first on
  rollback). `efw-dev` VM, NM 1.58.0: `tests/nm/checkpoint.sh` 46/46
  (2026-11-21): profiles applied (IPv4/IPv6 addresses, VLAN 40, static
  route), peers reach the appliance; deadline, explicit rollback, agent
  `kill -9` + restart and NM's own timer (agent dead) all restore the
  renumbered LAN and the removed VLAN; NetworkManager restart during a test
  drops the checkpoint (`Checkpoints` = `ao 0`, verified) and the agent
  rewrites the confirmed profiles instead; a foreign profile and the VM's
  `eth0` stay untouched.
  Defects found and fixed: NM 1.58 rejects `DISCONNECT_NEW_DEVICES` with an
  explicit device list (only `DELETE_NEW_CONNECTIONS` is used); a VLAN
  removed by the change did not come back because its device was not in the
  checkpoint (the checkpoint now also covers devices of existing owned
  profiles).
- [x] Recovery `efwctl`: `status`, `diff`, `apply`, `confirm`, `rollback`,
  `history`, `show`, `recover` (direct store access when the agent is down).
- [ ] Real VM reboot during a pending change (needs the systemd unit; stage 4)
- [ ] SSH access on management interfaces in the model (schema 2 + migration)
- [x] HTTPS with self-signed certificate and custom upload, one-time bootstrap,
  login, sessions, CSRF, rate limiting. `go test ./internal/auth ./internal/tlsutil
  ./internal/web` (TLS test server, real accounts, in-process agent).
- [x] Console restricted to the management network by default, server side
  (local address of a management interface, `admin.sources`; loopback always).
- [x] Backup download and restore preview with schema compatibility
  (`go test ./internal/backup`, pinned schema-1 backup).
- [x] UI flows reviewed in a browser against the local stack (`scripts/dev.sh`,
  fake `nft`, 2026-11-21): administrator setup with the one-time credential →
  First access wizard → Changes (validated diff) → apply with countdown banner
  on every page → Keep changes → History with author, time and result; rule
  added and reordered by keyboard; draft indicator; light and dark themes;
  375 px width without page-level horizontal scroll. Defects found and fixed:
  focus stayed on the old row after moving a rule; the rule editor did not
  receive focus; "rolls back to revision 0" wording; author spacing in
  History; the draft was lost on reload (now kept in `sessionStorage`, with a
  restore race fixed).
- [ ] UI flows against an installed appliance with real nftables and
  NetworkManager (stage 4 VM), including reconnecting through a new
  management address

## Stage 4 — Distribution

- [ ] Signed RPMs for x86_64 and aarch64 with declared dependencies
- [ ] SELinux module and hardened systemd units, validated in enforcing mode
- [ ] Idempotent installer (checks Rocky 10, architecture, signature, conflicts)
- [ ] Explicit and reversible firewalld transition
- [ ] One ISO per architecture (mkksiso over verified official media), offline install
- [ ] ISO vs installer comparison (services, permissions, SELinux, versions)
- [ ] Pre-release: clean install and upgrade

## v1.0.0 acceptance criteria

- [ ] Four complete VM installs: installer and ISO on x86_64 and aarch64.
- [ ] The ISO installs without network, boots the appliance and reaches first access.
- [ ] Both install paths deliver the same version and hardening profile per architecture.
- [ ] The console works from authorized networks and is unreachable from the WAN in the default profile.
- [ ] IPv4, IPv6, VLANs, routes, stateful firewall and NAT pass with real traffic, per the support matrix.
- [ ] Invalid change, connectivity loss, timeout, service restart and reboot during a pending change are tested, with recovery recorded.
- [ ] Confirmed configuration persists across reboot; reinstall, upgrade and restore preserve the configuration.
- [ ] SELinux enforcing with services working under the intended permissions.
- [ ] Release contains installer, RPMs, ISOs, checksums, signatures, SBOM, guides and support matrix; tests on virtual ARM and on physical hardware are identified.
