# Release checklist — Edge FWSec v1.0.0

Rule: an item is only checked with evidence (command, environment, date,
result). The `v1.0.0` tag is created only when every acceptance criterion is
checked.

## ▶ Next concrete step

Stage 4, x86_64 ISO on the CI KVM runner (run 44944896846 proved KVM + UEFI
boot of the official media there): build `edge-fwsec-*-x86_64-test.iso` with
`packaging/iso/build-iso.sh` from the verified x86_64 Minimal ISO and the
x86_64 RPM, install it offline (no NIC) in UEFI, boot from disk, run
`tests/install/e2e.sh phase1` and `tests/install/fingerprint.sh`, and compare
with an installer-path install on the same runner. Then the release key and
SBOM attachment for the pre-release.

## External items / blockers

| Item | Command | Result | What is missing |
|---|---|---|---|
| License ([#5](https://github.com/saulolimabrito/edge-fwsec/issues/5)) | — | not chosen; the repository is already public | Maintainer decision (e.g. GPL-3.0, Apache-2.0). |
| Rocky 10 Minimal: is firewalld installed by default? ([#6](https://github.com/saulolimabrito/edge-fwsec/issues/6)) | clean offline installs of the official 10.3 Minimal media, UEFI, no NIC: aarch64 (QEMU 11.1.3/HVF) and x86_64 (KVM, CI run 44944896846) | **yes: `firewalld-2.4.3-4.el10_2` enabled and active**; `nftables-1.1.5-6.el10_2` installed; SELinux enforcing | Resolved: the installer requires `--replace-firewalld` (snapshot + `--restore-firewalld`); the Edge FWSec ISO excludes firewalld. |
| x86_64 VM ([#7](https://github.com/saulolimabrito/edge-fwsec/issues/7)) | CI run 44944896846 | a GitHub Ubuntu runner with KVM installed the official x86_64 Minimal ISO offline and booted it in UEFI | Use that runner for the x86_64 appliance ISO and installer tests. |

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

- [x] Fixed-address IPv4 SNAT with real TCP traffic. On Rocky Linux 10.3
  aarch64 with SELinux enforcing, `tests/policy/scenarios.sh` passed 40/40
  on 2026-11-21. The upstream HTTP server observed the configured secondary
  WAN address (203.0.113.99) and the LAN client received HTTP 200.

- [x] DHCP client firewall rules with real UDP traffic under the default
  drop policy. On Rocky Linux 10.3 aarch64 with SELinux enforcing,
  `tests/policy/scenarios.sh` passed 44/44 on 2026-11-21. A DHCPv4 broadcast
  from WAN and a link-local DHCPv6 packet reached the client ports, while
  packets using a different interface, source or server port were dropped.

DHCP lease acquisition belongs to the installed-appliance tests. Hairpin
NAT is out of scope for v1 (support matrix).

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
- [x] Real VM reboot during a pending change (see Stage 4: clean shutdown and power cut)
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
- [x] UI flows against an installed appliance with real nftables and NetworkManager,
  including reconnecting and confirming through a new management address (see Stage 4)

## Stage 4 — Distribution

- [x] RPMs for x86_64 and aarch64 built (`make rpm-src` + `rpmbuild` in `efw-dev`), signed with a
  TEST key (release key pending), dependencies declared; deterministic GNU build-id per binary.
- [x] Installer (`packaging/install.sh`): checks Rocky 10, architecture (x86-64-v3), signature
  against only the given key, NetworkManager, SELinux, conflicting firewall services; refuses an
  unsigned package; dry run changes nothing; upgrade 0.1 → 0.2 kept `/etc/edge-fwsec/web.env`.
- [x] Installed-appliance end to end (`tests/install/e2e.sh phase1`, 2026-11-21, `efw-inst`,
  SELinux domains permissive while collecting denials): 20/20 — bootstrap via API, NetworkManager +
  nftables applied, confirm, masquerade, console unreachable from WAN/LAN, deadline rollback.
  Defects found and fixed: `nnp_transition` needed for NoNewPrivileges units and for nft;
  sd_notify socket labelled `kernel_t`; isolated rpm keyring needs `rpm_var_lib_t`.
- [x] SELinux confined domains `efw_agent_t` / `efw_web_t` in enforcing mode (`efw-inst`,
  edge-fwsec 0.4.0-0.3, module efw 1.0.2, 2026-11-21): `tests/install/e2e.sh phase1` 20/20 with
  0 AVC/SELINUX_ERR records during the run; services confirmed in their domains with `ps -eZ`.
  Denials found and fixed during convergence (domains temporarily permissive, then removed):
  `nnp_transition` for the units and for nft, sd_notify socket labelled `kernel_t`,
  `/proc/sys/net` reads by the agent and by Go's listener.
- [x] Real reboot during a pending change, enforcing, 0 AVCs, on `efw-inst`:
  clean shutdown → agent rolled back revision 7 on SIGTERM; hard power cut
  (`limactl stop --force`) → revision 8 abandoned at boot ("abandoned revision left under
  test"); after both, confirmed revision 5 active (ruleset, LAN address, LAN egress), checked
  with `e2e.sh reboot-check` (6/6). Note: Lima's SSH-over-vsock forwarder looped after a stop
  (`accept: bad file descriptor`, 4 GB log); fixed with `.ssh.overVsock=false` on the test VM.
- [x] Upgrade 0.2 → 0.3 with the installer kept configuration, accounts and confirmed revision.
- [ ] Signed RPMs with the release key
- [x] SELinux module and hardened systemd units, validated in enforcing mode (see below)
- [ ] Idempotent installer (checks Rocky 10, architecture, signature, conflicts)
- [ ] Explicit and reversible firewalld transition
- [x] aarch64 ISO (2026-11-21): `packaging/iso/build-iso.sh` (mkksiso, lorax 40.5.19) over
  `Rocky-10.3-20261113.0-aarch64-minimal.iso`, re-verified here: SHA-256 OK and good signature
  from "Release Engineering (Rocky Linux 10)", key fingerprint
  FC22 6859 C086 0BF0 DDB9 5B08 5B10 6C73 6FED FC85. The ISO carries the same signed RPM
  (sha256 e05513853953…) in an on-disc repository and records provenance in `BUILD-INFO`.
  - Test variant, QEMU 11.1.3/HVF, EDK2 UEFI, **no NIC**: unattended install completed offline;
    boot from disk: Rocky 10.3, SELinux enforcing, 0 AVCs, firewalld not installed, services
    active in `efw_agent_t` / `efw_web_t`; `efw-firstboot` chose the management interface and
    the local serial console showed the console URL and the one-time credential.
    `tests/install/e2e.sh phase1` on that install: 20/20, 0 AVC/SELINUX_ERR.
  - Release variant: boots to Anaconda's text hub with `[!] Installation Destination`,
    `[!] Root password`, `[!] User creation` waiting for the operator; installation source and
    software selection preconfigured; the blank disk stayed untouched (196 KiB qcow2).
- [x] ISO vs installer comparison on aarch64 with the same RPM: `tests/install/fingerprint.sh`
  (package and `rpm -V`, services, domains, effective sandbox, accounts, modes/owners/SELinux
  labels, sysctl) is identical (35 lines). The first comparison found two differences, both from
  the installer preparing first access with its own code; fixed by making the installer use the
  same `efwctl firstboot` / `efw-firstboot.service` as the ISO.
- [x] aarch64 ISO install, hard power cut during a pending change (2026-11-22, QEMU/HVF):
  `e2e.sh phase2` + `kill -9` of QEMU + `reboot-check` 6/6, enforcing, 0 AVCs.
- [x] Console flow on the ISO-installed appliance (2026-11-22, browser through the UI dev server
  proxied to the appliance's real API): sign in, change the management address
  (DHCP → static 10.0.2.20/24) in Network, validated diff with the management-access warning,
  apply with a 5-minute window; the old tab reports that the appliance stopped answering and
  shows the new address and the time limit; sign-in through the new address shows the
  countdown banner; Keep changes → revision 5 confirmed; history records author, time and
  result. Defects found and fixed (commit "Never let a failed network change survive its
  rollback"): a profile whose device was absent (veth gone after reboot) failed the whole
  change; an activation still in flight completed after the checkpoint rollback and left the
  new management address with no revision under test; recovery after a power cut logged
  `network rollback failed` for the same reason; the console waited forever when an apply
  moved its own address. After the fix: the same flow succeeds, and a repeated power cut
  records no network rollback failure and restores the confirmed address.
- [x] Offline upgrade of an ISO-installed appliance (no internet): the installer retries with
  the local package only when the configured repositories are unreachable (0.4 → 0.5 kept
  configuration, services active, enforcing).
- [ ] Release builds from a clean tag: the 0.4 test RPM reported version `a8a2210-dirty`
  (built before its changes were committed); 0.5 reports `32c0ca0`.
- [ ] x86_64 ISO built, installed offline in UEFI and compared (CI KVM runner)
- [ ] Pre-release: clean install and upgrade

## v1.0.0 acceptance criteria

- [ ] Four complete VM installs: installer and ISO on x86_64 and aarch64.
- [ ] The ISO installs without network, boots the appliance and reaches first access. (aarch64 done; x86_64 pending)
- [ ] Both install paths deliver the same version and hardening profile per architecture.
- [ ] The console works from authorized networks and is unreachable from the WAN in the default profile.
- [ ] IPv4, IPv6, VLANs, routes, stateful firewall and NAT pass with real traffic, per the support matrix.
- [ ] Invalid change, connectivity loss, timeout, service restart and reboot during a pending change are tested, with recovery recorded.
- [ ] Confirmed configuration persists across reboot; reinstall, upgrade and restore preserve the configuration.
- [ ] SELinux enforcing with services working under the intended permissions.
- [ ] Release contains installer, RPMs, ISOs, checksums, signatures, SBOM, guides and support matrix; tests on virtual ARM and on physical hardware are identified.
