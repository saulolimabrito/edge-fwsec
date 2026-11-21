# AGENTS.md — Edge FWSec

Instructions for whoever (person or agent) continues this project. Also read
`docs/architecture.md`, `docs/threat-model.md` and `docs/release-checklist.md`;
these four files are the reference between sessions. The next concrete step
is always at the top of the checklist.

## What it is

A single-node edge firewall appliance on Rocky Linux 10 (x86_64 with the
x86-64-v3 baseline, and aarch64). Go backend; Svelte 5 + TypeScript + Vite
console embedded in the binary with `go:embed`. nftables for filtering and
NAT, NetworkManager for interfaces, VLANs and routes.

## Commands

| Goal | Command |
|---|---|
| Full check (gofmt, vet, Go tests, svelte-check, vitest) | `make check` |
| Go tests with the race detector | `make test-race` |
| Local build (UI + host binaries) | `make build` |
| Appliance binaries (linux x86_64 v3 + aarch64) and `dist/SHA256SUMS` | `make linux` |
| Reproducible-build proof (two builds, hashes compared) | `make repro` |
| Local stack: agent (fake `nft`, no network changes) + HTTPS console on 127.0.0.1:8443, prints a bootstrap credential | `make run` |
| UI dev server on http://localhost:5173 proxying to the local stack | `cd ui && npm run dev` |
| Issue a one-time administrator credential (appliance console) | `efwctl bootstrap [hours]` |
| Validate / render / kernel-check a configuration | `efwctl policy validate\|render\|check <file>` |
| Refresh the generator's golden output (review the diff!) | `go test ./internal/nft -update` |
| Test topology (disposable VM only, as root) | `EFW_TEST_VM=1 tests/topology/netns.sh up\|verify\|down` |
| Policy traffic scenarios (disposable VM, root) | `EFW_TEST_VM=1 tests/policy/scenarios.sh <efwctl> internal/policy/testdata/edge.json tests/topology/netns.sh` |
| Agent lifecycle: confirm, deadline, kill -9, reboot, recover (VM, root) | `EFW_TEST_VM=1 tests/agent/lifecycle.sh dist/linux-aarch64 internal/policy/testdata/edge.json tests/topology/netns.sh tests/policy/httpd.py` |
| NetworkManager checkpoints on a real NM (VM root namespace, root) | `EFW_TEST_VM=1 tests/nm/checkpoint.sh dist/linux-aarch64` |
| Build RPM sources for both architectures (then `rpmbuild` on a Rocky 10 builder) | `make rpm-src` |
| Build an ISO from verified official media (Rocky 10 builder with lorax) | `packaging/iso/build-iso.sh --iso IN --rpm RPM --key KEY --out OUT [--test-ssh-key PUB]` |
| Installed-appliance end to end (installed VM, root, run detached) | `EFW_TEST_VM=1 tests/install/e2e.sh phase1\|phase2\|reboot-check [mgmt-dev]` |
| Compare two installs (ISO vs installer) | `tests/install/fingerprint.sh` on each, then `diff` |
| Local test VM (macOS, Lima) | `limactl start --name=efw-dev --mount-none template:rocky-10` |

Linux tests from macOS: build the test binary with
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/<pkg>`, copy it
with `limactl copy` and run it in the `efw-dev` VM. Never run `netns.sh`,
`nft` or `nmcli` on the development workstation.

## Layout

```
cmd/efw-web     unprivileged web server (console + API)
cmd/efw-agent   privileged service: revision store, apply/confirm/rollback, recovery
cmd/efwctl      local diagnostics and recovery CLI
internal/       Go packages: sysinfo, web (API, access check), auth (accounts, bootstrap,
                sessions, limiter), tlsutil, backup, version, policy (model + validation),
                nft (generator + loader), nm (NetworkManager profiles + checkpoints),
                store (revisions), agent (state machine + socket protocol), fsutil, textdiff
ui/             Svelte console; `ui/dist` is generated and embedded (only `.keep` is tracked)
tests/topology  WAN/LAN/VLAN/MGMT topology in network namespaces
tests/policy    policy traffic scenarios (44 checks)
tests/agent     agent lifecycle with real traffic (38 checks)
tests/nm        NetworkManager checkpoint lifecycle (46 checks)
docs/           architecture, threat model, checklist, topology, support matrix
```

## Conventions

- Go: standard library unless there is a documented reason. Current
  exceptions: `github.com/godbus/dbus/v5` (NetworkManager D-Bus API) and
  `golang.org/x/crypto/argon2` (password hashing).
  `gofmt`; errors carry context; no `panic` on request paths.
- Frontend: Svelte 5 runes, strict TypeScript, no inline CSS/JS (the CSP
  blocks `style=` attributes and inline scripts), no external fonts or
  assets (the appliance works offline). Color tokens live in `ui/src/app.css`.
- Values the kernel did not report are `null` in the API and "—" in the UI.
  Never show zero or an invented metric.
- npm dependencies pinned (`--save-exact`) and `package-lock.json` tracked.
  TypeScript pinned to 6.x: `svelte-check` 4.7 still needs a dual setup for TS 7.
- Small, imperative commits in English; each stage updates the checklist with
  what was verified and how.
- Single authorship: `Saulo Brito <100214355+saulolimabrito@users.noreply.github.com>`.
  Commits, merges, PRs and issues carry no `Co-Authored-By` trailers or
  generator-tool footers.
- Language: all documentation (this file, README, `docs/`, issues, release
  notes) is written in English (en-US). Code, identifiers and UI text are
  English too.

## Security invariants (do not break)

1. `efw-web` never runs commands or changes the system. Changes go through
   `efw-agent` over a Unix socket (0660, dedicated group) with a typed,
   per-operation protocol, validated on both sides. No shell, no arbitrary
   commands, no free-text nftables from the API.
2. The console is HTTPS only and every API call except session discovery,
   login and bootstrap needs a session; mutations need the CSRF token and a
   same-origin request. Requests are served only on management-interface
   addresses (or loopback), checked server side in addition to nftables.
3. The project only changes the nftables tables it owns (`inet efw_filter`
   and `ip efw_nat`), by atomic replacement; never `flush ruleset`. Foreign
   tables are preserved. NetworkManager profiles are owned only when the id
   starts with `efw-` and the UUID is the derived v5 UUID; others are never
   modified.
4. Every change is applied with a deadline enforced by the service; without
   confirmation it returns to the last confirmed revision — also after a
   process or machine restart.
5. SELinux stays enforcing. No `setenforce 0` in scripts, tests or docs.
6. Tests that change network, firewall, disk or boot run only in a
   disposable VM or their own namespaces (`EFW_TEST_VM=1`). The development
   workstation's network, firewall and credentials are never touched.
7. Secrets (password hashes, TLS key, session key) never reach logs,
   unencrypted backups or API responses.
8. Reproducible builds: `-trimpath`, `-buildvcs=false`, `-buildid=`,
   `SOURCE_DATE_EPOCH` from the last commit, `CGO_ENABLED=0`. `make repro`
   must pass before any release.

## Verified environment

- Development: macOS arm64, Go 1.27.4, Node 26, npm.
- Test VM: Lima `efw-dev`, Rocky Linux 10.3 aarch64 (GenericCloud image, not
  Minimal), kernel 6.12.0-264, NetworkManager 1.58.0, SELinux enforcing. The
  image ships without nftables and firewalld; nftables 1.1.5 was installed
  with `dnf` for the tests.
- Rocky's udev rules leave veth devices unmanaged by NetworkManager unless
  they are named `eth<digit>…`; `tests/nm` relies on that.
- The `rocky10-kea` VM belongs to another project and `efw-codex-restore` to a parallel
  workstream: do not use or modify them. Lima test VMs here use `.ssh.overVsock=false`
  (the vsock SSH forwarder looped after stops and filled the host log).
- QEMU on macOS (Apple Silicon): `-machine virt,accel=hvf -cpu host`, EDK2 from
  `/opt/homebrew/share/qemu/edk2-aarch64-code.fd`, console on `ttyAMA0`. macOS `tar` reads
  ISO 9660 (`hdiutil` cannot mount the hybrid ISOs).
