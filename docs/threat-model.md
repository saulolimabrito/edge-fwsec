# Threat model — Edge FWSec v1

Scope: a single-node appliance exposed to a hostile WAN, with one or more
LANs and a management network. Review at every stage; each mitigation has a
matching verification in the checklist.

## Assets

1. Availability of forwarding and of management access.
2. Integrity of the active policy and of stored revisions.
3. Admin credentials, TLS key, session key, bootstrap credential.
4. Configuration backups (they contain the policy and, if included, secrets).
5. Integrity of distributed artifacts (RPM, ISO, installer).

## Trust boundaries

| Boundary | From → to | Note |
|---|---|---|
| WAN → appliance | Internet → kernel/nftables | No management service exposed by default. |
| Management network → `efw-web` | admin → HTTPS | Authenticated, CSRF, rate limited. |
| `efw-web` → `efw-agent` | unprivileged → root | Unix socket, typed protocol, revalidation in the agent. |
| Local console → `efwctl` | physical operator → root | Recovery; trust by physical/console access. |
| Build → appliance | CI/maintainer → RPM/ISO | GPG signatures, checksums, SBOM. |

## Threats and mitigations

| # | Threat | Mitigation | State |
|---|---|---|---|
| T1 | Console reachable from the WAN | Ruleset: console port accepted only on management interfaces; validation refuses the WAN as a management interface; scenario confirms it is blocked from `efw-inet` (v4/v6). Server side: requests are refused unless the local address belongs to a management interface (or a bootstrap interface before the first configuration) and the source matches `admin.sources` (`TestMgmtAccessBeforeAndAfterConfig`, `TestAccessRestriction`). Missing: end-to-end check on an installed appliance (stage 4). | active |
| T2 | Compromise of `efw-web` becomes root | Process separation; the agent accepts only typed operations, strict per-op fields, 1 MiB limit; no shell; caller recorded via SO_PEERCRED; socket 0660 (unprivileged users refused, tested). systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, capability bounding, syscall filter, dedicated `efw-web` user with only `CAP_NET_BIND_SERVICE`) and confined SELinux domains `efw_web_t` / `efw_agent_t`, validated enforcing with 0 AVCs. | active |
| T3 | nftables rule injection | Structured model → validation → Go generator; identifiers and devices restricted to a charset that needs no escaping; addresses via `netip`; never free text from the API; `nft` via `exec` with stdin, no shell. Tests: `internal/policy`, `internal/nft`. | active |
| T4 | A change locks the administrator out | Apply with a deadline, automatic rollback owned by the agent, NetworkManager checkpoint with its own timer as a second net, recovery from the console (`efwctl recover`). Tested: LAN cut and console moved off the management network are both undone. Planned: UI warning when the current path would be cut. | active |
| T5 | Reboot/crash mid-change leaves an inconsistent state | `testing` persisted before applying; at startup the agent rolls back the checkpoint and restores the confirmed ruleset before opening the socket. Tested with `kill -9`, simulated reboot, NM restart, and on an installed VM with a clean reboot (rollback on SIGTERM) and a hard power cut (abandoned at boot). | active |
| T6 | Login brute force | 10 attempts per address per 5 min; per-user lockout doubling from 30 s to 15 min; Argon2id; constant-time path for unknown users; failures logged (`TestLoginLockout`, `TestLimiter`). | active |
| T7 | CSRF / session hijacking | `__Host-` cookie, `Secure`, `HttpOnly`, `SameSite=Strict`; per-session CSRF token and same-origin check on mutations; 15 min idle / 8 h absolute expiry; logout and password change end sessions (`TestAuthFlow`, `TestSessionsExpire`). | active |
| T8 | XSS in the console | Svelte escapes by default; CSP without inline (active since stage 1); no `{@html}`. | active |
| T9 | Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY`. | active |
| T10 | Bootstrap credential reused or leaked | Issued only by root on the console (`efwctl bootstrap`), 120 bits, 24 h default, stored hashed, deleted on use, rate limited (`TestBootstrapIsSingleUseAndExpires`). | active |
| T11 | Backup exposes secrets | Backups contain only the policy; accounts, hashes and TLS keys are never exported (`TestRoundTrip` checks the output). Encrypted inclusion of secrets is not offered in v1. | active |
| T12 | Malicious or old backup restored | Strict envelope, newer schemas refused, registered migrations for older ones, full validation, then the normal validate/diff/apply-with-deadline flow (`TestRejects`, `TestSchema1BackupStaysReadable`). | active |
| T13 | Tampered artifact | Signed RPM and ISO; the installer verifies the signature before installing; reproducible build (`make repro`). | partial (repro active) |
| T14 | Interference with third-party rules or profiles | Only owned tables, atomic replacement, never `flush ruleset` (`TestOnlyOwnedTables` + scenario with a foreign table). NetworkManager: only `efw-` profiles with the derived UUID; checkpoints never cover all devices (foreign profile and `eth0` untouched, tested). | active |
| T15 | Resource exhaustion in `efw-web` | Read/write/header timeouts and header limit (active); body limit on mutations. | partial |
| T16 | IPv6 open by omission | inet chains with a drop policy for both families; restricted essential ICMPv6 (RFC 4890); IPv6 scenarios with real traffic. | active |
| T17 | Journal flooding by firewall logging | Default-policy log limited to 10/s (burst 20). | active |
| T19 | Weak or mismatched custom certificate | Upload validates the pair, validity period, server-auth usage, ECDSA P-256/P-384 or RSA ≥ 2048; a refused upload leaves the active certificate unchanged (`TestRejectsBadCustom`). | active |
| T18 | Corrupted state after power loss | Atomic writes with file and directory `fsync`; a corrupt `state.json` stops the agent instead of resetting; torn audit lines ignored. | active |

## Accepted risks in v1

- No HA: a hardware failure interrupts service.
- No MFA in v1 (to evaluate after v1).
- The local console with physical access is trusted.
