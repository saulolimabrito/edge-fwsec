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
| T1 | Console reachable from the WAN | Loopback-only bind until stage 3 (code). Ruleset: console port accepted only on management interfaces; validation refuses the WAN as a management interface; scenario confirms it is blocked from `efw-inet` (v4/v6). Missing: the real service behind the rule (stage 3). | partial |
| T2 | Compromise of `efw-web` becomes root | Process separation; the agent accepts only typed operations, strict per-op fields, 1 MiB limit; no shell; caller recorded via SO_PEERCRED; socket 0660 (unprivileged users refused, tested). Planned: systemd `NoNewPrivileges`, `ProtectSystem=strict`, dedicated user; SELinux. | partial |
| T3 | nftables rule injection | Structured model → validation → Go generator; identifiers and devices restricted to a charset that needs no escaping; addresses via `netip`; never free text from the API; `nft` via `exec` with stdin, no shell. Tests: `internal/policy`, `internal/nft`. | active |
| T4 | A change locks the administrator out | Apply with a deadline, automatic rollback owned by the agent, NetworkManager checkpoint with its own timer as a second net, recovery from the console (`efwctl recover`). Tested: LAN cut and console moved off the management network are both undone. Planned: UI warning when the current path would be cut. | active |
| T5 | Reboot/crash mid-change leaves an inconsistent state | `testing` persisted before applying; at startup the agent rolls back the checkpoint and restores the confirmed ruleset before opening the socket. Tested with `kill -9`, simulated reboot, NM restart. Real reboot with systemd: stage 4. | active |
| T6 | Login brute force | Rate limit per IP and per user, exponential delay, Argon2id hashes, audit. | planned |
| T7 | CSRF / session hijacking | `__Host-` cookie, `Secure`, `HttpOnly`, `SameSite=Strict`; per-session CSRF token on mutations; idle and absolute expiry. | planned |
| T8 | XSS in the console | Svelte escapes by default; CSP without inline (active since stage 1); no `{@html}`. | active |
| T9 | Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY`. | active |
| T10 | Bootstrap credential reused or leaked | Single use, expiry, shown only on the local console, invalidated after the first login. | planned |
| T11 | Backup exposes secrets | Secrets excluded by default; optional inclusion encrypted with a passphrase (AES-GCM + KDF); 0600 permissions. | planned |
| T12 | Malicious or old backup restored | Schema validation, versioned migrations, goes through the same validate/diff/apply-with-deadline flow. | planned |
| T13 | Tampered artifact | Signed RPM and ISO; the installer verifies the signature before installing; reproducible build (`make repro`). | partial (repro active) |
| T14 | Interference with third-party rules or profiles | Only owned tables, atomic replacement, never `flush ruleset` (`TestOnlyOwnedTables` + scenario with a foreign table). NetworkManager: only `efw-` profiles with the derived UUID; checkpoints never cover all devices (foreign profile and `eth0` untouched, tested). | active |
| T15 | Resource exhaustion in `efw-web` | Read/write/header timeouts and header limit (active); body limit on mutations. | partial |
| T16 | IPv6 open by omission | inet chains with a drop policy for both families; restricted essential ICMPv6 (RFC 4890); IPv6 scenarios with real traffic. | active |
| T17 | Journal flooding by firewall logging | Default-policy log limited to 10/s (burst 20). | active |
| T18 | Corrupted state after power loss | Atomic writes with file and directory `fsync`; a corrupt `state.json` stops the agent instead of resetting; torn audit lines ignored. | active |

## Accepted risks in v1

- No HA: a hardware failure interrupts service.
- No MFA in v1 (to evaluate after v1).
- The local console with physical access is trusted.
