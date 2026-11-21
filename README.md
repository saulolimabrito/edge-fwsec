# Edge FWSec

An edge firewall appliance for Rocky Linux 10 (x86_64 with x86-64-v3, and
aarch64): stateful firewall with nftables, routing, VLANs and NAT through
NetworkManager, managed from its own web console.

**Status:** stage 3 of 5 in progress. The policy engine and the privileged
agent work (apply with a confirmation deadline, automatic rollback,
NetworkManager checkpoints, console recovery); the web console is still
read-only and there are no packages yet. Not for production use.

## Run locally

Requires Go ≥ 1.25 and Node.js ≥ 22.

```bash
make check
```

```bash
make run
```

Open http://127.0.0.1:8080. Without TLS and authentication the server refuses
any address other than loopback.

Appliance binaries (static, reproducible):

```bash
make linux
```

## Documentation

- [AGENTS.md](AGENTS.md) — commands, conventions and security invariants
- [docs/architecture.md](docs/architecture.md)
- [docs/threat-model.md](docs/threat-model.md)
- [docs/release-checklist.md](docs/release-checklist.md) — progress and next step
- [docs/test-topology.md](docs/test-topology.md)
- [docs/support-matrix.md](docs/support-matrix.md)
