# Edge FWSec

An edge firewall appliance for Rocky Linux 10 (x86_64 with x86-64-v3, and
aarch64): stateful firewall with nftables, routing, VLANs and NAT through
NetworkManager, managed from its own web console.

**Status:** stages 1–3 implemented: policy engine, privileged agent (apply
with a confirmation deadline, automatic rollback, NetworkManager checkpoints,
console recovery) and an authenticated HTTPS console with the full change
flow. No packages, systemd units or ISO yet (stage 4). Not for production use.

## Run locally

Requires Go ≥ 1.25 and Node.js ≥ 22.

```bash
make check
```

```bash
make run
```

`make run` starts a local stack that never touches this machine's network
(the agent uses a fake `nft`) and prints a one-time credential. Open
https://127.0.0.1:8443 (self-signed certificate), or run `cd ui && npm run dev`
and open http://localhost:5173.

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
