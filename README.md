# Edge FWSec

Appliance de firewall de borda para Rocky Linux 10 (x86_64 x86-64-v3 e
aarch64): firewall stateful com nftables, roteamento, VLAN e NAT via
NetworkManager, administrado por uma console web própria.

**Estado:** etapa 1 de 5 — console somente leitura com dados reais de
interfaces. Ainda não aplica políticas. Não use em produção.

## Rodar localmente

Requer Go ≥ 1.25 e Node.js ≥ 22.

```bash
make check
```

```bash
make run
```

Abra http://127.0.0.1:8080. Sem TLS e autenticação o servidor recusa
endereços que não sejam loopback.

Binários do appliance (estáticos, reproduzíveis):

```bash
make linux
```

## Documentação

- [AGENTS.md](AGENTS.md) — comandos, convenções e invariantes de segurança
- [docs/architecture.md](docs/architecture.md)
- [docs/threat-model.md](docs/threat-model.md)
- [docs/release-checklist.md](docs/release-checklist.md) — progresso e próximo passo
- [docs/test-topology.md](docs/test-topology.md)
- [docs/support-matrix.md](docs/support-matrix.md)
