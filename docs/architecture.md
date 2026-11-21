# Arquitetura — Edge FWSec v1

Status: etapa 1 implementada (leitura). Seções marcadas **[planejado]** são o
contrato para as etapas seguintes; mudanças nelas exigem atualizar este
arquivo e o modelo de ameaças.

## Escopo da v1

Appliance single-node: firewall stateful, roteamento estático, NAT IPv4,
VLAN 802.1Q, administração web e CLI de recuperação. Fora da v1 (roadmap):
HA, BGP/OSPF, IDS/IPS, VPN, multi-WAN, plugins, NAT66/NPTv6.

## Processos

```
 navegador ──HTTPS──▶ efw-web (usuário efw-web, sem privilégios)
                         │  API JSON /api/v1, console embutido (go:embed)
                         │  socket Unix /run/efw/agent.sock (0660 root:efw-agent-clients)
                         ▼  protocolo tipado, uma operação por mensagem   [planejado]
                      efw-agent (root com capabilities restritas)
                         ├─ store de revisões  /var/lib/efw/
                         ├─ nftables (libnftables JSON via `nft -j -f -`, sem shell)
                         └─ NetworkManager (D-Bus: Settings, Checkpoint*)
 console local ──▶ efwctl (lê o store diretamente; root)
```

| Componente | Estado | Privilégio | Responsabilidade |
|---|---|---|---|
| `efw-web` | etapa 1: leitura | nenhum | API, sessões, CSRF, UI embutida. Nunca altera o sistema. |
| `efwctl` | etapa 1: leitura | root p/ recuperação | Diagnóstico; na etapa 3: listar revisões, reverter para a última confirmada, reemitir credencial de bootstrap. |
| `efw-agent` | planejado | root, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW` + D-Bus | Valida, aplica, temporiza e reverte mudanças. Dono do prazo de confirmação. |

### Leitura de estado (implementado)

`internal/sysinfo` lê `net.Interfaces`, `/sys/class/net/*/statistics`,
`operstate`, `uevent`, e rtnetlink `RTM_GETLINK` (`IFLA_LINKINFO`) para tipo
de link e VLAN ID. `/proc/net/vlan/*` é `0600 root` no Rocky 10 e por isso
não é usado no processo sem privilégios (verificado na VM). Valores ausentes
são `null`.

### API (implementado)

| Método | Caminho | Resposta |
|---|---|---|
| GET | `/healthz` | `{"status":"ok"}` |
| GET | `/api/v1/version` | versão, commit, data do build |
| GET | `/api/v1/system` | hostname, os-release, kernel, arquitetura, uptime |
| GET | `/api/v1/interfaces` | interfaces, endereços IPv4/IPv6, contadores, `observed_at` |

Qualquer outro método em `/api/` → 405; caminho desconhecido → 404 JSON.
Cabeçalhos: CSP `default-src 'self'` sem inline, `X-Frame-Options: DENY`,
`nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` na API.

## Modelo de configuração [planejado, etapa 2]

Documento único, versionado por `schema_version` (inteiro) e serializado em
JSON canônico. Entidades: `interfaces` (papel wan/lan/mgmt/opt, IPv4/IPv6
estático ou DHCP/SLAAC cliente), `vlans` (pai, VID 1–4094), `routes`
(família explícita), `objects.networks`, `objects.services`,
`firewall.rules` (lista ordenada; posição = ordem de avaliação),
`firewall.default_policy` por direção, `nat.source` (masquerade/SNAT, só
IPv4), `nat.port_forwards` (DNAT IPv4 + regra de forward associada gerada e
exibida), `admin` (redes autorizadas, certificado).

### Revisões

| Estado | Significado |
|---|---|
| `draft` | edição pendente de um usuário; baseada na revisão N (`base_revision`) |
| `testing` | revisão aplicada aguardando confirmação, com `deadline` |
| `confirmed` | última revisão confirmada; sobrevive a reboot |
| `rejected` / `rolled_back` | histórico, com motivo |

Store em `/var/lib/efw/revisions/<n>.json` + `state.json` atualizado por
escrita atômica (arquivo temporário + `fsync` + `rename` + `fsync` do
diretório). Concorrência: confirmar um draft exige `base_revision ==
confirmed` (controle otimista); conflito → 409 com diff.

## Fluxo de mudança [planejado, etapa 3]

1. **Validar** (web e agent): esquema, referências, sobreposição de
   prefixos, conflitos de NAT/port-forward, regra que corta o acesso de
   gerenciamento atual.
2. **Diff**: modelo (semântico) e ruleset nftables gerado.
3. **Aplicar com prazo** (padrão 120 s, máx. 600 s):
   - nftables: o lote completo das tabelas do projeto passa por
     `nft --check` e depois é aplicado em uma transação única
     (`delete table` + `add table` no mesmo arquivo carregado com `nft -f`),
     que é atômica no kernel.
   - rede: `CheckpointCreate` do NetworkManager com `rollback_timeout` = prazo
     + margem, sobre os dispositivos afetados; depois ativação dos perfis.
   - o agent grava `testing` + `deadline` no store **antes** de aplicar.
4. **Confirmar**: o agent chama `CheckpointDestroy`, marca `confirmed`.
5. **Reverter** (expiração, pedido explícito ou falha): reaplica o ruleset
   da última confirmada e `CheckpointRollback`; ordem: rede primeiro, depois
   firewall, para não deixar regras referenciando interfaces inexistentes.
6. **Recuperação no boot**: `efw-agent` inicia antes de `network-online`;
   se encontrar `testing`, descarta-a e aplica a confirmada. Checkpoints do
   NM não sobrevivem a reinício do NM, por isso os perfis do projeto são
   regravados a partir da revisão confirmada.

Mudança que altera IP/VLAN/rota de gerenciamento: a UI mostra o novo
endereço, o prazo e a instrução de reconectar e confirmar por ele; o agent
aceita a confirmação vinda de qualquer rede autorizada pela revisão em teste.

## Propriedade de recursos do sistema

- nftables: tabelas `inet efw_filter` e `ip efw_nat` (nomes reservados). O
  agent nunca executa `flush ruleset`. Tabelas de terceiros são preservadas
  e listadas no diagnóstico.
- NetworkManager: perfis com nome `efw-<papel>-<iface>` e
  `connection.uuid` registrado no store. Perfis alheios não são editados;
  a configuração inicial só adota um perfil existente com confirmação.
- firewalld: a transição é explícita — o instalador detecta, mostra o
  estado, exige confirmação, para e mascara o firewalld e guarda um
  snapshot (`nft -j list ruleset`, zonas) para reverter com
  `efwctl firewalld restore`. Verificar presença no Rocky 10 Minimal (aberto
  no checklist).

## Build e distribuição

`make linux` gera binários estáticos (`CGO_ENABLED=0`) para
`linux/amd64` com `GOAMD64=v3` e `linux/arm64`, com hashes em
`dist/SHA256SUMS`; `make repro` prova reprodutibilidade. Etapa 4: RPM
`edge-fwsec` (Requires: nftables, NetworkManager, selinux-policy; unidades
systemd; módulo SELinux), instalador `install.sh` (DNF, idempotente) e ISO
por arquitetura via `mkksiso` sobre a mídia oficial verificada, ambos
convergindo no mesmo RPM e no mesmo `efwctl bootstrap`.
