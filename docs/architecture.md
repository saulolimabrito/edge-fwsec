# Arquitetura — Edge FWSec v1

Status: etapas 1 (leitura) e 2 (motor de políticas) implementadas. Seções marcadas **[planejado]** são o
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
                         ├─ nftables (script gerado → `nft --check -f -` → `nft -f -`, stdin, sem shell)
                         └─ NetworkManager (D-Bus: Settings, Checkpoint*)
 console local ──▶ efwctl (lê o store diretamente; root)
```

| Componente | Estado | Privilégio | Responsabilidade |
|---|---|---|---|
| `efw-web` | etapa 1: leitura | nenhum | API, sessões, CSRF, UI embutida. Nunca altera o sistema. |
| `efwctl` | etapa 1: leitura | root p/ recuperação | Diagnóstico; na etapa 3: listar revisões, reverter para a última confirmada, reemitir credencial de bootstrap. |
| `efw-agent` | etapa 3: nftables, store, prazo e recuperação | root, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW` + D-Bus | Valida, aplica, temporiza e reverte mudanças. Dono do prazo de confirmação. |

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

## Modelo de configuração (implementado: `internal/policy`)

Documento único com `schema_version: 1`, lido com `Decode` estrito (campo
desconhecido ou dado extra = erro) e gravado com `Canonical` (JSON
determinístico). Exemplo completo: `internal/policy/testdata/edge.json`.

| Seção | Conteúdo |
|---|---|
| `interfaces[]` | nome lógico, papel `wan/lan/mgmt/opt`, device do kernel, `vlan {parent,id}`, `ipv4 {mode: none/static/dhcp}`, `ipv6 {mode: none/static/slaac/dhcp6}` |
| `routes[]` | destino, gateway (mesma família), interface lógica, métrica |
| `networks[]` | objeto de rede com prefixos IPv4 e/ou IPv6 |
| `services[]` | objeto de serviço: entradas `tcp/udp` (faixas de portas) ou `icmp/icmpv6` |
| `admin` | porta HTTPS, interfaces lógicas autorizadas (nunca WAN), origens opcionais |
| `firewall` | `default_input` (drop/reject), `default_forward` (drop/reject/accept), `log_default`, `rules[]` ordenadas |
| `nat` | `source[]` (masquerade/snat, só IPv4), `port_forwards[]` (DNAT IPv4) |

Regras: `id`, `direction` (input/forward), `in`, `out`, `family`
(any/ipv4/ipv6), `source`/`destination` (nomes de objeto ou literais),
`service`, `action` (accept/drop/reject), `log`, `disabled`. A posição na
lista é a ordem de avaliação dentro da direção.

Validação (`Validate`) devolve todos os problemas com caminho
(`firewall.rules[2].source[0]`). Principais checagens: identificadores
`^[a-z][a-z0-9_-]{0,31}$` e devices compatíveis com IFNAMSIZ (nada que
precise de escape no nftables); VID 1–4094; família de endereços;
sobreposição de prefixos entre interfaces; um único WAN; gateway na mesma
família; objetos sem bits de host; faixas de porta; referências existentes;
regra cuja combinação de origem/destino/serviço/família nunca casa;
`default_input: accept` recusado; gerenciamento sem interface ou no WAN
recusado; NAT só IPv4; conflitos de port forward (mesma interface,
protocolo, endereço e portas sobrepostas); port forward que sombreia a
porta do painel; remapeamento de faixa para porta única recusado.

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

## Geração nftables (implementado: `internal/nft`)

`Render` revalida e gera um script com o idioma de substituição atômica,
verificado no nftables 1.1.5 do Rocky 10.3:

```
table inet efw_filter
delete table inet efw_filter
table ip efw_nat
delete table ip efw_nat
table inet efw_filter { ... }
table ip efw_nat { ... }
```

Ordem das cadeias:

- `input` (policy drop): `ct state` vmap → `lo` → ICMPv6 essencial → DHCP/DHCPv6 cliente nas
  interfaces que usam → acesso ao painel nas interfaces de gerenciamento → regras do usuário →
  log padrão (limitado a 10/s) → `reject` se a política for reject.
- `forward` (policy drop ou accept): `ct state` → erros ICMPv6 → aceites implícitos dos port
  forwards (`ct status dnat`, avaliados antes das regras do usuário) → regras do usuário → log
  padrão → reject.
- `ip efw_nat`: `prerouting` com DNAT e `postrouting` com masquerade/SNAT.

ICMPv6 segue a RFC 4890: erros (incluindo Packet Too Big) sempre; ND só com
hop limit 255; MLD só de link-local; redirect não é aceito. Regras usam
`iifname`/`oifname` (o `iif` exige a interface existente no carregamento).
Conjuntos de prefixos e portas são normalizados (o nftables recusa
intervalos sobrepostos). `Runner.Apply` executa `nft --check -f -` e depois
`nft -f -` via `exec`, sem shell. Saída de referência:
`internal/nft/testdata/edge.nft` (teste de ouro).

Limites da v1: sem NAT66/NPTv6, sem hairpin NAT (cliente da LAN acessando o
IP do WAN), sem regras de saída (`output` fica aberto).

## Store e agent (implementado: `internal/store`, `internal/agent`, `cmd/efw-agent`)

Store em `/var/lib/efw` (0700): `lock` (flock exclusivo: um único
escritor), `state.json` (`confirmed`, `testing{revision, deadline,
author}`, `last_revision`), `revisions/<n>.json` (imutáveis, 0600),
`history.jsonl` (auditoria, linha rasgada ignorada). Escrita atômica:
temporário + `fsync` + `rename` + `fsync` do diretório. `state.json`
corrompido é erro, nunca reset silencioso.

Protocolo no socket (`/run/efw/agent.sock`, 0660 root:efw): um objeto JSON
por conexão em cada sentido, máx. 1 MiB, decodificação estrita, cada
operação aceita apenas os próprios campos.

| op | campos | efeito |
|---|---|---|
| `status` | — | confirmada, em teste, segundos restantes |
| `validate` | `config` | problemas com caminho |
| `diff` | `config` | diff do ruleset contra a confirmada + ruleset novo |
| `apply` | `config`, `base_revision`, `timeout_seconds`, `author`, `message` | grava revisão, marca teste, aplica, arma o prazo |
| `confirm` | `revision`, `author` | torna confirmada; desarma o prazo |
| `rollback` | `author` | abandona o teste e reaplica a confirmada |
| `history` | `limit` | auditoria |
| `get` | `revision` | configuração armazenada |

O autor gravado é `<author> via uid=<uid>,pid=<pid>` (SO_PEERCRED). Prazo:
30 s a 10 min (padrão 2 min). Sem revisão confirmada, "confirmada" significa
remover as tabelas do projeto.

Recuperação: na inicialização (antes de abrir o socket) qualquer teste
pendente é abandonado e a confirmada é reaplicada — cobre crash, `kill -9`,
reinício do serviço e reboot. `SIGTERM` durante teste reverte antes de
sair. `efwctl recover` usa o agent se ele responder; com o agent parado,
abre o store e reaplica a confirmada direto.

## Fluxo de mudança [rede: planejado, etapa 3]

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
