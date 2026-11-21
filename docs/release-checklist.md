# Release checklist — Edge FWSec v1.0.0

Regra: um item só é marcado com evidência (comando, ambiente, data,
resultado). A tag `v1.0.0` só é criada com todos os critérios de aceite
marcados.

## ▶ Próximo passo concreto

Etapa 3, primeiro incremento: `internal/store` com revisões
`draft/testing/confirmed` em `/var/lib/efw` (escrita atômica: temporário +
`fsync` + `rename` + `fsync` do diretório; `state.json` com
`confirmed`, `testing` e `deadline`; controle otimista por
`base_revision`), testes de unidade incluindo falha no meio da escrita; em
seguida o esqueleto do `cmd/efw-agent` com socket Unix e protocolo tipado
(`Validate`, `Diff`, `Apply{revision, timeout}`, `Confirm`, `Rollback`,
`Status`), aplicando nftables via `nft.Runner` com prazo controlado pelo
agent e teste em namespace de timeout → rollback para a confirmada. Antes:
confirmar na documentação do NetworkManager (D-Bus `CheckpointCreate`,
`rollback_timeout`, flags) o comportamento no NM 1.58 do Rocky 10.

## Pendências externas / bloqueios

| Item | Comando | Resultado | O que falta |
|---|---|---|---|
| Licença ([#5](https://github.com/saulolimabrito/edge-fwsec/issues/5)) | — | não definida; repositório já é público | Decisão do mantenedor (ex.: GPL-3.0, Apache-2.0). |
| Rocky 10 Minimal: firewalld presente por padrão? ([#6](https://github.com/saulolimabrito/edge-fwsec/issues/6)) | — | não verificado (VM atual é GenericCloud, sem firewalld nem nftables) | Instalar a partir da ISO Minimal oficial em VM e registrar `rpm -q firewalld nftables`. |
| VM x86_64 ([#7](https://github.com/saulolimabrito/edge-fwsec/issues/7)) | — | não disponível localmente (host Apple Silicon) | Host ou runner x86_64 com KVM para testes de instalação/ISO e boot UEFI. |

Repositório: https://github.com/saulolimabrito/edge-fwsec (público, criado em
2026-11-21). Acompanhamento por etapa nas Issues #1–#4.

## Etapa 1 — Base executável ✅ (2026-11-21)

- [x] Go + Svelte: `efw-web` serve a UI compilada via `go:embed`; API de
  leitura `/api/v1/{version,system,interfaces}` com dados reais do kernel.
  Evidência: `make check` no macOS → gofmt/vet OK, `go test` 3 pacotes OK,
  `svelte-check` 0 erros/0 avisos, vitest 6/6.
- [x] Testes Linux no Rocky 10.3 aarch64 (VM `efw-dev`): binários de teste
  cruzados `sysinfo`, `web`, `efw-web` → PASS (8 testes em sysinfo,
  incluindo leitura real via rtnetlink).
- [x] VLAN detectada sem privilégios: `efw-web` como uid 501 reporta
  `efwdum0.20 vlan 20 on efwdum0`. Defeito encontrado e corrigido:
  `/proc/net/vlan/*` é `0600 root`; agora usa `RTM_GETLINK`.
- [x] Trava de segurança: `efw-web -listen 0.0.0.0:8080` → recusa, saída 2
  (verificado na VM).
- [x] Build reproduzível: `make repro` → dois builds com UI recompilada,
  `SHA256SUMS` idênticos para `linux-x86_64` (GOAMD64=v3) e `linux-aarch64`;
  binários estáticos ELF conferidos com `file`.
- [x] Console revisado em navegador contra a VM: visão geral, interfaces,
  taxa derivada de duas amostras, estado "API inacessível" com dados
  antigos mantidos e aviso, atalhos `1`/`2`/`r`, foco visível, layout em
  375 px. Defeitos corrigidos: espaços colapsados em "vid"/"link"; grade
  mobile dividindo altura.
- [x] CLI `efwctl version|system|interfaces [--json]` verificada na VM.
- [x] Topologia WAN/LAN/VLAN/MGMT definida e verificada
  (`docs/test-topology.md`): 3×10/10 PASS na VM.
- [x] CI no GitHub verde (run 44934235705): `check` (make check + make repro +
  topologia netns 10/10) em ubuntu-24.04 x86_64 e ubuntu-24.04-arm; testes Go
  em container Rocky Linux 10.3 nas duas arquiteturas. Primeiro run falhou
  porque o container `rockylinux:10` não declara PATH e o `setup-go` o
  substituía; corrigido fixando PATH no container.

Em aberto da etapa 1: tema claro não revisado visualmente (somente escuro).

## Etapa 2 — Motor de políticas ✅ (2026-11-21)

Ambiente: VM `efw-dev` (Rocky 10.3 aarch64, kernel 6.12.0-264, nftables
1.1.5). Comando: `EFW_TEST_VM=1 tests/policy/scenarios.sh` → 36/36 PASS em
3 execuções seguidas; sem namespaces nem tabelas residuais.

- [x] Modelo versionado (`schema_version: 1`) + validação:
  `go test ./internal/policy` (fixture válida, decodificação estrita,
  round-trip canônico, 32 casos de erro com caminho, famílias de regra).
- [x] Gerador com teste de ouro (`internal/nft/testdata/edge.nft`),
  determinismo, recusa de config inválida, só tabelas próprias,
  normalização de conjuntos.
- [x] Semântica do nftables 1.1.5 verificada na VM: idioma
  declarar/`delete table`/redefinir funciona com tabela ausente ou
  presente e troca a policy da cadeia; lote com erro deixa a tabela
  anterior intacta; `nft -c` detecta erro semântico; `iif` exige device
  existente (por isso `iifname`). Documentação oficial: `nft -f` aplica em
  uma operação atômica (wiki nftables, "Atomic rule replacement").
- [x] `efwctl policy validate|render|check`.
- [x] Allow/deny stateful IPv4 e IPv6 com tráfego real.
- [x] Masquerade (origem 203.0.113.2 vista pelo destino) e port forward
  IPv4 com origem preservada e regra de forward associada; IPv6 roteado sem
  NAT.
- [x] ICMPv6 essencial sob política drop: ND após flush de vizinhos e
  Packet Too Big encaminhado (PMTU 1280 aprendido pelo cliente).
- [x] Painel: 443 aceito só pela rede de gerenciamento (v4/v6), bloqueado
  pelo WAN e pela LAN.
- [x] VLAN 30 (convidados) com reject distinguido de drop e log no kernel.
- [x] Tabela de terceiros preservada; reaplicação idempotente; lote quebrado
  recusado sem alterar o ruleset.
- [x] Cenários no CI: run 44935781368, `scenarios.sh` 36/36 em ubuntu-24.04
  (x86_64) e ubuntu-24.04-arm (kernel e nftables do Ubuntu; o Rocky 10 é
  coberto pela VM).

Defeitos encontrados e corrigidos: objeto misto IPv4/IPv6 recusado em
regra de uma família (agora filtra); log padrão sem limite (agora 10/s);
cliente VLAN sem namespace próprio na topologia; servidor de teste travando
em `getfqdn()`.

Em aberto (não bloqueiam a etapa 3): SNAT para endereço fixo e regras de
DHCP/DHCPv6 cliente só verificados por renderização e `nft --check`, sem
tráfego; hairpin NAT fora da v1 (matriz de suporte).

## Etapa 3 — Operação completa

- [ ] `efw-agent` + protocolo tipado no socket Unix, validação nos dois lados
- [ ] Store de revisões (draft/testing/confirmed), escrita atômica, controle otimista
- [ ] Aplicar com prazo, confirmar, reverter; checkpoint NetworkManager
- [ ] Recuperação após reinício do serviço e reboot com mudança pendente
- [ ] HTTPS, bootstrap de uso único, login, sessões, CSRF, rate limit, certificado próprio
- [ ] Painel restrito à rede de gerenciamento por padrão
- [ ] Primeiro acesso: WAN, LAN, gerenciamento
- [ ] Regras/objetos/NAT/rotas/VLANs na UI com diff e contagem regressiva
- [ ] Auditoria (autor, horário, resultado); backup/validação/restauração
- [ ] `efwctl` de recuperação: revisões, rollback para a confirmada

## Etapa 4 — Distribuição

- [ ] RPM x86_64 e aarch64 assinados, dependências declaradas
- [ ] Módulo SELinux e unidades systemd endurecidas, validados em enforcing
- [ ] Instalador idempotente (verifica Rocky 10, arquitetura, assinatura, conflitos)
- [ ] Transição explícita e reversível do firewalld
- [ ] ISO por arquitetura (mkksiso sobre mídia oficial verificada), instalação offline
- [ ] Comparação ISO × instalador (serviços, permissões, SELinux, versões)
- [ ] Pré-release: instalação limpa e upgrade

## Critérios de aceite da v1.0.0

- [ ] Quatro instalações completas em VM: instalador e ISO em x86_64 e aarch64.
- [ ] ISO instala sem rede, inicializa o appliance e chega ao primeiro acesso.
- [ ] Mesma versão e mesmo perfil de hardening pelas duas formas, por arquitetura.
- [ ] Painel opera pelas redes autorizadas e é inacessível pela WAN no perfil padrão.
- [ ] IPv4, IPv6, VLANs, rotas, firewall stateful e NAT com tráfego real, conforme a matriz.
- [ ] Mudança inválida, perda de conectividade, timeout, reinício do serviço e reboot durante mudança pendente testados, com recuperação registrada.
- [ ] Configuração confirmada persiste após reboot; reinstalação, atualização e restauração preservam a configuração.
- [ ] SELinux enforcing com serviços nas permissões previstas.
- [ ] Release com instalador, RPMs, ISOs, checksums, assinaturas, SBOM, guias e matriz; testes em ARM virtual e hardware físico identificados.
