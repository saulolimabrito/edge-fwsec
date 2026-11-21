# Topologia de testes

Implementação: `tests/topology/netns.sh`. Roda somente em VM descartável ou
runner de CI, com `EFW_TEST_VM=1` e root. Todos os objetos usam o prefixo
`efw-` e ficam em namespaces próprios.

```
 efw-inet ── efw-wanr ══ wan0 ── efw-fw ── lan0 (trunk) ══ efw-lan (untagged)
 (host "internet")  (roteador ISP)   │ (DUT)                  └─ eth0.30 ── efw-guest (VLAN 30)
                                   mgmt0
                                     ║
                                  efw-mgmt (estação do administrador)
```

| Segmento | IPv4 | IPv6 | DUT | Par |
|---|---|---|---|---|
| WAN | 203.0.113.0/24 | 2001:db8:ffff::/64 | .2 / ::2 | `efw-wanr` .1 / ::1 |
| "Internet" | 198.51.100.0/24 | 2001:db8:100::/64 | — | `efw-inet` .10 / ::10 |
| LAN | 192.168.10.0/24 | 2001:db8:10::/64 | .1 / ::1 | `efw-lan` .10 / ::10 |
| VLAN 30 (em lan0) | 192.168.30.0/24 | 2001:db8:30::/64 | .1 / ::1 | `efw-guest` eth0.30 .10 / ::10 |
| Gerenciamento | 10.99.0.0/24 | fd00:99::/64 | .1 / ::1 | `efw-mgmt` .10 / ::10 |

Na topologia base o roteador ISP tem rotas de volta para LAN/VLAN, permitindo
testar tanto roteamento puro quanto NAT (quando a política aplica
masquerade, o retorno passa a usar 203.0.113.2). IPv6 é roteado sem NAT,
conforme o escopo da v1.

O device VLAN do cliente é movido para o namespace `efw-guest` (o pai
continua em `efw-lan`), então o tráfego do convidado sai realmente marcado
na VLAN 30.

## Verificações atuais (`verify`)

Alcance v4/v6 de LAN, VLAN 30 e gerenciamento ao DUT; LAN → internet v4/v6
roteado; internet → LAN v4 (sem política ainda: esperado PASS); vizinho NDP
no DUT.

## Cenários de política (`tests/policy/scenarios.sh`)

Aplica o ruleset gerado de `internal/policy/testdata/edge.json` no
`efw-fw` e testa com tráfego real (servidor `tests/policy/httpd.py`,
cliente `curl`, `ping`): saída da LAN v4 com masquerade e v6 roteado sem
NAT; retorno stateful; novas conexões do WAN bloqueadas; publicação IPv6
por regra; port forward com origem preservada; painel só pela rede de
gerenciamento (v4/v6) e inacessível pelo WAN; VLAN convidada com
reject vs drop distinguidos; log do kernel; ICMP; ND sob política drop;
Packet Too Big encaminhado (PMTU 1280 aprendido); tabela de terceiros
preservada; reaplicação idempotente; lote quebrado recusado sem alterar o
ruleset.

Notas do ambiente: `python3 -m http.server` chama `getfqdn()` e trava em
namespaces sem DNS, por isso o servidor próprio; logs do netfilter em
namespaces exigem `net.netfilter.nf_log_all_netns=1` (só no teste; o
appliance roda no namespace inicial).

## Resultado registrado

2026-11-21, VM Lima `efw-dev`, Rocky Linux 10.3 aarch64, kernel
6.12.0-264.16.1.el10_3: 3 execuções seguidas de `up` + `verify`, 10/10 PASS
em cada; `down` remove todos os namespaces; interfaces do host inalteradas.
Primeira tentativa com `ping -c1 -W1` falhou em LAN→internet IPv6 por
resolução ND em dois saltos; os checks agora usam 3 pacotes e 2 s.

2026-11-21, mesma VM, nftables 1.1.5: `scenarios.sh` 36/36 PASS em 3
execuções seguidas; após cada execução não restam namespaces nem tabelas.
