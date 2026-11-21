# Topologia de testes

Implementação: `tests/topology/netns.sh`. Roda somente em VM descartável ou
runner de CI, com `EFW_TEST_VM=1` e root. Todos os objetos usam o prefixo
`efw-` e ficam em namespaces próprios.

```
 efw-inet ── efw-wanr ══ wan0 ── efw-fw ── lan0 (untagged + VLAN 30) ══ efw-lan
 (host "internet")  (roteador ISP)   │ (DUT)
                                   mgmt0
                                     ║
                                  efw-mgmt (estação do administrador)
```

| Segmento | IPv4 | IPv6 | DUT | Par |
|---|---|---|---|---|
| WAN | 203.0.113.0/24 | 2001:db8:ffff::/64 | .2 / ::2 | `efw-wanr` .1 / ::1 |
| "Internet" | 198.51.100.0/24 | 2001:db8:100::/64 | — | `efw-inet` .10 / ::10 |
| LAN | 192.168.10.0/24 | 2001:db8:10::/64 | .1 / ::1 | `efw-lan` .10 / ::10 |
| VLAN 30 (em lan0) | 192.168.30.0/24 | 2001:db8:30::/64 | .1 / ::1 | `efw-lan` eth0.30 .10 / ::10 |
| Gerenciamento | 10.99.0.0/24 | fd00:99::/64 | .1 / ::1 | `efw-mgmt` .10 / ::10 |

Na topologia base o roteador ISP tem rotas de volta para LAN/VLAN, permitindo
testar tanto roteamento puro quanto NAT (quando a política aplica
masquerade, o retorno passa a usar 203.0.113.2). IPv6 é roteado sem NAT,
conforme o escopo da v1.

## Verificações atuais (`verify`)

Alcance v4/v6 de LAN, VLAN 30 e gerenciamento ao DUT; LAN → internet v4/v6
roteado; internet → LAN v4 (sem política ainda: esperado PASS); vizinho NDP
no DUT. Na etapa 2 entram os casos de política (allow/deny stateful, NAT,
port forwarding, ICMPv6 essencial, painel inacessível pela WAN).

## Resultado registrado

2026-11-21, VM Lima `efw-dev`, Rocky Linux 10.3 aarch64, kernel
6.12.0-264.16.1.el10_3: 3 execuções seguidas de `up` + `verify`, 10/10 PASS
em cada; `down` remove todos os namespaces; interfaces do host inalteradas.
Primeira tentativa com `ping -c1 -W1` falhou em LAN→internet IPv6 por
resolução ND em dois saltos; os checks agora usam 3 pacotes e 2 s.
