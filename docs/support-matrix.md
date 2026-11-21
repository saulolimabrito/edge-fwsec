# Matriz de suporte (rascunho)

Só entra como "suportado" o que tiver evidência registrada em
`docs/release-checklist.md`. Até a v1.0.0 esta matriz descreve o escopo
pretendido.

## Plataformas

| Plataforma | Instalador | ISO | Boot testado | Evidência |
|---|---|---|---|---|
| Rocky Linux 10, x86_64 (x86-64-v3), VM | pretendido | pretendido | UEFI (a testar) | — |
| Rocky Linux 10, aarch64, VM | pretendido | pretendido | UEFI (a testar) | — |
| Hardware físico | por modelo, somente com evidência do modelo | | | — |

BIOS legado só será anunciado se testado. CPUs x86_64 sem x86-64-v3 não são
suportadas (requisito do Rocky/RHEL 10).

## Funcionalidades de rede

| Recurso | IPv4 | IPv6 | Observação |
|---|---|---|---|
| Endereço estático | sim | sim | |
| DHCP cliente / SLAAC | DHCP | SLAAC + DHCPv6 cliente (a confirmar) | WAN |
| VLAN 802.1Q | sim | sim | VID 1–4094 |
| Rotas estáticas | sim | sim | |
| Firewall stateful, regras ordenadas | sim | sim | política padrão por família |
| ICMPv6 essencial (ND, RA, PMTU/Packet Too Big, erros) | — | sim | sempre permitido de forma restrita |
| Masquerade / SNAT | sim | **não** | NAT66/NPTv6 fora da v1 |
| DNAT / port forward | sim | **não** | IPv6: liberar por regra de forward; faixa de portas é encaminhada sem remapear |
| Hairpin NAT (LAN → IP público do WAN) | **não** | — | fora da v1 |
| Filtragem de saída do próprio appliance | **não** | **não** | cadeia `output` aberta na v1 |
| Multi-WAN, VPN, IDS/IPS, HA, BGP | não | não | roadmap pós-v1 |
