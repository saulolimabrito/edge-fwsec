# Modelo de ameaças — Edge FWSec v1

Escopo: appliance single-node exposto a uma WAN hostil, com uma ou mais LANs
e uma rede de gerenciamento. Revisar a cada etapa; cada mitigação tem uma
verificação associada no checklist.

## Ativos

1. Disponibilidade do encaminhamento e do acesso de gerenciamento.
2. Integridade da política ativa e das revisões armazenadas.
3. Credenciais administrativas, chave TLS, chave de sessão, credencial de
   bootstrap.
4. Backups de configuração (contêm a política e, se incluídos, segredos).
5. Integridade dos artefatos distribuídos (RPM, ISO, instalador).

## Fronteiras de confiança

| Fronteira | De → para | Observação |
|---|---|---|
| WAN → appliance | Internet → kernel/nftables | Nenhum serviço de gerenciamento exposto por padrão. |
| Rede de gerenciamento → `efw-web` | admin → HTTPS | Autenticado, CSRF, rate limit. |
| `efw-web` → `efw-agent` | sem privilégio → root | Socket Unix, protocolo tipado, revalidação no agent. |
| Console local → `efwctl` | operador físico → root | Recuperação; confiança por acesso físico/console. |
| Build → appliance | CI/maintainer → RPM/ISO | Assinatura GPG, checksums, SBOM. |

## Ameaças e mitigações

| # | Ameaça | Mitigação | Estado |
|---|---|---|---|
| T1 | Painel acessível pela WAN | Bind só em loopback até a etapa 3 (código). Ruleset: porta do painel aceita só nas interfaces de gerenciamento; validação recusa WAN como gerenciamento; cenário confirma bloqueio a partir de `efw-inet` (v4/v6). Falta: serviço real atrás da regra (etapa 3). | parcial |
| T2 | Comprometimento do `efw-web` vira root | Separação de processos; agent aceita apenas operações tipadas; sem shell; systemd `NoNewPrivileges`, `ProtectSystem=strict`, usuário dedicado; SELinux. | planejado |
| T3 | Injeção de regras nftables | Modelo estruturado → validação → gerador em Go; identificadores e devices restritos a charset sem escape; endereços via `netip`; nunca texto livre da API; `nft` via `exec` com stdin, sem shell. Testes: `internal/policy`, `internal/nft`. | ativo |
| T4 | Mudança tranca o administrador fora | Aplicar com prazo, rollback automático controlado pelo agent, checkpoint NM, validação que avisa sobre corte do caminho atual, recuperação por console. | planejado |
| T5 | Reboot/crash no meio da mudança deixa estado inconsistente | `testing` gravado antes de aplicar; no boot o agent restaura a confirmada antes de `network-online`. | planejado |
| T6 | Força bruta de login | Rate limit por IP e por usuário, atraso exponencial, hash Argon2id, auditoria. | planejado |
| T7 | CSRF / sequestro de sessão | Cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`; token CSRF por sessão em mutações; expiração ociosa e absoluta. | planejado |
| T8 | XSS no console | Svelte escapa por padrão; CSP sem inline (ativa desde a etapa 1); sem `{@html}`. | ativo |
| T9 | Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY` (ativo). | ativo |
| T10 | Credencial de bootstrap reutilizada/vazada | Uso único, expiração, mostrada só no console local, invalidada após o primeiro login. | planejado |
| T11 | Backup expõe segredos | Segredos excluídos por padrão; inclusão opcional cifrada com senha (AES-GCM + KDF); permissões 0600. | planejado |
| T12 | Restauração de backup malicioso/antigo | Validação de esquema, migrações versionadas, passa pelo mesmo fluxo validar/diff/aplicar com prazo. | planejado |
| T13 | Artefato adulterado | RPM e ISO assinados; instalador verifica assinatura antes de instalar; build reproduzível (`make repro`). | parcial (repro ativo) |
| T14 | Interferência em regras de terceiros | Só tabelas próprias, substituição atômica; nunca `flush ruleset`. Teste `TestOnlyOwnedTables` + cenário com tabela alheia. | ativo |
| T15 | Exaustão de recursos no `efw-web` | Timeouts de leitura/escrita/cabeçalho e limite de cabeçalho (ativos); limite de corpo nas mutações. | parcial |
| T16 | IPv6 aberto por omissão | Cadeias inet com política drop para as duas famílias; ICMPv6 essencial restrito (RFC 4890); cenários IPv6 com tráfego real. | ativo |
| T17 | Inundação do journal por log do firewall | Log da política padrão limitado a 10/s (burst 20). | ativo |

## Riscos aceitos na v1

- Sem HA: falha de hardware interrompe o serviço.
- Sem MFA na v1 (avaliar pós-v1).
- Console local com acesso físico é considerado confiável.
