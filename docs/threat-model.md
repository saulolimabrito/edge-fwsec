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
| T1 | Painel acessível pela WAN | Etapa 1: bind só em loopback (código). Etapa 3: regra padrão aceita 443 apenas nas redes de gerenciamento; teste a partir do namespace `efw-inet`. | parcial |
| T2 | Comprometimento do `efw-web` vira root | Separação de processos; agent aceita apenas operações tipadas; sem shell; systemd `NoNewPrivileges`, `ProtectSystem=strict`, usuário dedicado; SELinux. | planejado |
| T3 | Injeção de regras nftables | Modelo estruturado → gerador em Go → `nft -j` (JSON); nomes/identificadores validados por regex estrita; nunca texto livre da API. | planejado |
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
| T14 | Interferência em regras de terceiros | Agent só altera tabelas próprias; nunca `flush ruleset`. | planejado |
| T15 | Exaustão de recursos no `efw-web` | Timeouts de leitura/escrita/cabeçalho e limite de cabeçalho (ativos); limite de corpo nas mutações. | parcial |
| T16 | IPv6 aberto por omissão | Política padrão explícita por família; ICMPv6 essencial (ND, PMTU) permitido de forma restrita; testes IPv6 dedicados. | planejado |

## Riscos aceitos na v1

- Sem HA: falha de hardware interrompe o serviço.
- Sem MFA na v1 (avaliar pós-v1).
- Console local com acesso físico é considerado confiável.
