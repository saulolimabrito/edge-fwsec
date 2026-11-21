# AGENTS.md — Edge FWSec

Instruções para quem (pessoa ou agente) continuar este projeto. Leia também
`docs/architecture.md`, `docs/threat-model.md` e `docs/release-checklist.md`;
os quatro arquivos são a referência entre sessões. O próximo passo concreto
está sempre no topo do checklist.

## O que é

Appliance de firewall de borda single-node sobre Rocky Linux 10 (x86_64
x86-64-v3 e aarch64). Backend Go, console Svelte 5 + TypeScript + Vite
embutido no binário via `go:embed`. nftables para filtragem/NAT,
NetworkManager para interfaces/VLANs/rotas.

## Comandos

| Objetivo | Comando |
|---|---|
| Checagem completa (gofmt, vet, testes Go, svelte-check, vitest) | `make check` |
| Build local (UI + binários do host) | `make build` |
| Binários do appliance (linux x86_64 v3 + aarch64) e `dist/SHA256SUMS` | `make linux` |
| Prova de build reproduzível (dois builds, compara hashes) | `make repro` |
| Servidor local em 127.0.0.1:8080 | `make run` |
| UI em modo dev com proxy para :8080 | `cd ui && npm run dev` |
| Topologia de teste (só em VM descartável, como root) | `EFW_TEST_VM=1 tests/topology/netns.sh up\|verify\|down` |
| VM de teste local (macOS, Lima) | `limactl start --name=efw-dev --mount-none template:rocky-10` |

Testes Linux em macOS: compile o binário de teste com
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/<pkg>`, copie
com `limactl copy` e execute na VM `efw-dev`. Nunca rode `netns.sh`, nft ou
nmcli na estação de desenvolvimento.

## Layout

```
cmd/efw-web     servidor web sem privilégios (console + API)
cmd/efwctl      CLI local de diagnóstico e recuperação
cmd/efw-agent   (etapa 3) serviço privilegiado que aplica mudanças
internal/       pacotes Go (sysinfo, web, version; depois policy, nft, nm, store, auth)
ui/             console Svelte; `ui/dist` é gerado e embutido (só `.keep` é versionado)
tests/topology  topologia WAN/LAN/VLAN/MGMT em namespaces
docs/           arquitetura, ameaças, checklist, topologia, matriz de suporte
```

## Convenções

- Go: só biblioteca padrão até haver motivo documentado; `gofmt`; erros com
  contexto; nada de `panic` em caminho de requisição.
- Frontend: Svelte 5 runes, TypeScript estrito, sem CSS/JS inline (a CSP
  bloqueia `style=`/scripts inline), sem fontes ou recursos externos (o
  appliance opera offline). Tokens de cor em `ui/src/app.css`.
- Valores não lidos do kernel são `null` na API e "—" na UI. Nunca exibir
  zero ou métrica inventada.
- Versões de dependências npm fixas (`--save-exact`) e `package-lock.json`
  versionado. TypeScript fixado em 6.x: `svelte-check` 4.7 ainda exige
  configuração dupla para TS 7.
- Commits pequenos, em inglês, imperativos; cada etapa atualiza o checklist
  com o que foi verificado e como.
- Autoria única: `Saulo Brito <100214355+saulolimabrito@users.noreply.github.com>`.
  Commits, merges, PRs e Issues não levam trailers `Co-Authored-By` nem
  rodapés de ferramentas de geração.
- Textos de documentação em português; código, identificadores e mensagens
  da UI em inglês.

## Invariantes de segurança (não quebrar)

1. `efw-web` nunca executa comandos nem altera o sistema. Mudanças passam
   por `efw-agent` via socket Unix (0660, grupo dedicado) com protocolo
   tipado por operação; validação nos dois lados. Sem shell, sem comando
   arbitrário, sem nftables em texto livre vindo da API.
2. Sem TLS + autenticação, o servidor só escuta em loopback
   (`checkLoopback` em `cmd/efw-web`). Não remover essa trava antes da
   etapa 3 estar completa.
3. O projeto só altera as tabelas nftables que possui (`inet efw`, `ip efw_nat`
   — nomes finais em `docs/architecture.md`). Tabelas alheias são preservadas.
4. Toda aplicação de mudança tem prazo controlado pelo serviço; sem
   confirmação, volta para a última revisão confirmada — inclusive após
   reinício do processo ou da máquina.
5. SELinux permanece em enforcing. Nada de `setenforce 0` em scripts,
   testes ou documentação.
6. Testes que alteram rede, firewall, disco ou boot rodam apenas em VM
   descartável ou namespaces próprios (`EFW_TEST_VM=1`). A rede, o firewall e
   as credenciais da estação de desenvolvimento nunca são tocados.
7. Segredos (hash de senha, chave TLS, chave de sessão) nunca entram em logs,
   backups sem cifra ou respostas da API.
8. Builds reproduzíveis: `-trimpath`, `-buildvcs=false`, `-buildid=`,
   `SOURCE_DATE_EPOCH` do último commit, `CGO_ENABLED=0`. `make repro` deve
   passar antes de qualquer release.

## Ambiente verificado

- Desenvolvimento: macOS arm64, Go 1.27.4, Node 26, npm.
- VM de teste: Lima `efw-dev`, Rocky Linux 10.3 aarch64 (imagem GenericCloud,
  não Minimal), kernel 6.12.0-264, NetworkManager 1.58, SELinux enforcing,
  sem nftables e sem firewalld instalados por padrão nessa imagem.
- A VM `rocky10-kea` pertence a outro projeto: não usar nem alterar.
