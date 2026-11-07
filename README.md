# vibeshield-api

Backend do **VibeShield**: um scanner de segurança para código gerado por IA. Recebe a URL de um
repositório público do GitHub, baixa o tarball do `codeload`, varre os arquivos e devolve um
relatório com nota (A–F), score (0–100) e achados com um prompt de correção pronto para colar num
assistente de IA.

O contrato da API está em [`docs/CONTRACT.md`](docs/CONTRACT.md) (fonte única para api e web).
O OpenAPI 3.1 gerado do código fica em `GET /api/v1/openapi.json` e o Swagger UI em `/docs`.

## Como rodar

Requisitos: Rust 1.90+ (CI usa 1.99.0).

```bash
cp .env.example .env        # opcional; todos os valores têm default
cargo run --release
curl -s localhost:8080/api/v1/health
curl -s -X POST localhost:8080/api/v1/scans \
  -H 'content-type: application/json' \
  -d '{"repo_url":"https://github.com/octocat/Hello-World"}'
```

Docker:

```bash
docker build -t vibeshield-api .
docker run --rm -p 8080:8080 -e FRONTEND_URL=http://localhost:5173 vibeshield-api
```

Qualidade (o mesmo que a CI roda):

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test          # não acessa a internet: codeload e registros são servidores falsos locais
```

## Endpoints

| Método | Caminho | O quê |
|---|---|---|
| GET | `/api/v1/health` | `{"status":"ok","version":"0.1.0"}` |
| GET | `/api/v1/openapi.json` | documento OpenAPI |
| GET | `/docs` | Swagger UI |
| POST | `/api/v1/scans` | `{"repo_url": "...", "check_dependencies": true}` → relatório |

Erros sempre no formato `{"error":{"code":"...","message":"..."}}` (códigos no contrato).

## Regras de detecção

| rule_id | categoria | severidade |
|---|---|---|
| `unicode.bidi` | HIDDEN_UNICODE | CRITICAL |
| `unicode.tag` | HIDDEN_UNICODE | CRITICAL |
| `unicode.zero-width` | HIDDEN_UNICODE | HIGH (BOM no início do arquivo não conta) |
| `secret.known-prefix` | SECRET | CRITICAL (AWS, GitHub, Anthropic, OpenAI, Slack, Google, Stripe, chave privada) |
| `secret.high-entropy` | SECRET | HIGH (entropia ≥ 4.5 em atribuição a nome sugestivo, ou ≥ 5.0) |
| `code.cors-wildcard` | INSECURE_CODE | MEDIUM |
| `code.eval` | INSECURE_CODE | MEDIUM (JS/TS e Python) |
| `code.dangerous-html` | INSECURE_CODE | LOW |
| `deps.not-found` | SLOPSQUATTING | HIGH (pacote inexistente no npm/PyPI) |
| `deps.too-new` | SLOPSQUATTING | MEDIUM (pacote criado há < 30 dias) |

Score = `max(0, 100 − Σ pesos)` com CRITICAL 25, HIGH 10, MEDIUM 4, LOW 1. Nota: A ≥ 90, B ≥ 80,
C ≥ 70, D ≥ 50, F < 50. Score e `summary` contam **todos** os achados; a lista `findings` é
ordenada (severidade → arquivo → linha) e cortada em 500 (`truncated: true`).

## Configuração (env)

| Variável | Default | Observação |
|---|---|---|
| `PORT` | `8080` | |
| `FRONTEND_URL` | `http://localhost:5173` | lista separada por vírgula; únicas origens com CORS |
| `MAX_DOWNLOAD_BYTES` | `52428800` | teto do tarball baixado (50 MiB) |
| `MAX_FILE_BYTES` | `1048576` | arquivos maiores são pulados (`files_skipped`) |
| `MAX_FILES` | `20000` | arquivos além disso são pulados |
| `SCAN_TIMEOUT_SECS` | `60` | tempo total por scan → 504 |
| `RATE_LIMIT_PER_MINUTE` | `10` | por IP, só em `POST /api/v1/scans` |
| `GITHUB_CODELOAD_BASE` | `https://codeload.github.com` | |
| `NPM_REGISTRY_BASE` | `https://registry.npmjs.org` | |
| `PYPI_BASE` | `https://pypi.org` | |
| `RUST_LOG` | `info` | |

Valor inválido derruba o boot com mensagem clara (ex.: `PORT=abc`, `FRONTEND_URL=*`).

## Decisões de segurança

- **URL validada pela regex exata do contrato**, mais rejeição de `..`; nada é passado para shell e
  não usamos `git`: só HTTP GET em `{GITHUB_CODELOAD_BASE}/{owner}/{repo}/tar.gz/HEAD`.
- **Download com teto real**: os bytes do stream são contados (o `Content-Length` só serve para
  abortar mais cedo). Passou de `MAX_DOWNLOAD_BYTES` → 413 `REPO_TOO_LARGE`.
- **Extração defensiva**: symlinks, hardlinks, devices e FIFOs nunca são materializados; entradas
  com `..` ou caminho absoluto são rejeitadas; o prefixo `owner-repo-sha/` é removido; arquivos
  acima de `MAX_FILE_BYTES` e além de `MAX_FILES` são pulados; o total descompactado é limitado a
  4× `MAX_DOWNLOAD_BYTES` (gzip bomb → 413).
- **Diretório temporário** (`tempfile::TempDir`) removido ao fim de cada scan; os caminhos expostos
  são sempre relativos à raiz do repo.
- **Segredos sempre mascarados** no snippet (no máximo 4 chars de cada ponta + `…`), inclusive
  quando aparecem na linha de outro achado. Todo corte de string é por fronteira de char (UTF-8
  multibyte não causa panic).
- **Varredura em paralelo** (rayon) dentro de `spawn_blocking`; respeita `.gitignore` do repo mas
  ignora gitignore global/excludes do servidor. Timeout do scan sinaliza cancelamento para a
  extração e a varredura.
- **Dependências**: até 8 consultas simultâneas, 5 s por requisição, no máximo 300 pacotes por
  scan; erro/timeout do registro não gera achado (não acusamos o que não verificamos).
- **HTTP**: corpo limitado a 16 KB; CORS só para `FRONTEND_URL`; rate limit por IP; erros sem
  stacktrace (detalhe só no log); sem `unwrap()` em caminho de requisição.
- **Docker**: build multi-stage, runtime `debian:bookworm-slim` com usuário não-root (uid 10001).

## Limites conhecidos

- Rate limit usa o IP do peer TCP. Atrás de proxy/CDN todos os clientes compartilham o IP do proxy;
  usar `X-Forwarded-For` exige confiar no proxy (não habilitado para não permitir spoofing).
- Rotas inexistentes devolvem o 404/405 padrão do axum (corpo vazio), fora do formato de erro.
- `deps.too-new` depende da data de criação do registro; packuments gigantes (> 8 MiB) são
  tratados como pacotes existentes e antigos.
