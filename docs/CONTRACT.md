# Contrato da API VibeShield — v1 (fonte única para api e web)

Base: `/api/v1`. Todo corpo é JSON UTF-8. Campos em snake_case.

## GET /api/v1/health
200 `{ "status": "ok", "version": "0.1.0" }`

## GET /api/v1/openapi.json
200 documento OpenAPI 3.1 gerado do código (utoipa). Swagger UI em `/docs`.

## POST /api/v1/scans
Requisição:
```json
{ "repo_url": "https://github.com/owner/repo", "check_dependencies": true }
```
- `repo_url` (obrigatório): deve casar EXATAMENTE `^https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}?(?:\.git)?/?$`.
  Rejeitar: outros hosts, http, credenciais na URL, query/fragment, `..`, porta, caminhos extras (`/tree/...`).
  Repo name `.` ou `..` é inválido.
- `check_dependencies` (opcional, default `true`): consulta registros públicos (npm, PyPI).

Resposta 200:
```json
{
  "scan_id": "uuid-v4",
  "repo": { "owner": "owner", "name": "repo", "url": "https://github.com/owner/repo" },
  "score": 72,
  "grade": "C",
  "files_scanned": 143,
  "files_skipped": 4,
  "bytes_downloaded": 812345,
  "duration_ms": 1830,
  "truncated": false,
  "summary": {
    "by_severity": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 3, "LOW": 1 },
    "by_category": { "SECRET": 2, "HIDDEN_UNICODE": 0, "SLOPSQUATTING": 1, "INSECURE_CODE": 3 }
  },
  "findings": [
    {
      "id": "uuid-v4",
      "rule_id": "secret.high-entropy",
      "category": "SECRET",
      "severity": "HIGH",
      "file": "src/config.ts",
      "line": 12,
      "snippet": "sk_liv…9f2a",
      "description": "texto pt-BR",
      "fix_prompt": "texto pt-BR pronto para colar num assistente de IA"
    }
  ]
}
```
Regras de campos:
- `file`: caminho RELATIVO à raiz do repo, com `/`. Nunca expor o diretório temporário do servidor.
- `line`: 1-based. Achados de dependência apontam para a linha do pacote no manifesto.
- `snippet`: no máximo 120 caracteres; segredos SEMPRE mascarados (no máx. 4 chars de cada ponta + `…`); Unicode invisível renderizado como `<U+200B>`.
- `category` ∈ `SECRET | HIDDEN_UNICODE | SLOPSQUATTING | INSECURE_CODE`.
- `severity` ∈ `CRITICAL | HIGH | MEDIUM | LOW`.
- `findings` ordenados por severidade (CRITICAL→LOW), depois `file`, depois `line`. No máximo 500 (então `truncated: true`).
- `score` = `max(0, 100 - Σ peso)`, pesos CRITICAL 25, HIGH 10, MEDIUM 4, LOW 1.
- `grade`: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 50, F < 50.

## Erros (todos os status ≠ 2xx)
```json
{ "error": { "code": "INVALID_REPO_URL", "message": "texto pt-BR" } }
```
| status | code | quando |
|---|---|---|
| 400 | INVALID_REPO_URL | URL fora do padrão |
| 400 | INVALID_BODY | JSON malformado / campo ausente / tipo errado |
| 404 | REPO_NOT_FOUND | repo inexistente ou privado |
| 413 | REPO_TOO_LARGE | download passou de MAX_DOWNLOAD_BYTES |
| 429 | RATE_LIMITED | limite por IP estourado |
| 502 | UPSTREAM_ERROR | GitHub indisponível / resposta inesperada |
| 504 | SCAN_TIMEOUT | passou de SCAN_TIMEOUT_SECS |
| 500 | INTERNAL | qualquer outro (sem stacktrace no corpo) |

## Regras de detecção (rule_id → categoria, severidade)
- `unicode.bidi` → HIDDEN_UNICODE, CRITICAL: U+202A–202E, U+2066–2069.
- `unicode.tag` → HIDDEN_UNICODE, CRITICAL: U+E0000–E007F (ASCII smuggling contra LLMs).
- `unicode.zero-width` → HIDDEN_UNICODE, HIGH: U+200B, 200C, 200D, 2060, FEFF (exceto BOM no início do arquivo).
- `secret.known-prefix` → SECRET, CRITICAL: AKIA[0-9A-Z]{16}, ghp_/gho_/ghs_/github_pat_, sk-ant-, sk-proj-/sk-, xox[baprs]-, AIza[0-9A-Za-z_-]{35}, sk_live_, -----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----.
- `secret.high-entropy` → SECRET, HIGH: token 20–200 chars, entropia Shannon ≥ 4.5 E em contexto de atribuição a nome sugestivo (key, secret, token, password, passwd, api, auth, credential) OU entropia ≥ 5.0 sozinho. Ignorar: lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, poetry.lock, go.sum), `integrity`/`sha512-`/`sha256-`, hashes hex puros de 32/40/64 chars, UUIDs, URLs, arquivos `.min.js`/`.map`, `.svg`.
- `code.cors-wildcard` → INSECURE_CODE, MEDIUM: `Access-Control-Allow-Origin: *`, `origin: '*'`/`"*"`, `allow_origin(Any)`, `CORS_ALLOW_ALL_ORIGINS = True`.
- `code.eval` → INSECURE_CODE, MEDIUM: `eval(` / `new Function(` em .js/.ts/.jsx/.tsx/.mjs/.cjs; `eval(`/`exec(` em .py.
- `code.dangerous-html` → INSECURE_CODE, LOW: `dangerouslySetInnerHTML`, `v-html`, `.innerHTML =`.
- `deps.not-found` → SLOPSQUATTING, HIGH: pacote de package.json (dependencies, devDependencies, optionalDependencies, peerDependencies) ou requirements.txt que retorna 404 no registro público. Ignorar especificadores `file:`, `link:`, `workspace:`, `git+`, `github:`, `http(s):`, `npm:` (alias). Escopo `@a/b` → URL `@a%2Fb`.
- `deps.too-new` → SLOPSQUATTING, MEDIUM: pacote existe mas foi criado há < 30 dias.

Arquivos: respeitar .gitignore; pular `.git`, `node_modules`, `target`, `dist`, `build`, `vendor`, binários (NUL nos primeiros 8 KB) e arquivos > MAX_FILE_BYTES (contam em `files_skipped`).

## Configuração (env, todas com default)
`PORT=8080`, `FRONTEND_URL=http://localhost:5173` (lista separada por vírgula), `MAX_DOWNLOAD_BYTES=52428800`, `MAX_FILE_BYTES=1048576`, `MAX_FILES=20000`, `SCAN_TIMEOUT_SECS=60`, `RATE_LIMIT_PER_MINUTE=10`, `GITHUB_CODELOAD_BASE=https://codeload.github.com`, `NPM_REGISTRY_BASE=https://registry.npmjs.org`, `PYPI_BASE=https://pypi.org`, `RUST_LOG=info`.
