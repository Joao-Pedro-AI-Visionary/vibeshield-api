//! Segredos: prefixos conhecidos e tokens de alta entropia. Snippet SEMPRE mascarado.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use super::{Category, RawFinding, Severity};
use crate::text::{mask_secret, shannon_entropy};

static KNOWN_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA) )?PRIVATE KEY-----",
        r"|\bAKIA[0-9A-Z]{16}\b",
        r"|\bgithub_pat_[A-Za-z0-9_]{22,255}",
        r"|\bgh[pos]_[A-Za-z0-9]{36,255}\b",
        r"|\bsk-ant-[A-Za-z0-9_\-]{20,}",
        r"|\bsk-proj-[A-Za-z0-9_\-]{20,}",
        r"|\bsk-[A-Za-z0-9]{20,}",
        r"|\bxox[baprs]-[A-Za-z0-9\-]{10,}",
        r"|\bAIza[0-9A-Za-z_\-]{35}",
        r"|\bsk_live_[0-9A-Za-z]{16,}",
    ))
    .expect("regex estática válida")
});

static PEM_BEGIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN [A-Z0-9 ]+-----").expect("regex estática válida"));

static PEM_END_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----END [A-Z0-9 ]+-----").expect("regex estática válida"));

static TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_\-]{20,}").expect("regex estática válida"));

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s'`]+").expect("regex estática válida")
});

static HEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]+$").expect("regex estática válida"));

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .expect("regex estática válida")
});

/// Atribuição a nome sugestivo imediatamente antes do token (`api_key = "`, `token: '`...).
static ASSIGN_CTX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:key|secret|token|passwd|password|api|auth|credential)[\w.\-]*["'\]]*\s*(?::=|=>|=|:)\s*["'`]?$"#)
        .expect("regex estática válida")
});

const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "go.sum",
];

fn skip_entropy_for_file(file: &str) -> bool {
    let name = file.rsplit('/').next().unwrap_or(file);
    LOCKFILES.contains(&name)
        || name.ends_with(".min.js")
        || name.ends_with(".map")
        || name.ends_with(".svg")
}

/// Substitui segredos de prefixo conhecido na linha pela versão mascarada.
/// Usado por outras regras antes de expor uma linha como snippet.
pub fn redact_line(line: &str) -> String {
    KNOWN_PREFIX_RE
        .replace_all(line, |c: &regex::Captures<'_>| mask_secret(&c[0]))
        .into_owned()
}

fn overlaps(r: &Range<usize>, others: &[Range<usize>]) -> bool {
    others.iter().any(|o| r.start < o.end && o.start < r.end)
}

fn looks_ignorable(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if lower.starts_with("sha512-")
        || lower.starts_with("sha384-")
        || lower.starts_with("sha256-")
        || lower.starts_with("sha1-")
    {
        return true;
    }
    if HEX_RE.is_match(token) && matches!(token.len(), 32 | 40 | 64) {
        return true;
    }
    UUID_RE.is_match(token)
}

pub fn scan(file: &str, content: &str) -> Vec<RawFinding> {
    let check_entropy = !skip_entropy_for_file(file);
    let mut out = Vec::new();
    let mut in_pem = false;
    for (idx, line) in content.lines().enumerate() {
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        // Bloco PEM: o corpo base64 nunca gera achado; chave privada gera um só
        // `secret.known-prefix` na linha do BEGIN; certificado/chave pública, nada.
        if in_pem {
            if PEM_END_RE.is_match(line) {
                in_pem = false;
            }
            continue;
        }
        let pem_begin = PEM_BEGIN_RE.find(line);
        if let Some(b) = pem_begin {
            in_pem = !PEM_END_RE.is_match(&line[b.end()..]);
        }
        let mut known: Vec<Range<usize>> = Vec::new();
        for m in KNOWN_PREFIX_RE.find_iter(line) {
            known.push(m.range());
            out.push(RawFinding {
                rule_id: "secret.known-prefix",
                category: Category::Secret,
                severity: Severity::Critical,
                file: file.to_string(),
                line: line_no,
                snippet: mask_secret(m.as_str()),
                description: "Credencial com formato conhecido (AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe ou chave privada) exposta no código.".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, há uma credencial real escrita no código. Remova o valor do código, leia-o de uma variável de ambiente (com um .env fora do git e um .env.example sem valores), e me lembre de revogar e gerar uma nova credencial no provedor, pois ela já vazou no histórico do git."),
            });
        }
        if pem_begin.is_some() || !check_entropy || line.to_ascii_lowercase().contains("integrity")
        {
            continue;
        }
        let without_urls =
            URL_RE.replace_all(line, |c: &regex::Captures<'_>| " ".repeat(c[0].len()));
        for m in TOKEN_RE.find_iter(&without_urls) {
            let token = m.as_str();
            let len = token.chars().count();
            if !(20..=200).contains(&len) || overlaps(&m.range(), &known) || looks_ignorable(token)
            {
                continue;
            }
            let entropy = shannon_entropy(token);
            let prefix = &without_urls[..m.start()];
            let assigned = ASSIGN_CTX_RE.is_match(prefix);
            if !((assigned && entropy >= 4.5) || entropy >= 5.0) {
                continue;
            }
            out.push(RawFinding {
                rule_id: "secret.high-entropy",
                category: Category::Secret,
                severity: Severity::High,
                file: file.to_string(),
                line: line_no,
                snippet: mask_secret(token),
                description: "Valor de alta entropia com cara de segredo (token, senha ou chave) escrito diretamente no código.".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, parece haver um segredo (token, senha ou chave) escrito direto no código. Se for um segredo, mova-o para uma variável de ambiente, adicione o nome ao .env.example sem o valor e garanta que o .env está no .gitignore; se não for segredo, explique o que é esse valor."),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(f: &[RawFinding]) -> Vec<&str> {
        f.iter().map(|x| x.rule_id).collect()
    }

    #[test]
    fn detecta_prefixos_conhecidos_e_mascara() {
        let aws = "AKIAIOSFODNN7EXAMPLE";
        let gh = format!("ghp_{}", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A");
        let ant = "sk\x2dant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        let content = format!("aws = \"{aws}\"\ntoken: {gh}\nANTHROPIC={ant}\n");
        let f = scan("src/config.ts", &content);
        let known: Vec<&RawFinding> = f
            .iter()
            .filter(|x| x.rule_id == "secret.known-prefix")
            .collect();
        assert_eq!(known.len(), 3, "{f:?}");
        assert_eq!(known[0].line, 1);
        assert_eq!(known[0].snippet, "AKIA…MPLE");
        for (k, secret) in known.iter().zip([aws, gh.as_str(), ant]) {
            assert!(!k.snippet.contains(secret));
            let (head, tail) = k.snippet.split_once('…').expect("mascarado");
            assert!(head.chars().count() <= 4 && tail.chars().count() <= 4);
            assert_eq!(k.severity, Severity::Critical);
        }
        // Não duplica como alta entropia.
        assert!(!rules(&f).contains(&"secret.high-entropy"), "{f:?}");
    }

    #[test]
    fn hash_de_lockfile_e_hex_nao_acusam() {
        let lock = r#"      "integrity": "sha512-Xa8yT3pQz9KmN2vB7cL4wR6sE1dF5gH0jJ8kU3iO9pA2qS4zX6cV8bN1mM5lK7jH9gF3dS2aQ1wE4rT6yU8iO0pA==","#;
        assert!(scan("package-lock.json", lock).is_empty());
        let other = r#"hash = "sha512-Xa8yT3pQz9KmN2vB7cL4wR6sE1dF5gH0jJ8kU3iO9pA2qS4zX6cV8bN1mM5lK7jH9gF3dS2aQ1wE4rT6yU8iO0pA==""#;
        assert!(scan("src/a.ts", other).is_empty());
        let hex = "commit_token = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"";
        assert!(scan("src/a.ts", hex).is_empty());
        let uuid = "api_id = \"123e4567-e89b-12d3-a456-426614174000\"";
        assert!(scan("src/a.ts", uuid).is_empty());
        let url = "api_url = \"https://example.com/aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5AqZ8w\"";
        assert!(scan("src/a.ts", url).is_empty());
    }

    #[test]
    fn alta_entropia_em_atribuicao() {
        // 28 chars distintos + 4 repetidos => entropia 4.75 (entre 4.5 e 5.0).
        let token: &str = "Zx8Qp2Lm9Vt4\x52b7Nc1Hd6Kf3Wj5YZx8Q";
        assert!((shannon_entropy(token) - 4.75).abs() < 1e-9);
        let line = format!("const apiSecret = \"{token}\";");
        let f = scan("src/a.ts", &line);
        assert_eq!(rules(&f), vec!["secret.high-entropy"], "{f:?}");
        assert!(!f[0].snippet.contains(token));
        // Mesmo valor sem contexto de atribuição (entropia < 5.0) não acusa.
        assert!(scan("src/a.ts", &format!("x(\"{token}\")")).is_empty());
        // Entropia >= 5.0 acusa mesmo sem contexto.
        let f = scan("src/a.ts", "x(\"Zx8Qp2Lm9Vt4\x52b7Nc1Hd6Kf3Wj5Ys0GaEuTo\")");
        assert_eq!(rules(&f), vec!["secret.high-entropy"]);
        let line = line.as_str();
        // Em .min.js / .svg não roda entropia.
        assert!(scan("dist/app.min.js", line).is_empty());
    }

    #[test]
    fn acentos_e_emoji_nao_dao_panic() {
        let line = "senha_token = \"çãõéÁÉ😀🔥Zx8Qp2Lm9Vt4\x52b7Nc1Hd6Kf3Wj5Ys0GaEuTo😀ção\" // AKIAIOSFODNN7EXAMPLE😀";
        let f = scan("src/ç.ts", line);
        assert!(f.iter().any(|x| x.rule_id == "secret.known-prefix"));
        for x in &f {
            assert!(x.snippet.chars().count() <= 120);
        }
        let _ = scan("a.ts", &"😀".repeat(500));
        let _ = scan("a.ts", &format!("key = \"{}\"", "é".repeat(300)));
    }

    #[test]
    fn redact_line_mascara() {
        let r = redact_line("eval(\"AKIAIOSFODNN7EXAMPLE\")");
        assert_eq!(r, "eval(\"AKIA…MPLE\")");
    }

    /// Linha base64 que, sozinha, dispara alta entropia (36+ chars distintos).
    const B64_LINE: &str = "Zx8Qp2Lm9Vt4\x52b7Nc1Hd6Kf3Wj5Ys0GaEuTo+/AbCdEfGhIjKlMnOpQrStUvWxYz01";

    fn pem(kind: &str) -> String {
        format!(
            "-----BEGIN {kind}-----\n{B64_LINE}\n{B64_LINE}\n{B64_LINE}\n-----END {kind}-----\n"
        )
    }

    #[test]
    fn pem_linha_base64_isolada_dispara_precondicao() {
        assert_eq!(rules(&scan("a.txt", B64_LINE)), vec!["secret.high-entropy"]);
    }

    #[test]
    fn pem_publico_nao_gera_achado() {
        for kind in ["CERTIFICATE", "PUBLIC KEY", "CERTIFICATE REQUEST"] {
            let f = scan("certs/cert.pem", &pem(kind));
            assert!(f.is_empty(), "{kind}: {f:?}");
        }
    }

    #[test]
    fn pem_privado_gera_um_achado_na_linha_do_begin() {
        for kind in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
        ] {
            let content = format!("const x = 1;\n{}", pem(kind));
            let f = scan("keys/server.key", &content);
            assert_eq!(rules(&f), vec!["secret.known-prefix"], "{kind}: {f:?}");
            assert_eq!(f[0].line, 2);
        }
    }

    #[test]
    fn pem_depois_do_end_volta_a_acusar() {
        let content = format!(
            "{}token = \"{}\"\n",
            pem("CERTIFICATE"),
            "Zx8Qp2Lm9Vt4\x52b7Nc1Hd6Kf3Wj5Ys0GaEuTo"
        );
        let f = scan("a.ts", &content);
        assert_eq!(rules(&f), vec!["secret.high-entropy"]);
        assert_eq!(f[0].line, 6);
    }
}
