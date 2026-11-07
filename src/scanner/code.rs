//! Padrões de código inseguro: CORS curinga, eval e HTML perigoso.

use std::sync::LazyLock;

use regex::Regex;

use super::{Category, RawFinding, Severity, secrets};
use crate::text::{SNIPPET_MAX_CHARS, truncate_chars};

static CORS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)access-control-allow-origin["']?\s*[:,]\s*["']?\*"#,
        r#"|\borigin\s*:\s*['"]\*['"]"#,
        r#"|allow_origin\(\s*(?:[\w:]+::)?Any\s*\)"#,
        r#"|CORS_ALLOW_ALL_ORIGINS\s*=\s*True"#,
    ))
    .expect("regex estática válida")
});

static JS_EVAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^\w.$])eval\s*\(|\bnew\s+Function\s*\(").expect("regex estática válida")
});

static PY_EVAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^\w.])(?:eval|exec)\s*\(").expect("regex estática válida"));

static HTML_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"dangerouslySetInnerHTML|\bv-html\b|\.innerHTML\s*=[^=]|\.innerHTML\s*=$")
        .expect("regex estática válida")
});

const JS_EXT: &[&str] = &["js", "ts", "jsx", "tsx", "mjs", "cjs"];
const DOC_EXT: &[&str] = &["md", "mdx", "markdown", "txt", "rst", "adoc"];

fn extension(file: &str) -> String {
    let name = file.rsplit('/').next().unwrap_or(file);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn snippet(line: &str) -> String {
    truncate_chars(secrets::redact_line(line).trim(), SNIPPET_MAX_CHARS)
}

pub fn scan(file: &str, content: &str) -> Vec<RawFinding> {
    let ext = extension(file);
    if DOC_EXT.contains(&ext.as_str()) {
        return Vec::new();
    }
    let is_js = JS_EXT.contains(&ext.as_str());
    let is_py = ext == "py";
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if CORS_RE.is_match(line) {
            out.push(RawFinding {
                rule_id: "code.cors-wildcard",
                category: Category::InsecureCode,
                severity: Severity::Medium,
                file: file.to_string(),
                line: line_no,
                snippet: snippet(line),
                description: "CORS liberado para qualquer origem (*): qualquer site pode chamar esta API pelo navegador do usuário.".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, o CORS aceita qualquer origem (*). Troque por uma lista explícita de origens permitidas lida de variável de ambiente (ex.: FRONTEND_URL), e não combine curinga com credenciais/cookies."),
            });
        }
        let eval_hit = (is_js && JS_EVAL_RE.is_match(line)) || (is_py && PY_EVAL_RE.is_match(line));
        if eval_hit {
            out.push(RawFinding {
                rule_id: "code.eval",
                category: Category::InsecureCode,
                severity: Severity::Medium,
                file: file.to_string(),
                line: line_no,
                snippet: snippet(line),
                description: "Execução dinâmica de código (eval/exec/new Function): se a entrada vier do usuário, vira execução remota de código.".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, há execução dinâmica de código (eval, exec ou new Function). Substitua por uma alternativa segura (JSON.parse/json.loads, um mapa de funções permitidas ou um parser dedicado) e garanta que nenhuma entrada do usuário seja executada como código."),
            });
        }
        if HTML_RE.is_match(line) {
            out.push(RawFinding {
                rule_id: "code.dangerous-html",
                category: Category::InsecureCode,
                severity: Severity::Low,
                file: file.to_string(),
                line: line_no,
                snippet: snippet(line),
                description: "HTML inserido sem escape (dangerouslySetInnerHTML, v-html ou innerHTML): risco de XSS se o conteúdo não for confiável.".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, HTML é inserido sem escape. Renderize como texto quando possível; se precisar de HTML, sanitize com uma biblioteca como DOMPurify antes de inserir, e nunca use conteúdo vindo do usuário sem sanitização."),
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
    fn cors_wildcard() {
        for line in [
            "res.setHeader('Access-Control-Allow-Origin', '*');",
            "Access-Control-Allow-Origin: *",
            "app.use(cors({ origin: '*' }))",
            "let cors = CorsLayer::new().allow_origin(Any);",
            "CORS_ALLOW_ALL_ORIGINS = True",
        ] {
            assert_eq!(
                rules(&scan("server.ts", line)),
                vec!["code.cors-wildcard"],
                "{line}"
            );
        }
        assert!(scan("server.ts", "app.use(cors({ origin: 'https://a.com' }))").is_empty());
    }

    #[test]
    fn eval_em_ts_sim_em_md_nao() {
        let f = scan("src/app.ts", "const r = eval(userInput);");
        assert_eq!(rules(&f), vec!["code.eval"]);
        assert_eq!(f[0].line, 1);
        assert!(scan("README.md", "const r = eval(userInput);").is_empty());
        assert_eq!(
            rules(&scan("a.js", "const f = new Function('a', b);")),
            vec!["code.eval"]
        );
        assert!(scan("a.js", "regex.exec(s); obj.eval(x); myeval(x)").is_empty());
        assert_eq!(rules(&scan("a.py", "exec(code)")), vec!["code.eval"]);
        assert!(scan("a.go", "eval(x)").is_empty());
    }

    #[test]
    fn html_perigoso() {
        assert_eq!(
            rules(&scan(
                "a.jsx",
                "<div dangerouslySetInnerHTML={{__html: x}} />"
            )),
            vec!["code.dangerous-html"]
        );
        assert_eq!(
            rules(&scan("a.vue", "<p v-html=\"raw\"></p>")),
            vec!["code.dangerous-html"]
        );
        assert_eq!(
            rules(&scan("a.js", "el.innerHTML = x;")),
            vec!["code.dangerous-html"]
        );
        assert!(scan("a.js", "if (el.innerHTML == x) {}").is_empty());
    }

    #[test]
    fn snippet_mascara_segredo_na_linha() {
        let f = scan("a.ts", "eval(\"AKIAIOSFODNN7EXAMPLE\")");
        assert_eq!(f[0].snippet, "eval(\"AKIA…MPLE\")");
    }
}
