//! Padrões de código inseguro: CORS curinga, eval e HTML perigoso.

use std::sync::LazyLock;

use regex::Regex;

use super::{FileSink, RawFinding, rules};
use crate::redact;

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
    Regex::new(r"dangerouslySetInnerHTML|\bv-html\b").expect("regex estática válida")
});

static INNER_HTML_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.innerHTML\s*=").expect("regex estática válida"));

/// Se `s` começa com um literal string completo, devolve o resto após ele.
/// Template com `${` não conta como literal.
fn strip_string_literal(s: &str) -> Option<&str> {
    let mut chars = s.char_indices();
    let (_, quote) = chars.next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }
    let mut escaped = false;
    let mut prev_dollar = false;
    for (i, c) in chars {
        if escaped {
            escaped = false;
            prev_dollar = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '{' if quote == '`' && prev_dollar => return None,
            c if c == quote => return Some(&s[i + c.len_utf8()..]),
            _ => {}
        }
        prev_dollar = c == '$';
    }
    None // literal não fechado na linha: não dá para afirmar que é estático
}

/// `true` se alguma atribuição `.innerHTML =` da linha tem lado direito não literal.
fn inner_html_dynamic(line: &str) -> bool {
    for m in INNER_HTML_RE.find_iter(line) {
        let rest = &line[m.end()..];
        if rest.starts_with('=') {
            continue; // comparação `==`/`===`
        }
        let rhs = rest.trim_start();
        let is_literal = strip_string_literal(rhs).is_some_and(|after| {
            let after = after.trim_start();
            after.is_empty() || after.starts_with(';') || after.starts_with("//")
        });
        if !is_literal {
            return true;
        }
    }
    false
}

const JS_EXT: &[&str] = &["js", "ts", "jsx", "tsx", "mjs", "cjs"];
const DOC_EXT: &[&str] = &["md", "mdx", "markdown", "txt", "rst", "adoc"];

fn extension(file: &str) -> String {
    let name = file.rsplit('/').next().unwrap_or(file);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub fn scan_into(content: &str, sink: &mut FileSink) {
    let ext = extension(sink.file());
    if DOC_EXT.contains(&ext.as_str()) {
        return;
    }
    let is_js = JS_EXT.contains(&ext.as_str());
    let is_py = ext == "py";
    for (idx, line) in content.lines().enumerate() {
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if CORS_RE.is_match(line) {
            sink.hit(rules::CODE_CORS, line_no, || redact::snippet(line));
        }
        let eval_hit = (is_js && JS_EVAL_RE.is_match(line)) || (is_py && PY_EVAL_RE.is_match(line));
        if eval_hit {
            sink.hit(rules::CODE_EVAL, line_no, || redact::snippet(line));
        }
        if HTML_RE.is_match(line) || inner_html_dynamic(line) {
            sink.hit(rules::CODE_HTML, line_no, || redact::snippet(line));
        }
    }
}

/// Conveniência para testes.
pub fn scan(file: &str, content: &str) -> Vec<RawFinding> {
    let mut sink = FileSink::new(file);
    scan_into(content, &mut sink);
    sink.finish().0
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

    #[test]
    fn inner_html_com_literal_puro_nao_acusa() {
        for line in [
            "el.innerHTML = '';",
            "el.innerHTML = \"\";",
            "el.innerHTML = '<span>Searching...</span>';",
            "el.innerHTML = \"<b>a;b</b>\"; // ok",
            "el.innerHTML = `<p>estático</p>`;",
            "el.innerHTML = 'it\\'s';",
            "el.innerHTML=''",
        ] {
            assert!(scan("a.js", line).is_empty(), "{line}");
        }
    }

    #[test]
    fn inner_html_dinamico_continua_acusando() {
        for line in [
            "el.innerHTML = x;",
            "el.innerHTML = '<b>' + name + '</b>';",
            "el.innerHTML = `<b>${name}</b>`;",
            "el.innerHTML = html",
            "a.innerHTML = ''; b.innerHTML = user;",
            "el.innerHTML =",
        ] {
            assert_eq!(
                rules(&scan("a.js", line)),
                vec!["code.dangerous-html"],
                "{line}"
            );
        }
    }
}
