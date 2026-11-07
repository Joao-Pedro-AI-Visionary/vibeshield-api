//! Unicode invisível: bidi (Trojan Source), tags (ASCII smuggling) e zero-width.

use super::{FileSink, RawFinding, Rule, rules};
use crate::redact;

fn classify(c: char) -> Option<Rule> {
    match c as u32 {
        0x202A..=0x202E | 0x2066..=0x2069 => Some(rules::UNICODE_BIDI),
        0xE0000..=0xE007F => Some(rules::UNICODE_TAG),
        0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF => Some(rules::UNICODE_ZERO_WIDTH),
        _ => None,
    }
}

/// Regras presentes em `text` (na ordem bidi, tag, zero-width), sem repetição.
fn rules_in(text: &str, skip_leading_bom: bool) -> Vec<Rule> {
    let mut found: Vec<Rule> = Vec::new();
    for (i, c) in text.chars().enumerate() {
        if skip_leading_bom && i == 0 && c == '\u{FEFF}' {
            continue; // BOM no início do arquivo é legítimo
        }
        if let Some(r) = classify(c)
            && !found.contains(&r)
        {
            found.push(r);
        }
    }
    let order = [
        rules::UNICODE_BIDI,
        rules::UNICODE_TAG,
        rules::UNICODE_ZERO_WIDTH,
    ];
    order.into_iter().filter(|r| found.contains(r)).collect()
}

pub fn scan_into(content: &str, sink: &mut FileSink) {
    for (idx, line) in content.lines().enumerate() {
        let is_first = idx == 0;
        let found = rules_in(line, is_first);
        if found.is_empty() {
            continue;
        }
        let shown = if is_first {
            line.strip_prefix('\u{FEFF}').unwrap_or(line)
        } else {
            line
        };
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        for rule in found {
            sink.hit(rule, line_no, || redact::snippet(shown));
        }
    }
}

/// Achados para um CAMINHO com Unicode invisível (o arquivo em si é pulado).
pub fn scan_path(raw_path: &str, rendered: &str, sink: &mut FileSink) {
    for rule in rules_in(raw_path, false) {
        sink.hit(rule, 1, || redact::snippet(rendered));
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
    use crate::scanner::Severity;

    #[test]
    fn detecta_bidi() {
        let f = scan("a.js", "let x = 1; // \u{202E} oi\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "unicode.bidi");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].snippet.contains("<U+202E>"));
    }

    #[test]
    fn detecta_tag() {
        let f = scan("a.md", "texto\nolá \u{E0041}\u{E0042} fim\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "unicode.tag");
        assert_eq!(f[0].line, 2);
        assert!(f[0].snippet.contains("<U+E0041>"));
    }

    #[test]
    fn detecta_zero_width_e_renderiza() {
        let f = scan("a.ts", "const a\u{200B}b = 1;\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "unicode.zero-width");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].snippet, "const a<U+200B>b = 1;");
    }

    #[test]
    fn bom_no_inicio_nao_acusa_mas_no_meio_sim() {
        assert!(scan("a.ts", "\u{FEFF}const a = 1;\n").is_empty());
        let f = scan("a.ts", "\u{FEFF}ok\nx\u{FEFF}y\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 2);
    }

    #[test]
    fn snippet_limitado_a_120_chars_com_multibyte() {
        let line = format!("{}\u{200B}{}", "ç".repeat(300), "😀".repeat(300));
        let f = scan("a.txt", &line);
        assert_eq!(f.len(), 1);
        assert!(f[0].snippet.chars().count() <= 120);
        assert!(f[0].snippet.contains("<U+200B>"));
    }

    #[test]
    fn snippet_de_unicode_nao_vaza_segredo_da_linha() {
        let f = scan(
            "a.ts",
            "x\u{200B}y AKIAIOSFODNN7EXAMPLE ghp\x5faB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A\n",
        );
        assert_eq!(f.len(), 1);
        assert!(!f[0].snippet.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(
            !f[0]
                .snippet
                .contains("ghp\x5faB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A")
        );
        assert!(f[0].snippet.contains("<U+200B>"));
    }
}
