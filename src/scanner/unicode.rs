//! Unicode invisível: bidi (Trojan Source), tags (ASCII smuggling) e zero-width.

use super::{Category, RawFinding, Severity};
use crate::text::SNIPPET_MAX_CHARS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bidi,
    Tag,
    ZeroWidth,
}

fn classify(c: char) -> Option<Kind> {
    match c as u32 {
        0x202A..=0x202E | 0x2066..=0x2069 => Some(Kind::Bidi),
        0xE0000..=0xE007F => Some(Kind::Tag),
        0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF => Some(Kind::ZeroWidth),
        _ => None,
    }
}

/// Renderiza a linha trocando invisíveis por `<U+XXXX>` e corta em até 120 chars,
/// centrando a janela no primeiro invisível. `skip_first_bom` ignora BOM inicial.
fn render_snippet(line: &str, skip_first_bom: bool) -> String {
    let mut rendered: Vec<String> = Vec::new();
    let mut first_marker: Option<usize> = None;
    for (i, c) in line.chars().enumerate() {
        if i == 0 && skip_first_bom && c == '\u{FEFF}' {
            continue;
        }
        if classify(c).is_some() {
            if first_marker.is_none() {
                first_marker = Some(rendered.len());
            }
            rendered.push(format!("<U+{:04X}>", c as u32));
        } else if c == '\t' {
            rendered.push(" ".to_string());
        } else {
            rendered.push(c.to_string());
        }
    }
    let start = first_marker.unwrap_or(0).saturating_sub(20);
    let mut out = String::new();
    let mut count = 0usize;
    let mut truncated = false;
    for piece in rendered.iter().skip(start) {
        let n = piece.chars().count();
        if count + n > SNIPPET_MAX_CHARS - 1 {
            truncated = true;
            break;
        }
        out.push_str(piece);
        count += n;
    }
    if truncated {
        out.push('…');
    }
    out.trim().to_string()
}

pub fn scan(file: &str, content: &str) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let is_first = idx == 0;
        let mut found = [false; 3];
        for (ci, c) in line.chars().enumerate() {
            if is_first && ci == 0 && c == '\u{FEFF}' {
                continue; // BOM no início do arquivo é legítimo
            }
            match classify(c) {
                Some(Kind::Bidi) => found[0] = true,
                Some(Kind::Tag) => found[1] = true,
                Some(Kind::ZeroWidth) => found[2] = true,
                None => {}
            }
        }
        if !found.iter().any(|f| *f) {
            continue;
        }
        let snippet = render_snippet(line, is_first);
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if found[0] {
            out.push(RawFinding {
                rule_id: "unicode.bidi",
                category: Category::HiddenUnicode,
                severity: Severity::Critical,
                file: file.to_string(),
                line: line_no,
                snippet: snippet.clone(),
                description: "Caractere de controle bidirecional (Trojan Source): o código exibido pode ser diferente do que é executado.".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, há caracteres Unicode de controle bidirecional (U+202A–U+202E, U+2066–U+2069). Remova todos eles, reescreva a linha só com caracteres visíveis e confirme que a lógica continua a mesma."),
            });
        }
        if found[1] {
            out.push(RawFinding {
                rule_id: "unicode.tag",
                category: Category::HiddenUnicode,
                severity: Severity::Critical,
                file: file.to_string(),
                line: line_no,
                snippet: snippet.clone(),
                description: "Caracteres Unicode de tag (U+E0000–U+E007F): texto invisível que pode esconder instruções para LLMs (ASCII smuggling).".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, há caracteres Unicode de tag (U+E0000–U+E007F), invisíveis para humanos mas lidos por IAs. Remova todos eles e verifique se algum prompt ou instrução escondida foi injetado no projeto."),
            });
        }
        if found[2] {
            out.push(RawFinding {
                rule_id: "unicode.zero-width",
                category: Category::HiddenUnicode,
                severity: Severity::High,
                file: file.to_string(),
                line: line_no,
                snippet,
                description: "Caractere de largura zero: pode disfarçar identificadores, strings ou comparações.".to_string(),
                fix_prompt: format!("No arquivo {file}, linha {line_no}, há caracteres de largura zero (U+200B, U+200C, U+200D, U+2060 ou U+FEFF). Remova-os e confira se nomes de variáveis e strings ficaram idênticos ao esperado."),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
