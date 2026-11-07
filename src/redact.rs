//! Redação ÚNICA de tudo que sai como `snippet` ou como `file` renderizado.
//!
//! - prefixos conhecidos e tokens que `secret.high-entropy` acusaria → mascarados;
//! - caracteres invisíveis → `<U+XXXX>`;
//! - caracteres de controle → removidos (tab vira espaço);
//! - no máximo 120 chars, cortando por fronteira de char.

use crate::scanner::secrets;
use crate::text::{SNIPPET_MAX_CHARS, mask_secret};

/// Invisíveis/formatação que nunca devem sair crus.
pub fn is_invisible(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0xE0000..=0xE007F
    )
}

enum Piece {
    Text(String),
    Marker(String),
}

impl Piece {
    fn as_str(&self) -> &str {
        match self {
            Piece::Text(s) | Piece::Marker(s) => s,
        }
    }
}

fn pieces(line: &str, mask: bool) -> Vec<Piece> {
    let ranges = if mask {
        secrets::secret_ranges(line)
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    let mut ri = 0usize;
    let mut skip_until = 0usize;
    for (i, c) in line.char_indices() {
        if i < skip_until {
            continue;
        }
        while ri < ranges.len() && ranges[ri].end <= i {
            ri += 1;
        }
        if let Some(r) = ranges.get(ri)
            && r.start == i
        {
            out.push(Piece::Text(mask_secret(&line[r.clone()])));
            skip_until = r.end;
            continue;
        }
        if is_invisible(c) {
            out.push(Piece::Marker(format!("<U+{:04X}>", c as u32)));
        } else if c == '\t' {
            out.push(Piece::Text(" ".to_string()));
        } else if c.is_control() {
            // removido
        } else {
            out.push(Piece::Text(c.to_string()));
        }
    }
    out
}

fn join_window(pieces: &[Piece], max: usize) -> String {
    let first_marker = pieces.iter().position(|p| matches!(p, Piece::Marker(_)));
    let start = first_marker.unwrap_or(0).saturating_sub(20);
    let mut out = String::new();
    let mut count = 0usize;
    let mut truncated = false;
    for p in pieces.iter().skip(start) {
        let n = p.as_str().chars().count();
        if count + n > max.saturating_sub(1) {
            truncated = true;
            break;
        }
        out.push_str(p.as_str());
        count += n;
    }
    if truncated {
        out.push('…');
    }
    out.trim().to_string()
}

/// Snippet redigido de uma linha (ou de um valor já mascarado).
pub fn snippet(line: &str) -> String {
    join_window(&pieces(line, true), SNIPPET_MAX_CHARS)
}

/// Caminho seguro para exibir: invisíveis como `<U+XXXX>`, sem controles, sem truncar.
pub fn render_path(path: &str) -> String {
    pieces(path, false)
        .iter()
        .map(|p| p.as_str().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const AKIA: &str = "AKIAIOSFODNN7EXAMPLE";
    const GHP: &str = "ghp\x5faB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A";
    const HE: &str = "Zx8Qp2Lm9Vt4\x52b7Nc1Hd6Kf3Wj5Ys0GaEuTo";

    #[test]
    fn mascara_prefixos_e_alta_entropia_e_renderiza_invisiveis() {
        let s = snippet(&format!("x\u{200B}y {AKIA} {GHP}"));
        assert_eq!(
            s,
            "x<U+200B>y AKIA…MPLE ghp_…z5A".replace("ghp_…z5A", &mask_secret(GHP))
        );
        assert!(!s.contains(AKIA) && !s.contains(GHP));
        let s = snippet(&format!("eval(x); api_secret = \"{HE}\""));
        assert!(!s.contains(HE), "{s}");
        assert!(s.starts_with("eval(x); api_secret = \""));
    }

    #[test]
    fn remove_controles() {
        let s = snippet("a\u{0007}b\u{001b}[31mc\r\td");
        assert_eq!(s, "ab[31mc d");
        assert_eq!(render_path("src/ok\n\nX\u{200B}.js"), "src/okX<U+200B>.js");
    }

    #[test]
    fn propriedade_nenhum_segredo_inteiro() {
        let segredos = [
            AKIA,
            GHP,
            HE,
            "sk\x2dant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345",
            "sk\x2dproj-AbCdEfGhIjKlMnOpQrStUvWx",
            "xoxb\x2d1234567890-abcdefghij",
            "AI\x7aaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
            "sk\x5flive_0123456789abcdefABCD",
            "github\x5fpat_11ABCDEFG0123456789_abcdefghijklmnop",
        ];
        let moldes = [
            "const k = \"{}\";",
            "{}",
            "eval(x) // {}",
            "\u{202E}{}\u{200B}",
            "ç😀ção = '{}' 😀",
            "{} {}",
        ];
        for sec in segredos {
            for m in moldes {
                let line = m.replace("{}", sec);
                let s = snippet(&line);
                assert!(!s.contains(sec), "{line:?} -> {s:?}");
                assert!(s.chars().count() <= SNIPPET_MAX_CHARS);
            }
        }
    }
}
