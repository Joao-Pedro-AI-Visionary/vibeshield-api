//! Utilidades de texto. Todo corte é por fronteira de char (nunca `&s[..n]` em bytes).

/// Tamanho máximo de um snippet, em caracteres.
pub const SNIPPET_MAX_CHARS: usize = 120;

/// Corta `s` para no máximo `max` caracteres; se cortar, termina com `…` (que conta no limite).
pub fn truncate_chars(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// Mascara um segredo: no máximo 4 chars de cada ponta + `…`.
/// Segredos curtos mostram menos (nunca mais que 1/4 de cada lado).
pub fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let keep = (chars.len() / 4).min(4);
    if keep == 0 {
        return "…".to_string();
    }
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{head}…{tail}")
}

/// Entropia de Shannon (bits por símbolo), calculada sobre chars.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respeita_utf8() {
        let s = "ação😀".repeat(100);
        let t = truncate_chars(&s, 120);
        assert_eq!(t.chars().count(), 120);
        assert!(t.ends_with('…'));
        assert_eq!(truncate_chars("abc", 120), "abc");
    }

    #[test]
    fn mask_nunca_mostra_mais_que_4_de_cada_ponta() {
        assert_eq!(mask_secret("AKI\x41ABCDEFGHIJKLMNOP"), "AKIA…MNOP");
        assert_eq!(mask_secret("çãõé😀çãõé😀çãõé😀xx"), "çãõé…é😀xx");
        assert_eq!(mask_secret("abc"), "…");
        assert_eq!(mask_secret("abcdefgh"), "ab…gh");
    }

    #[test]
    fn entropia_basica() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }
}
