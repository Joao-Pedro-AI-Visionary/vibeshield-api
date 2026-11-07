//! Validação da URL do repositório (regex exata do contrato + regras extras).

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use utoipa::ToSchema;

use crate::error::ApiError;

static REPO_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Regex do contrato, com grupos de captura para dono e nome.
    Regex::new(r"^https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")
        .expect("regex estática válida")
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RepoRef {
    pub owner: String,
    pub name: String,
    /// URL canônica `https://github.com/{owner}/{name}`.
    pub url: String,
}

pub fn parse_repo_url(input: &str) -> Result<RepoRef, ApiError> {
    let caps = REPO_URL_RE
        .captures(input)
        .ok_or(ApiError::InvalidRepoUrl)?;
    let owner = caps
        .get(1)
        .map(|m| m.as_str())
        .ok_or(ApiError::InvalidRepoUrl)?;
    let name = caps
        .get(2)
        .map(|m| m.as_str())
        .ok_or(ApiError::InvalidRepoUrl)?;
    if name == "." || name == ".." || name.contains("..") || input.contains("..") {
        return Err(ApiError::InvalidRepoUrl);
    }
    Ok(RepoRef {
        owner: owner.to_string(),
        name: name.to_string(),
        url: format!("https://github.com/{owner}/{name}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aceita_formas_validas() {
        let r = parse_repo_url("https://github.com/rust-lang/rust").expect("válida");
        assert_eq!((r.owner.as_str(), r.name.as_str()), ("rust-lang", "rust"));
        assert_eq!(r.url, "https://github.com/rust-lang/rust");

        let r = parse_repo_url("https://github.com/rust-lang/rust.git").expect("válida");
        assert_eq!(r.name, "rust");
        let r = parse_repo_url("https://github.com/rust-lang/rust/").expect("válida");
        assert_eq!(r.name, "rust");
        let r = parse_repo_url("https://github.com/octocat/Hello-World.git/").expect("válida");
        assert_eq!(r.name, "Hello-World");
        let r = parse_repo_url("https://github.com/a/my.repo_x").expect("válida");
        assert_eq!(r.name, "my.repo_x");
    }

    #[test]
    fn rejeita_formas_invalidas() {
        for bad in [
            "http://github.com/rust-lang/rust",
            "https://gitlab.com/rust-lang/rust",
            "https://user:pass@github.com/rust-lang/rust",
            "https://github.com/rust-lang/rust?x=1",
            "https://github.com/rust-lang/rust#frag",
            "https://github.com/rust-lang/rust/tree/main",
            "https://github.com/rust-lang/..",
            "https://github.com/rust-lang/.",
            "https://github.com/rust-lang/a..b",
            "https://github.com:443/rust-lang/rust",
            "https://github.com/-bad/rust",
            "https://github.com/rust-lang",
            " https://github.com/rust-lang/rust",
            "https://github.com/rust-lang/rust; rm -rf /",
            "",
        ] {
            assert!(parse_repo_url(bad).is_err(), "deveria rejeitar {bad:?}");
        }
    }
}
