//! Slopsquatting: dependências que não existem (ou são novas demais) nos registros públicos.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

use futures::StreamExt;
use regex::Regex;

use crate::scanner::{Category, Manifest, RawFinding, Severity};

pub const MAX_CONCURRENCY: usize = 8;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Teto de dependências consultadas por scan (protege tempo e os registros).
pub const MAX_DEPS: usize = 300;
/// Teto do corpo lido de cada registro (packuments gigantes = pacotes antigos).
const MAX_REGISTRY_BODY: usize = 8 * 1024 * 1024;
const TOO_NEW_SECS: i64 = 30 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    PyPi,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepRef {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub file: String,
    pub line: u32,
}

static NPM_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:@[a-zA-Z0-9\-~][a-zA-Z0-9\-._~]*/)?[a-zA-Z0-9\-~][a-zA-Z0-9\-._~]*$")
        .expect("regex estática válida")
});

static PY_REQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;].*)?$",
    )
    .expect("regex estática válida")
});

static PY_SEP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[-_.]+").expect("regex estática válida"));

const NPM_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

const NPM_IGNORED_SPECS: &[&str] = &[
    "file:",
    "link:",
    "workspace:",
    "git+",
    "git:",
    "github:",
    "http:",
    "https:",
    "npm:",
    "portal:",
    "patch:",
];

fn npm_spec_ignored(spec: &str) -> bool {
    let s = spec.trim();
    if NPM_IGNORED_SPECS.iter().any(|p| s.starts_with(p)) {
        return true;
    }
    // atalho `usuario/repo` do GitHub
    s.contains('/') && !s.starts_with('@')
}

fn line_of_key(content: &str, name: &str) -> u32 {
    let needle = format!("\"{name}\"");
    content
        .lines()
        .position(|l| {
            l.find(&needle)
                .is_some_and(|i| l[i + needle.len()..].trim_start().starts_with(':'))
        })
        .and_then(|i| u32::try_from(i + 1).ok())
        .unwrap_or(1)
}

pub fn parse_package_json(file: &str, content: &str) -> Vec<DepRef> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in NPM_SECTIONS {
        let Some(map) = v.get(section).and_then(|s| s.as_object()) else {
            continue;
        };
        for (name, spec) in map {
            let Some(spec) = spec.as_str() else { continue };
            if npm_spec_ignored(spec) || !NPM_NAME_RE.is_match(name) || name.len() > 214 {
                continue;
            }
            if out.iter().any(|d: &DepRef| &d.name == name) {
                continue;
            }
            out.push(DepRef {
                ecosystem: Ecosystem::Npm,
                name: name.clone(),
                file: file.to_string(),
                line: line_of_key(content, name),
            });
        }
    }
    // Ordem do manifesto (o Map do serde_json é ordenado por nome).
    out.sort_by_key(|d| d.line);
    out
}

pub fn normalize_pypi(name: &str) -> String {
    PY_SEP_RE
        .replace_all(&name.to_ascii_lowercase(), "-")
        .into_owned()
}

pub fn parse_requirements(file: &str, content: &str) -> Vec<DepRef> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.split(" #").next().unwrap_or("").trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('-')
            || line.contains("://")
            || line.contains(" @ ")
            || line.starts_with("git+")
        {
            continue;
        }
        let Some(caps) = PY_REQ_RE.captures(line) else {
            continue;
        };
        let Some(name) = caps.get(1).map(|m| normalize_pypi(m.as_str())) else {
            continue;
        };
        if out.iter().any(|d: &DepRef| d.name == name) {
            continue;
        }
        out.push(DepRef {
            ecosystem: Ecosystem::PyPi,
            name,
            file: file.to_string(),
            line: u32::try_from(idx + 1).unwrap_or(u32::MAX),
        });
    }
    out
}

pub fn collect_deps(manifests: &[Manifest]) -> Vec<DepRef> {
    let mut out = Vec::new();
    for m in manifests {
        let name = m.file.rsplit('/').next().unwrap_or(&m.file);
        match name {
            "package.json" => out.extend(parse_package_json(&m.file, &m.content)),
            "requirements.txt" => out.extend(parse_requirements(&m.file, &m.content)),
            _ => {}
        }
    }
    out.truncate(MAX_DEPS);
    out
}

/// URL do registro. Escopo `@a/b` vira `@a%2Fb`.
pub fn registry_url(eco: Ecosystem, name: &str, npm_base: &str, pypi_base: &str) -> String {
    match eco {
        Ecosystem::Npm => format!("{npm_base}/{}", name.replace('/', "%2F")),
        Ecosystem::PyPi => format!("{pypi_base}/pypi/{name}/json"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    NotFound,
    /// Existe; `created` em segundos Unix, se conhecido.
    Exists(Option<i64>),
    /// Erro/timeout: sem achado (não acusamos o que não verificamos).
    Unknown,
}

/// Converte `YYYY-MM-DDTHH:MM:SS...` em segundos Unix (UTC; fração/fuso ignorados
/// além do `Z`, precisão de dia é suficiente para a regra de 30 dias).
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse::<i64>().ok() };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = if b.len() >= 19 && (b[10] == b'T' || b[10] == b' ') {
        (num(11..13)?, num(14..16)?, num(17..19)?)
    } else {
        (0, 0, 0)
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // days_from_civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

fn created_from_npm(v: &serde_json::Value) -> Option<i64> {
    v.get("time")?
        .get("created")?
        .as_str()
        .and_then(parse_rfc3339)
}

fn created_from_pypi(v: &serde_json::Value) -> Option<i64> {
    let releases = v.get("releases")?.as_object()?;
    releases
        .values()
        .filter_map(|files| files.as_array())
        .flatten()
        .filter_map(|f| {
            f.get("upload_time_iso_8601")
                .or_else(|| f.get("upload_time"))
        })
        .filter_map(|t| t.as_str().and_then(parse_rfc3339))
        .min()
}

async fn read_capped(resp: reqwest::Response) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if buf.len() + chunk.len() > MAX_REGISTRY_BODY {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf)
}

pub async fn lookup(
    client: &reqwest::Client,
    eco: Ecosystem,
    name: &str,
    npm_base: &str,
    pypi_base: &str,
) -> Lookup {
    let url = registry_url(eco, name, npm_base, pypi_base);
    let fut = async {
        let resp = match client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(%url, error = %e, "falha ao consultar registro");
                return Lookup::Unknown;
            }
        };
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Lookup::NotFound;
        }
        if !status.is_success() {
            return Lookup::Unknown;
        }
        let Some(body) = read_capped(resp).await else {
            // corpo gigante: pacote existente e antigo
            return Lookup::Exists(None);
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return Lookup::Exists(None);
        };
        Lookup::Exists(match eco {
            Ecosystem::Npm => created_from_npm(&v),
            Ecosystem::PyPi => created_from_pypi(&v),
        })
    };
    // Timeout total por requisição (inclui leitura do corpo).
    tokio::time::timeout(REQUEST_TIMEOUT, fut)
        .await
        .unwrap_or(Lookup::Unknown)
}

fn registry_label(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "PyPI",
    }
}

/// Consulta os registros com concorrência ≤ 8 e devolve os achados.
pub async fn check_deps(
    client: &reqwest::Client,
    npm_base: &str,
    pypi_base: &str,
    deps: Vec<DepRef>,
    now_unix: i64,
) -> Vec<RawFinding> {
    let mut unique: Vec<(Ecosystem, String)> = Vec::new();
    for d in &deps {
        let key = (d.ecosystem, d.name.clone());
        if !unique.contains(&key) {
            unique.push(key);
        }
    }
    let results: HashMap<(Ecosystem, String), Lookup> = futures::stream::iter(unique)
        .map(|(eco, name)| async move {
            let r = lookup(client, eco, &name, npm_base, pypi_base).await;
            ((eco, name), r)
        })
        .buffer_unordered(MAX_CONCURRENCY)
        .collect()
        .await;

    let mut out = Vec::new();
    for d in deps {
        let reg = registry_label(d.ecosystem);
        let name = &d.name;
        let file = &d.file;
        let line = d.line;
        match results.get(&(d.ecosystem, d.name.clone())) {
            Some(Lookup::NotFound) => out.push(RawFinding {
                rule_id: "deps.not-found",
                category: Category::Slopsquatting,
                severity: Severity::High,
                file: d.file.clone(),
                line,
                snippet: crate::text::truncate_chars(name, crate::text::SNIPPET_MAX_CHARS),
                description: format!("O pacote \"{name}\" não existe no {reg}. Pode ser uma dependência alucinada por IA, que um atacante pode registrar (slopsquatting)."),
                fix_prompt: format!("Em {file}, linha {line}, a dependência \"{name}\" não existe no {reg}. Verifique qual pacote real faz o que o código precisa, troque pelo nome correto (confirmando no site do registro) ou remova a dependência e o código que a usa. Não registre nem instale nomes que não existem."),
            }),
            Some(Lookup::Exists(Some(created))) if now_unix - created < TOO_NEW_SECS => {
                let days = ((now_unix - created).max(0)) / 86_400;
                out.push(RawFinding {
                    rule_id: "deps.too-new",
                    category: Category::Slopsquatting,
                    severity: Severity::Medium,
                    file: d.file.clone(),
                    line,
                    snippet: crate::text::truncate_chars(name, crate::text::SNIPPET_MAX_CHARS),
                    description: format!("O pacote \"{name}\" foi criado no {reg} há {days} dia(s). Pacotes muito novos com nomes plausíveis são um vetor típico de slopsquatting."),
                    fix_prompt: format!("Em {file}, linha {line}, a dependência \"{name}\" foi publicada no {reg} há menos de 30 dias. Confirme que é o pacote oficial (autor, repositório, downloads); se houver dúvida, troque por uma alternativa estabelecida ou fixe uma versão auditada."),
                });
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_json_ignora_especificadores() {
        let content = r#"{
  "name": "app",
  "dependencies": {
    "react": "^18.0.0",
    "@scope/pkg": "1.0.0",
    "local": "file:../local",
    "alias": "npm:react@18",
    "ws": "workspace:*",
    "gh": "github:user/repo",
    "short": "user/repo",
    "url": "https://x.com/a.tgz"
  },
  "devDependencies": { "vitest": "1.0.0" }
}"#;
        let deps = parse_package_json("package.json", content);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["react", "@scope/pkg", "vitest"]);
        assert_eq!(deps[0].line, 4);
        assert_eq!(deps[2].line, 13);
    }

    #[test]
    fn parse_requirements_basico() {
        let content = "# comentario\nDjango==4.2\nrequests[security]>=2 # x\n-r outro.txt\ngit+https://x/y.git\nfoo @ https://x/foo.whl\nZope.Interface\n";
        let deps = parse_requirements("requirements.txt", content);
        let got: Vec<(&str, u32)> = deps.iter().map(|d| (d.name.as_str(), d.line)).collect();
        assert_eq!(
            got,
            vec![("django", 2), ("requests", 3), ("zope-interface", 7)]
        );
    }

    #[test]
    fn url_escopo_usa_percent_2f() {
        assert_eq!(
            registry_url(Ecosystem::Npm, "@scope/pkg", "http://npm", "http://pypi"),
            "http://npm/@scope%2Fpkg"
        );
        assert_eq!(
            registry_url(Ecosystem::PyPi, "django", "http://npm", "http://pypi"),
            "http://pypi/pypi/django/json"
        );
    }

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2000-03-01T00:00:00.000Z"), Some(951_868_800));
        assert_eq!(parse_rfc3339("2024-02-29"), Some(1_709_164_800));
        assert_eq!(parse_rfc3339("lixo"), None);
        assert_eq!(parse_rfc3339("2024-13-01"), None);
    }
}
