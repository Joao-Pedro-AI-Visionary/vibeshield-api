//! Configuração lida do ambiente. Valor inválido falha no boot com mensagem clara.

use std::time::Duration;

use axum::http::HeaderValue;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("variável de ambiente {name} inválida ({value:?}): {reason}")]
    Invalid {
        name: &'static str,
        value: String,
        reason: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub frontend_origins: Vec<HeaderValue>,
    pub max_download_bytes: u64,
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub scan_timeout: Duration,
    pub rate_limit_per_minute: u32,
    pub github_codeload_base: String,
    pub npm_registry_base: String,
    pub pypi_base: String,
}

impl Config {
    /// Lê do ambiente do processo.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Lê de uma função de busca (testável sem mexer no ambiente global).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let port = parse_num::<u16>(&get, "PORT", 8080)?;
        let max_download_bytes = parse_num::<u64>(&get, "MAX_DOWNLOAD_BYTES", 52_428_800)?;
        let max_file_bytes = parse_num::<u64>(&get, "MAX_FILE_BYTES", 1_048_576)?;
        let max_files = parse_num::<usize>(&get, "MAX_FILES", 20_000)?;
        let scan_timeout_secs = parse_num::<u64>(&get, "SCAN_TIMEOUT_SECS", 60)?;
        let rate_limit_per_minute = parse_num::<u32>(&get, "RATE_LIMIT_PER_MINUTE", 10)?;

        positive("MAX_DOWNLOAD_BYTES", max_download_bytes)?;
        positive("MAX_FILE_BYTES", max_file_bytes)?;
        positive("MAX_FILES", max_files as u64)?;
        positive("SCAN_TIMEOUT_SECS", scan_timeout_secs)?;
        positive("RATE_LIMIT_PER_MINUTE", u64::from(rate_limit_per_minute))?;
        if rate_limit_per_minute > 60_000 {
            return Err(ConfigError::Invalid {
                name: "RATE_LIMIT_PER_MINUTE",
                value: rate_limit_per_minute.to_string(),
                reason: "máximo de 60000",
            });
        }

        let frontend_raw =
            get("FRONTEND_URL").unwrap_or_else(|| "http://localhost:5173".to_string());
        let mut frontend_origins = Vec::new();
        for origin in frontend_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let valid = (origin.starts_with("http://") || origin.starts_with("https://"))
                && !origin.ends_with('/');
            let header = HeaderValue::from_str(origin).ok().filter(|_| valid);
            match header {
                Some(h) => frontend_origins.push(h),
                None => {
                    return Err(ConfigError::Invalid {
                        name: "FRONTEND_URL",
                        value: origin.to_string(),
                        reason: "cada origem deve ser http(s)://host[:porta], sem barra final",
                    });
                }
            }
        }
        if frontend_origins.is_empty() {
            return Err(ConfigError::Invalid {
                name: "FRONTEND_URL",
                value: frontend_raw,
                reason: "informe ao menos uma origem",
            });
        }

        Ok(Self {
            port,
            frontend_origins,
            max_download_bytes,
            max_file_bytes,
            max_files,
            scan_timeout: Duration::from_secs(scan_timeout_secs),
            rate_limit_per_minute,
            github_codeload_base: base_url(
                &get,
                "GITHUB_CODELOAD_BASE",
                "https://codeload.github.com",
            )?,
            npm_registry_base: base_url(&get, "NPM_REGISTRY_BASE", "https://registry.npmjs.org")?,
            pypi_base: base_url(&get, "PYPI_BASE", "https://pypi.org")?,
        })
    }
}

fn parse_num<T: std::str::FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: T,
) -> Result<T, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(v) => v.trim().parse::<T>().map_err(|_| ConfigError::Invalid {
            name,
            value: v,
            reason: "esperado um número inteiro não negativo",
        }),
    }
}

fn positive(name: &'static str, v: u64) -> Result<(), ConfigError> {
    if v == 0 {
        return Err(ConfigError::Invalid {
            name,
            value: "0".to_string(),
            reason: "deve ser maior que zero",
        });
    }
    Ok(())
}

fn base_url(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: &str,
) -> Result<String, ConfigError> {
    let v = get(name).unwrap_or_else(|| default.to_string());
    let trimmed = v.trim().trim_end_matches('/').to_string();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(ConfigError::Invalid {
            name,
            value: v,
            reason: "deve começar com http:// ou https://",
        });
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_do_contrato() {
        let c = cfg(&[]).expect("defaults válidos");
        assert_eq!(c.port, 8080);
        assert_eq!(c.max_download_bytes, 52_428_800);
        assert_eq!(c.max_file_bytes, 1_048_576);
        assert_eq!(c.max_files, 20_000);
        assert_eq!(c.scan_timeout, Duration::from_secs(60));
        assert_eq!(c.rate_limit_per_minute, 10);
        assert_eq!(c.github_codeload_base, "https://codeload.github.com");
        assert_eq!(c.frontend_origins.len(), 1);
    }

    #[test]
    fn lista_de_origens_e_valores_invalidos() {
        let c = cfg(&[("FRONTEND_URL", "http://a.com, https://b.com")]).expect("ok");
        assert_eq!(c.frontend_origins.len(), 2);
        assert!(cfg(&[("PORT", "abc")]).is_err());
        assert!(cfg(&[("RATE_LIMIT_PER_MINUTE", "0")]).is_err());
        assert!(cfg(&[("FRONTEND_URL", "*")]).is_err());
        assert!(cfg(&[("NPM_REGISTRY_BASE", "ftp://x")]).is_err());
    }
}
