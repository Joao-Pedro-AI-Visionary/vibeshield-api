//! Erros da API mapeados para status + JSON do contrato. Nunca expõe detalhe interno.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("URL de repositório inválida")]
    InvalidRepoUrl,
    #[error("corpo inválido: {0}")]
    InvalidBody(String),
    #[error("repositório não encontrado")]
    RepoNotFound,
    #[error("repositório grande demais")]
    RepoTooLarge,
    #[error("limite de requisições")]
    RateLimited,
    #[error("erro no upstream: {0}")]
    Upstream(String),
    #[error("tempo de análise esgotado")]
    ScanTimeout,
    #[error("servidor ocupado")]
    ServerBusy,
    #[error("rota não encontrada")]
    NotFound,
    #[error("método não permitido")]
    MethodNotAllowed,
    #[error("erro interno: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorDetail {
    /// Um de INVALID_REPO_URL, INVALID_BODY, REPO_NOT_FOUND, REPO_TOO_LARGE,
    /// RATE_LIMITED, UPSTREAM_ERROR, SCAN_TIMEOUT, SERVER_BUSY, NOT_FOUND, METHOD_NOT_ALLOWED, INTERNAL.
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::InvalidRepoUrl | ApiError::InvalidBody(_) => StatusCode::BAD_REQUEST,
            ApiError::RepoNotFound => StatusCode::NOT_FOUND,
            ApiError::RepoTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Upstream(_) => StatusCode::BAD_GATEWAY,
            ApiError::ScanTimeout => StatusCode::GATEWAY_TIMEOUT,
            ApiError::ServerBusy => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            ApiError::InvalidRepoUrl => "INVALID_REPO_URL",
            ApiError::InvalidBody(_) => "INVALID_BODY",
            ApiError::RepoNotFound => "REPO_NOT_FOUND",
            ApiError::RepoTooLarge => "REPO_TOO_LARGE",
            ApiError::RateLimited => "RATE_LIMITED",
            ApiError::Upstream(_) => "UPSTREAM_ERROR",
            ApiError::ScanTimeout => "SCAN_TIMEOUT",
            ApiError::ServerBusy => "SERVER_BUSY",
            ApiError::NotFound => "NOT_FOUND",
            ApiError::MethodNotAllowed => "METHOD_NOT_ALLOWED",
            ApiError::Internal(_) => "INTERNAL",
        }
    }

    /// Mensagem pública em pt-BR (sem detalhes internos).
    pub fn public_message(&self) -> String {
        match self {
            ApiError::InvalidRepoUrl => {
                "Informe a URL de um repositório público do GitHub no formato https://github.com/dono/repositorio.".to_string()
            }
            ApiError::InvalidBody(_) => {
                "Corpo da requisição inválido: envie JSON com o campo \"repo_url\" (texto) e, opcionalmente, \"check_dependencies\" (booleano), até 16 KB.".to_string()
            }
            ApiError::RepoNotFound => {
                "Repositório não encontrado. Ele existe e é público?".to_string()
            }
            ApiError::RepoTooLarge => {
                "O repositório é grande demais para ser analisado por este serviço.".to_string()
            }
            ApiError::RateLimited => {
                "Muitas análises em pouco tempo. Aguarde um minuto e tente de novo.".to_string()
            }
            ApiError::Upstream(_) => {
                "O GitHub não respondeu como esperado. Tente novamente em instantes.".to_string()
            }
            ApiError::ScanTimeout => {
                "A análise passou do tempo máximo permitido.".to_string()
            }
            ApiError::ServerBusy => {
                "Todas as análises simultâneas estão ocupadas. Tente de novo em instantes.".to_string()
            }
            ApiError::NotFound => "Rota não encontrada.".to_string(),
            ApiError::MethodNotAllowed => {
                "Método HTTP não permitido para esta rota.".to_string()
            }
            ApiError::Internal(_) => "Erro interno inesperado.".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match &self {
            ApiError::Internal(d) => tracing::error!(detail = %d, "erro interno"),
            ApiError::Upstream(d) => tracing::warn!(detail = %d, "erro de upstream"),
            ApiError::InvalidBody(d) => tracing::debug!(detail = %d, "corpo inválido"),
            _ => {}
        }
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code(),
                message: self.public_message(),
            },
        };
        (self.status(), Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapeamento_status_codigo() {
        let casos = [
            (ApiError::InvalidRepoUrl, 400, "INVALID_REPO_URL"),
            (ApiError::InvalidBody("x".into()), 400, "INVALID_BODY"),
            (ApiError::RepoNotFound, 404, "REPO_NOT_FOUND"),
            (ApiError::RepoTooLarge, 413, "REPO_TOO_LARGE"),
            (ApiError::RateLimited, 429, "RATE_LIMITED"),
            (ApiError::Upstream("x".into()), 502, "UPSTREAM_ERROR"),
            (ApiError::ScanTimeout, 504, "SCAN_TIMEOUT"),
            (ApiError::ServerBusy, 503, "SERVER_BUSY"),
            (ApiError::NotFound, 404, "NOT_FOUND"),
            (ApiError::MethodNotAllowed, 405, "METHOD_NOT_ALLOWED"),
            (ApiError::Internal("segredo".into()), 500, "INTERNAL"),
        ];
        for (e, status, code) in casos {
            assert_eq!(e.status().as_u16(), status);
            assert_eq!(e.code(), code);
            assert!(!e.public_message().contains("segredo"));
        }
    }
}
