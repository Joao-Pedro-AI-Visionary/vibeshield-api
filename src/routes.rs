//! Rotas HTTP, middlewares e documento OpenAPI.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{Method, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::config::Config;
use crate::error::{ApiError, ErrorBody};
use crate::fetch::{self, ExtractLimits};
use crate::repo_url::{self, RepoRef};
use crate::report::{self, ReportInput, ScanReport};
use crate::{deps, scanner};

pub const BODY_LIMIT_BYTES: usize = 16 * 1024;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("vibeshield-api/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .map_err(|e| format!("falha ao criar cliente HTTP: {e}"))?;
        Ok(Self {
            config: Arc::new(config),
            http,
        })
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScanRequest {
    /// URL de um repositório público do GitHub.
    pub repo_url: String,
    /// Consulta npm/PyPI (padrão `true`).
    #[serde(default = "default_true")]
    pub check_dependencies: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "VibeShield API",
        version = "0.1.0",
        description = "Scanner de segurança para código gerado por IA."
    ),
    paths(health, create_scan),
    components(schemas(ScanRequest, ScanReport, Health, ErrorBody, RepoRef))
)]
pub struct ApiDoc;

#[utoipa::path(get, path = "/api/v1/health", responses((status = 200, body = Health)))]
pub async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: VERSION,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/scans",
    request_body = ScanRequest,
    responses(
        (status = 200, body = ScanReport),
        (status = 400, body = ErrorBody, description = "INVALID_REPO_URL ou INVALID_BODY"),
        (status = 404, body = ErrorBody, description = "REPO_NOT_FOUND"),
        (status = 413, body = ErrorBody, description = "REPO_TOO_LARGE"),
        (status = 429, body = ErrorBody, description = "RATE_LIMITED"),
        (status = 502, body = ErrorBody, description = "UPSTREAM_ERROR"),
        (status = 504, body = ErrorBody, description = "SCAN_TIMEOUT"),
        (status = 500, body = ErrorBody, description = "INTERNAL"),
    )
)]
pub async fn create_scan(
    State(state): State<AppState>,
    body: Result<Json<ScanRequest>, JsonRejection>,
) -> Result<Json<ScanReport>, ApiError> {
    let Json(req) = body.map_err(|e| ApiError::InvalidBody(e.body_text()))?;
    let repo = repo_url::parse_repo_url(&req.repo_url)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let timeout = state.config.scan_timeout;
    let result = tokio::time::timeout(
        timeout,
        run_scan(&state, repo, req.check_dependencies, Arc::clone(&cancel)),
    )
    .await;
    match result {
        Ok(r) => r.map(Json),
        Err(_) => {
            cancel.store(true, Ordering::Relaxed);
            Err(ApiError::ScanTimeout)
        }
    }
}

async fn run_scan(
    state: &AppState,
    repo: RepoRef,
    check_dependencies: bool,
    cancel: Arc<AtomicBool>,
) -> Result<ScanReport, ApiError> {
    let started = Instant::now();
    let cfg = Arc::clone(&state.config);
    let data = fetch::download_tarball(
        &state.http,
        &cfg.github_codeload_base,
        &repo,
        cfg.max_download_bytes,
    )
    .await?;
    let bytes_downloaded = data.len() as u64;

    let limits = ExtractLimits {
        max_files: cfg.max_files,
        max_file_bytes: cfg.max_file_bytes,
        max_unpacked_bytes: cfg.max_download_bytes.saturating_mul(4),
    };
    let max_file_bytes = cfg.max_file_bytes;
    let scan = tokio::task::spawn_blocking(move || -> Result<_, ApiError> {
        let dir = tempfile::Builder::new()
            .prefix("vibeshield-")
            .tempdir()
            .map_err(|e| ApiError::Internal(format!("tempdir: {e}")))?;
        let stats = fetch::extract_tarball(&data, dir.path(), limits, &cancel)?;
        drop(data);
        let out = scanner::scan_tree(dir.path(), max_file_bytes, &cancel);
        // `dir` é removido aqui (Drop do TempDir).
        Ok((stats, out))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("tarefa de varredura falhou: {e}")))?;
    let (stats, out) = scan?;

    let mut findings = out.findings;
    if check_dependencies {
        let dep_refs = deps::collect_deps(&out.manifests);
        if !dep_refs.is_empty() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0);
            let mut dep_findings = deps::check_deps(
                &state.http,
                &cfg.npm_registry_base,
                &cfg.pypi_base,
                dep_refs,
                now,
            )
            .await;
            scanner::apply_test_context(&mut dep_findings);
            findings.extend(dep_findings);
        }
    }

    Ok(report::build_report(ReportInput {
        repo,
        findings,
        files_scanned: out.files_scanned,
        files_skipped: out.files_skipped + stats.files_skipped,
        bytes_downloaded,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }))
}

async fn not_found() -> ApiError {
    ApiError::NotFound
}

async fn method_not_allowed() -> ApiError {
    ApiError::MethodNotAllowed
}

/// Monta o app completo. O rate limit por IP exige servir com
/// `into_make_service_with_connect_info::<SocketAddr>()`.
pub fn build_app(state: AppState) -> Result<Router, String> {
    let per_minute = state.config.rate_limit_per_minute.max(1);
    let period_ms = (60_000 / u64::from(per_minute)).max(1);
    let governor = GovernorConfigBuilder::default()
        .per_millisecond(period_ms)
        .burst_size(per_minute)
        .finish()
        .ok_or_else(|| "configuração de rate limit inválida".to_string())?;
    let governor = Arc::new(governor);
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let limiter = governor.limiter().clone();
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                limiter.retain_recent();
            }
        });
    }
    let rate_limit = GovernorLayer::new(governor).error_handler(|e| match e {
        tower_governor::GovernorError::TooManyRequests { .. } => {
            ApiError::RateLimited.into_response()
        }
        other => ApiError::Internal(format!("rate limit: {other}")).into_response(),
    });

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(state.config.frontend_origins.clone()))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    // `route_layer` mantém o MethodRouter (para o fallback de 405 valer aqui também).
    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/scans", post(create_scan).route_layer(rate_limit))
        .merge(SwaggerUi::new("/docs").url("/api/v1/openapi.json", ApiDoc::openapi()))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    Ok(app)
}
