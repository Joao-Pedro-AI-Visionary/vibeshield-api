//! Integração HTTP com codeload e registros falsos (sem internet).

mod common;

use std::time::Duration;

use axum::body::Body;
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{config, spawn_app, tar_gz};

struct Fakes {
    codeload: MockServer,
    npm: MockServer,
    pypi: MockServer,
}

async fn fakes() -> Fakes {
    Fakes {
        codeload: MockServer::start().await,
        npm: MockServer::start().await,
        pypi: MockServer::start().await,
    }
}

fn base_overrides(f: &Fakes) -> Vec<(&'static str, String)> {
    vec![
        ("GITHUB_CODELOAD_BASE", f.codeload.uri()),
        ("NPM_REGISTRY_BASE", f.npm.uri()),
        ("PYPI_BASE", f.pypi.uri()),
        ("RATE_LIMIT_PER_MINUTE", "1000".to_string()),
    ]
}

async fn post_scan(base: &str, body: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/v1/scans"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("requisição");
    let status = resp.status().as_u16();
    let v = resp.json::<Value>().await.expect("corpo JSON");
    (status, v)
}

fn assert_error(v: &Value, code: &str) {
    assert_eq!(v["error"]["code"], code, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty())
    );
}

#[tokio::test]
async fn health_ok() {
    let f = fakes().await;
    let base = spawn_app(config(&base_overrides(&f))).await;
    let resp = reqwest::get(format!("{base}/api/v1/health"))
        .await
        .expect("req");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("json");
    assert_eq!(v, serde_json::json!({ "status": "ok", "version": "0.1.0" }));
}

#[tokio::test]
async fn openapi_e_docs() {
    let f = fakes().await;
    let base = spawn_app(config(&base_overrides(&f))).await;
    let resp = reqwest::get(format!("{base}/api/v1/openapi.json"))
        .await
        .expect("req");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("json");
    assert!(
        v["openapi"].as_str().is_some_and(|s| s.starts_with("3.1")),
        "{}",
        v["openapi"]
    );
    assert!(v["paths"]["/api/v1/scans"]["post"].is_object());
    let docs = reqwest::get(format!("{base}/docs/")).await.expect("req");
    assert_eq!(docs.status().as_u16(), 200);
}

#[tokio::test]
async fn scan_feliz_tem_todos_os_campos() {
    let f = fakes().await;
    let tarball = tar_gz(&[
        (
            "src/app.ts",
            b"const k = \"AKIAIOSFODNN7EXAMPLE\";\nconst r = eval(input);\n",
        ),
        ("README.md", b"use eval(x) com cuidado\n"),
        (
            "package.json",
            b"{\n  \"dependencies\": {\n    \"left-padx-ia\": \"1.0.0\"\n  }\n}\n",
        ),
    ]);
    Mock::given(method("GET"))
        .and(path("/octo/demo/tar.gz/HEAD"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
        .expect(1)
        .mount(&f.codeload)
        .await;
    Mock::given(method("GET"))
        .and(path("/left-padx-ia"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&f.npm)
        .await;

    let base = spawn_app(config(&base_overrides(&f))).await;
    let (status, v) = post_scan(&base, r#"{"repo_url":"https://github.com/octo/demo.git"}"#).await;
    assert_eq!(status, 200, "{v}");

    for key in [
        "scan_id",
        "repo",
        "score",
        "grade",
        "files_scanned",
        "files_skipped",
        "bytes_downloaded",
        "duration_ms",
        "truncated",
        "summary",
        "findings",
    ] {
        assert!(v.get(key).is_some(), "campo ausente: {key}");
    }
    assert_eq!(
        v["repo"],
        serde_json::json!({"owner":"octo","name":"demo","url":"https://github.com/octo/demo"})
    );
    assert_eq!(v["files_scanned"], 3);
    assert_eq!(v["files_skipped"], 0);
    assert_eq!(v["bytes_downloaded"], tarball.len() as u64);
    assert_eq!(v["truncated"], false);
    // CRITICAL 25 + HIGH 10 + MEDIUM 4 = 39 => 61 => D
    assert_eq!(v["score"], 61);
    assert_eq!(v["grade"], "D");
    assert_eq!(
        v["summary"]["by_severity"],
        serde_json::json!({"CRITICAL":1,"HIGH":1,"MEDIUM":1,"LOW":0})
    );
    assert_eq!(
        v["summary"]["by_category"],
        serde_json::json!({"SECRET":1,"HIDDEN_UNICODE":0,"SLOPSQUATTING":1,"INSECURE_CODE":1})
    );
    let findings = v["findings"].as_array().expect("array");
    let rules: Vec<(&str, &str, u64)> = findings
        .iter()
        .map(|x| {
            (
                x["rule_id"].as_str().unwrap_or(""),
                x["file"].as_str().unwrap_or(""),
                x["line"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    assert_eq!(
        rules,
        vec![
            ("secret.known-prefix", "src/app.ts", 1),
            ("deps.not-found", "package.json", 3),
            ("code.eval", "src/app.ts", 2),
        ]
    );
    for x in findings {
        for key in [
            "id",
            "rule_id",
            "category",
            "severity",
            "file",
            "line",
            "snippet",
            "description",
            "fix_prompt",
        ] {
            assert!(x.get(key).is_some(), "achado sem {key}: {x}");
        }
        let snippet = x["snippet"].as_str().unwrap_or("");
        assert!(snippet.chars().count() <= 120);
        assert!(!snippet.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!x["file"].as_str().unwrap_or("").contains("vibeshield-"));
    }
    assert_eq!(findings[0]["snippet"], "AKIA…MPLE");
}

#[tokio::test]
async fn check_dependencies_false_nao_consulta_registro() {
    let f = fakes().await;
    let tarball = tar_gz(&[(
        "package.json",
        b"{\"dependencies\":{\"x-nao-existe\":\"1\"}}",
    )]);
    Mock::given(method("GET"))
        .and(path("/octo/demo/tar.gz/HEAD"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(&f.codeload)
        .await;
    let base = spawn_app(config(&base_overrides(&f))).await;
    let (status, v) = post_scan(
        &base,
        r#"{"repo_url":"https://github.com/octo/demo","check_dependencies":false}"#,
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["findings"], serde_json::json!([]));
    assert_eq!(v["score"], 100);
    assert_eq!(v["grade"], "A");
    assert!(
        f.npm
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
}

#[tokio::test]
async fn url_invalida_400() {
    let f = fakes().await;
    let base = spawn_app(config(&base_overrides(&f))).await;
    for url in [
        "http://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://github.com/a/b/tree/main",
        "https://github.com/a/b?x=1",
    ] {
        let body = serde_json::json!({ "repo_url": url }).to_string();
        let (status, v) = post_scan(&base, &body).await;
        assert_eq!(status, 400, "{url}");
        assert_error(&v, "INVALID_REPO_URL");
    }
    assert!(
        f.codeload
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
}

#[tokio::test]
async fn corpo_invalido_400() {
    let f = fakes().await;
    let base = spawn_app(config(&base_overrides(&f))).await;
    let big = format!("{{\"repo_url\":\"{}\"}}", "a".repeat(17 * 1024));
    for body in [
        "{quebrado",
        "{}",
        r#"{"repo_url": 123}"#,
        r#"{"repo_url":"https://github.com/a/b","check_dependencies":"sim"}"#,
        big.as_str(),
    ] {
        let (status, v) = post_scan(&base, body).await;
        assert_eq!(status, 400, "{body:.40}");
        assert_error(&v, "INVALID_BODY");
    }
}

#[tokio::test]
async fn upstream_404_e_500() {
    let f = fakes().await;
    Mock::given(method("GET"))
        .and(path("/octo/sumiu/tar.gz/HEAD"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&f.codeload)
        .await;
    Mock::given(method("GET"))
        .and(path("/octo/caiu/tar.gz/HEAD"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&f.codeload)
        .await;
    Mock::given(method("GET"))
        .and(path("/octo/lixo/tar.gz/HEAD"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"nao e gzip".to_vec()))
        .mount(&f.codeload)
        .await;
    let base = spawn_app(config(&base_overrides(&f))).await;
    let (status, v) = post_scan(&base, r#"{"repo_url":"https://github.com/octo/sumiu"}"#).await;
    assert_eq!(status, 404);
    assert_error(&v, "REPO_NOT_FOUND");
    let (status, v) = post_scan(&base, r#"{"repo_url":"https://github.com/octo/caiu"}"#).await;
    assert_eq!(status, 502);
    assert_error(&v, "UPSTREAM_ERROR");
    let (status, v) = post_scan(&base, r#"{"repo_url":"https://github.com/octo/lixo"}"#).await;
    assert_eq!(status, 502);
    assert_error(&v, "UPSTREAM_ERROR");
}

#[tokio::test]
async fn tarball_acima_do_teto_413() {
    // Servidor que responde em chunks sem Content-Length: obriga a contar o stream.
    let app = axum::Router::new().route(
        "/{owner}/{repo}/tar.gz/HEAD",
        axum::routing::get(|| async {
            let chunks = (0..64).map(|_| Ok::<_, std::io::Error>(vec![7u8; 1024]));
            Body::from_stream(futures::stream::iter(chunks))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let f = fakes().await;
    let mut ov = base_overrides(&f);
    ov.retain(|(k, _)| *k != "GITHUB_CODELOAD_BASE");
    ov.push(("GITHUB_CODELOAD_BASE", format!("http://{addr}")));
    ov.push(("MAX_DOWNLOAD_BYTES", "10000".to_string()));
    let base = spawn_app(config(&ov)).await;
    let (status, v) = post_scan(&base, r#"{"repo_url":"https://github.com/octo/grande"}"#).await;
    assert_eq!(status, 413, "{v}");
    assert_error(&v, "REPO_TOO_LARGE");
}

#[tokio::test]
async fn timeout_504() {
    let f = fakes().await;
    Mock::given(method("GET"))
        .and(path("/octo/lento/tar.gz/HEAD"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(4)))
        .mount(&f.codeload)
        .await;
    let mut ov = base_overrides(&f);
    ov.push(("SCAN_TIMEOUT_SECS", "1".to_string()));
    let base = spawn_app(config(&ov)).await;
    let (status, v) = post_scan(&base, r#"{"repo_url":"https://github.com/octo/lento"}"#).await;
    assert_eq!(status, 504);
    assert_error(&v, "SCAN_TIMEOUT");
}

#[tokio::test]
async fn rate_limit_429() {
    let f = fakes().await;
    let mut ov = base_overrides(&f);
    ov.retain(|(k, _)| *k != "RATE_LIMIT_PER_MINUTE");
    ov.push(("RATE_LIMIT_PER_MINUTE", "1".to_string()));
    let base = spawn_app(config(&ov)).await;
    let body = r#"{"repo_url":"http://invalida"}"#;
    let (s1, _) = post_scan(&base, body).await;
    assert_eq!(s1, 400);
    let (s2, v) = post_scan(&base, body).await;
    assert_eq!(s2, 429);
    assert_error(&v, "RATE_LIMITED");
    // health não é limitado
    let h = reqwest::get(format!("{base}/api/v1/health"))
        .await
        .expect("req");
    assert_eq!(h.status().as_u16(), 200);
}

#[tokio::test]
async fn cors_so_para_frontend_url() {
    let f = fakes().await;
    let mut ov = base_overrides(&f);
    ov.push((
        "FRONTEND_URL",
        "http://localhost:5173,https://app.exemplo.com".to_string(),
    ));
    let base = spawn_app(config(&ov)).await;
    let client = reqwest::Client::new();
    let preflight = |origin: &'static str| {
        client
            .request(reqwest::Method::OPTIONS, format!("{base}/api/v1/scans"))
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .send()
    };
    let ok = preflight("https://app.exemplo.com").await.expect("req");
    assert_eq!(
        ok.headers()
            .get("access-control-allow-origin")
            .and_then(|h| h.to_str().ok()),
        Some("https://app.exemplo.com")
    );
    let bad = preflight("https://malicioso.com").await.expect("req");
    assert!(bad.headers().get("access-control-allow-origin").is_none());
}
