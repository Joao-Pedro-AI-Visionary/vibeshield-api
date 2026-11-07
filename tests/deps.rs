//! Checagem de dependências contra registros falsos (sem internet).

use std::time::{SystemTime, UNIX_EPOCH};

use vibeshield_api::deps::{check_deps, collect_deps};
use vibeshield_api::scanner::{Category, Manifest, Severity};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn iso(unix: i64) -> String {
    // Converte de volta para ISO 8601 (só para montar o fixture).
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[tokio::test]
async fn npm_e_pypi_contra_registro_falso() {
    let npm = MockServer::start().await;
    let pypi = MockServer::start().await;
    let now = now();

    Mock::given(method("GET"))
        .and(path("/pacote-alucinado"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&npm)
        .await;
    Mock::given(method("GET"))
        .and(path("/pacote-novo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "pacote-novo",
            "time": { "created": iso(now - 5 * 86_400) }
        })))
        .expect(1)
        .mount(&npm)
        .await;
    Mock::given(method("GET"))
        .and(path("/@scope%2Fpkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "time": { "created": "2015-01-01T00:00:00.000Z" }
        })))
        .expect(1)
        .mount(&npm)
        .await;
    Mock::given(method("GET"))
        .and(path("/pypi/inexistente-py/json"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&pypi)
        .await;
    Mock::given(method("GET"))
        .and(path("/pypi/django/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "releases": { "1.0": [ { "upload_time_iso_8601": "2005-07-21T00:00:00.000Z" } ] }
        })))
        .expect(1)
        .mount(&pypi)
        .await;

    let manifests = vec![
        Manifest {
            file: "web/package.json".into(),
            content: r#"{
  "dependencies": {
    "pacote-alucinado": "^1.0.0",
    "pacote-novo": "1.0.0",
    "@scope/pkg": "2.0.0",
    "local": "file:../local"
  }
}"#
            .into(),
        },
        Manifest {
            file: "requirements.txt".into(),
            content: "Django==4.2\ninexistente_py>=1\n".into(),
        },
    ];
    let deps = collect_deps(&manifests);
    assert!(deps.iter().all(|d| d.name != "local"), "file: ignorado");

    let base_npm = npm.uri();
    let base_pypi = pypi.uri();
    let client = reqwest::Client::new();
    let mut findings = check_deps(&client, &base_npm, &base_pypi, deps, now)
        .await
        .retained;
    findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.file.cmp(&b.file)));

    let got: Vec<(&str, &str, Severity, u32)> = findings
        .iter()
        .map(|f| (f.rule_id, f.file.as_str(), f.severity, f.line))
        .collect();
    assert_eq!(
        got,
        vec![
            ("deps.not-found", "requirements.txt", Severity::High, 2),
            ("deps.not-found", "web/package.json", Severity::High, 3),
            ("deps.too-new", "web/package.json", Severity::Medium, 4),
        ],
        "{findings:#?}"
    );
    assert!(
        findings
            .iter()
            .all(|f| f.category == Category::Slopsquatting)
    );
    assert!(
        vibeshield_api::report::describe(&findings[1])
            .0
            .contains("\"pacote-alucinado\"")
    );

    // Nenhuma requisição para o pacote `file:`.
    let reqs = npm.received_requests().await.unwrap_or_default();
    assert!(reqs.iter().all(|r| r.url.path() != "/local"));
    assert!(reqs.iter().any(|r| r.url.path() == "/@scope%2Fpkg"));
}

#[tokio::test]
async fn erro_ou_timeout_do_registro_nao_gera_achado() {
    let npm = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lento"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(7)))
        .mount(&npm)
        .await;
    Mock::given(method("GET"))
        .and(path("/quebrado"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&npm)
        .await;
    let manifests = vec![Manifest {
        file: "package.json".into(),
        content: r#"{"dependencies":{"lento":"1","quebrado":"1"}}"#.into(),
    }];
    let started = std::time::Instant::now();
    let client = reqwest::Client::new();
    let f = check_deps(
        &client,
        &npm.uri(),
        "http://127.0.0.1:9",
        collect_deps(&manifests),
        now(),
    )
    .await
    .retained;
    assert!(f.is_empty(), "{f:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(7),
        "timeout de 5s respeitado"
    );
}
