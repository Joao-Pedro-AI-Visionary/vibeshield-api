#![allow(dead_code)] // cada binário de teste usa um subconjunto destes helpers

use std::collections::HashMap;
use std::net::SocketAddr;

use flate2::Compression;
use flate2::write::GzEncoder;
use vibeshield_api::{AppState, Config, build_app};

/// Tarball `.tar.gz` com prefixo `owner-repo-sha/`, como o do codeload.
pub fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let gz = GzEncoder::new(Vec::new(), Compression::fast());
    let mut b = tar::Builder::new(gz);
    for (path, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append_data(&mut h, format!("octo-demo-0123abc/{path}"), *data)
            .expect("append");
    }
    b.into_inner().expect("tar").finish().expect("gz")
}

pub fn config(overrides: &[(&str, String)]) -> Config {
    let map: HashMap<String, String> = overrides
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    Config::from_lookup(|k| map.get(k).cloned()).expect("config de teste válida")
}

/// Sobe o app numa porta efêmera local e devolve a URL base.
pub async fn spawn_app(cfg: Config) -> String {
    let state = AppState::new(cfg).expect("state");
    let app = build_app(state).expect("app");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}
