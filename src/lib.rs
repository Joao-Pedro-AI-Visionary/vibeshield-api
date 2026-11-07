//! VibeShield API: scanner de segurança para código gerado por IA.

pub mod client_ip;
pub mod config;
pub mod deps;
pub mod error;
pub mod fetch;
pub mod redact;
pub mod repo_url;
pub mod report;
pub mod routes;
pub mod scanner;
pub mod text;

pub use config::Config;
pub use routes::{AppState, build_app};
