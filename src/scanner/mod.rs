//! Varredura dos arquivos extraídos: Unicode oculto, segredos e código inseguro.

pub mod code;
pub mod secrets;
pub mod unicode;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Severity::Critical => 25,
            Severity::High => 10,
            Severity::Medium => 4,
            Severity::Low => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    Secret,
    HiddenUnicode,
    Slopsquatting,
    InsecureCode,
}

/// Achado bruto (o `id` é atribuído na montagem do relatório).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFinding {
    pub rule_id: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub file: String,
    pub line: u32,
    pub snippet: String,
    pub description: String,
    pub fix_prompt: String,
}

/// Manifesto de dependências encontrado na árvore.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub file: String,
    pub content: String,
}

#[derive(Debug, Default)]
pub struct ScanOutput {
    pub findings: Vec<RawFinding>,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub manifests: Vec<Manifest>,
}

const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "dist", "build", "vendor"];
const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// Aplica todas as regras de conteúdo a um arquivo de texto.
pub fn scan_text(file: &str, content: &str) -> Vec<RawFinding> {
    let mut out = unicode::scan(file, content);
    out.extend(secrets::scan(file, content));
    out.extend(code::scan(file, content));
    apply_test_context(&mut out);
    out
}

const TEST_SEGMENTS: &[&str] = &[
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    "__fixtures__",
    "examples",
    "example",
    "e2e",
];

pub const TEST_SUFFIX: &str = " (em arquivo de teste/exemplo)";

/// Caminho de teste/exemplo: diretório com nome da lista ou arquivo `*.test.*`/`*.spec.*`.
pub fn is_test_path(file: &str) -> bool {
    let mut segments: Vec<&str> = file.split('/').collect();
    let name = segments.pop().unwrap_or("");
    if segments.iter().any(|s| TEST_SEGMENTS.contains(s)) {
        return true;
    }
    // `a.test.ts`: o marcador precisa ter algo antes e uma extensão depois.
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= 3
        && !parts[0].is_empty()
        && parts[1..parts.len() - 1]
            .iter()
            .any(|p| *p == "test" || *p == "spec")
}

/// Rebaixa um nível a severidade de achados em arquivos de teste/exemplo
/// (exceto `unicode.*`, que é ataque em qualquer lugar).
pub fn apply_test_context(findings: &mut [RawFinding]) {
    for f in findings.iter_mut() {
        if f.rule_id.starts_with("unicode.") || !is_test_path(&f.file) {
            continue;
        }
        f.severity = match f.severity {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium | Severity::Low => Severity::Low,
        };
        f.description.push_str(TEST_SUFFIX);
    }
}

/// Caminho relativo com `/`, sem expor o diretório temporário.
pub fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn is_manifest(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == "package.json" || name == "requirements.txt"
}

enum FileResult {
    Scanned {
        findings: Vec<RawFinding>,
        manifest: Option<Manifest>,
    },
    Skipped,
    Cancelled,
}

/// Varre a árvore em `root` (respeitando .gitignore) em paralelo com rayon.
/// Deve ser chamada dentro de `spawn_blocking`.
pub fn scan_tree(root: &Path, max_file_bytes: u64, cancel: &AtomicBool) -> ScanOutput {
    let mut files: Vec<PathBuf> = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .parents(false)
        .ignore(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|e| {
            let is_dir = e.file_type().is_some_and(|t| t.is_dir());
            !(is_dir && e.depth() > 0 && SKIP_DIRS.iter().any(|d| e.file_name() == *d))
        })
        .build();
    for entry in walker.flatten() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if entry.file_type().is_some_and(|t| t.is_file()) {
            files.push(entry.into_path());
        }
    }

    let results: Vec<FileResult> = files
        .par_iter()
        .map(|path| {
            if cancel.load(Ordering::Relaxed) {
                return FileResult::Cancelled;
            }
            scan_one(root, path, max_file_bytes)
        })
        .collect();

    let mut out = ScanOutput::default();
    for r in results {
        match r {
            FileResult::Scanned { findings, manifest } => {
                out.files_scanned += 1;
                out.findings.extend(findings);
                if let Some(m) = manifest {
                    out.manifests.push(m);
                }
            }
            FileResult::Skipped => out.files_skipped += 1,
            FileResult::Cancelled => {}
        }
    }
    out.manifests.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

fn scan_one(root: &Path, path: &Path, max_file_bytes: u64) -> FileResult {
    let Some(rel) = relative_path(root, path) else {
        return FileResult::Skipped;
    };
    let too_big = std::fs::symlink_metadata(path).map_or(true, |m| m.len() > max_file_bytes);
    if too_big {
        return FileResult::Skipped;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return FileResult::Skipped;
    };
    let sniff = &bytes[..bytes.len().min(BINARY_SNIFF_BYTES)];
    if sniff.contains(&0) {
        return FileResult::Skipped;
    }
    let content = String::from_utf8_lossy(&bytes);
    let findings = scan_text(&rel, &content);
    let manifest = is_manifest(&rel).then(|| Manifest {
        file: rel.clone(),
        content: content.clone().into_owned(),
    });
    FileResult::Scanned { findings, manifest }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_tree_respeita_gitignore_dirs_e_binarios() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("src")).expect("mkdir");
        std::fs::create_dir_all(root.join("node_modules/x")).expect("mkdir");
        std::fs::write(root.join(".gitignore"), "ignorado.js\n").expect("w");
        std::fs::write(root.join("src/app.ts"), "eval(x)\n").expect("w");
        std::fs::write(root.join("ignorado.js"), "eval(x)\n").expect("w");
        std::fs::write(root.join("node_modules/x/i.js"), "eval(x)\n").expect("w");
        std::fs::write(root.join("bin.dat"), b"ab\0cd").expect("w");
        std::fs::write(root.join("grande.txt"), "a".repeat(2000)).expect("w");
        std::fs::write(root.join("package.json"), "{}").expect("w");

        let out = scan_tree(root, 1000, &AtomicBool::new(false));
        let files: Vec<&str> = out.findings.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(files, vec!["src/app.ts"]);
        assert_eq!(out.files_skipped, 2, "binário + grande");
        assert_eq!(out.files_scanned, 3, ".gitignore, src/app.ts, package.json");
        assert_eq!(out.manifests.len(), 1);
        assert_eq!(out.manifests[0].file, "package.json");
    }

    const SUFIXO: &str = " (em arquivo de teste/exemplo)";

    #[test]
    fn caminho_de_teste_detectado() {
        for p in [
            "test/a.js",
            "tests/unit/a.js",
            "src/__tests__/a.js",
            "spec/a.rb",
            "specs/a.rb",
            "fixtures/a.json",
            "x/__fixtures__/a.json",
            "examples/a.py",
            "example/a.py",
            "e2e/login.ts",
            "src/a.test.ts",
            "src/a.spec.js",
        ] {
            assert!(is_test_path(p), "{p}");
        }
        for p in [
            "src/app.ts",
            "testing/a.js",
            "src/latest.ts",
            "contest/a.js",
            "src/test.ts",
        ] {
            assert!(!is_test_path(p), "{p}");
        }
    }

    #[test]
    fn rebaixa_severidade_em_teste_exceto_unicode() {
        let content = "const k = \"AKIAIOSFODNN7EXAMPLE\";\nconst r = eval(x);\nel.innerHTML = y;\nconst a\u{200B}b = 1;\n";
        let f = scan_text("tests/unit/app.test.ts", content);
        let got: Vec<(&str, Severity)> = f.iter().map(|x| (x.rule_id, x.severity)).collect();
        assert_eq!(
            got,
            vec![
                ("unicode.zero-width", Severity::High),
                ("secret.known-prefix", Severity::High),
                ("code.eval", Severity::Low),
                ("code.dangerous-html", Severity::Low),
            ]
        );
        for x in &f {
            if x.rule_id.starts_with("unicode.") {
                assert!(!x.description.ends_with(SUFIXO));
            } else {
                assert!(x.description.ends_with(SUFIXO), "{}", x.description);
            }
        }
        // Fora de teste, nada muda.
        let f = scan_text("src/app.ts", content);
        assert!(f.iter().all(|x| !x.description.ends_with(SUFIXO)));
        assert!(f.iter().any(|x| x.severity == Severity::Critical));
    }
}
