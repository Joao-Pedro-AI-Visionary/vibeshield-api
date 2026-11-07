//! Varredura dos arquivos extraídos: Unicode oculto, segredos e código inseguro.
//!
//! Memória limitada: cada arquivo retém no máximo [`MAX_PER_FILE`] achados (os mais
//! graves) e o scan retém no máximo [`MAX_RETAINED`]; o resto só é CONTADO em [`Tally`],
//! para `summary` e `score` continuarem exatos. Textos (`description`/`fix_prompt`)
//! só são gerados para os retidos, na montagem do relatório.

pub mod code;
pub mod secrets;
pub mod unicode;

use std::cmp::Ordering as CmpOrdering;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
use serde::Serialize;
use utoipa::ToSchema;

use crate::redact;

pub const MAX_PER_FILE: usize = 50;
pub const MAX_RETAINED: usize = 500;
/// Manifestos guardados para checagem de dependências (o teto de pacotes é em `deps`).
pub const MAX_MANIFESTS: usize = 200;

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

    fn idx(self) -> usize {
        self as usize
    }

    fn downgraded(self) -> Self {
        match self {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium | Severity::Low => Severity::Low,
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

impl Category {
    fn idx(self) -> usize {
        self as usize
    }
}

/// Regra de detecção: id, categoria e severidade base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub id: &'static str,
    pub category: Category,
    pub severity: Severity,
}

impl Rule {
    /// `unicode.*` e `secret.known-prefix` nunca rebaixam em teste/exemplo.
    pub fn downgradable(self) -> bool {
        !(self.id.starts_with("unicode.") || self.id == rules::SECRET_KNOWN_PREFIX.id)
    }
}

pub mod rules {
    use super::{Category, Rule, Severity};

    const fn r(id: &'static str, category: Category, severity: Severity) -> Rule {
        Rule {
            id,
            category,
            severity,
        }
    }

    pub const UNICODE_BIDI: Rule = r("unicode.bidi", Category::HiddenUnicode, Severity::Critical);
    pub const UNICODE_TAG: Rule = r("unicode.tag", Category::HiddenUnicode, Severity::Critical);
    pub const UNICODE_ZERO_WIDTH: Rule = r(
        "unicode.zero-width",
        Category::HiddenUnicode,
        Severity::High,
    );
    pub const SECRET_KNOWN_PREFIX: Rule =
        r("secret.known-prefix", Category::Secret, Severity::Critical);
    pub const SECRET_HIGH_ENTROPY: Rule =
        r("secret.high-entropy", Category::Secret, Severity::High);
    pub const CODE_CORS: Rule = r(
        "code.cors-wildcard",
        Category::InsecureCode,
        Severity::Medium,
    );
    pub const CODE_EVAL: Rule = r("code.eval", Category::InsecureCode, Severity::Medium);
    pub const CODE_HTML: Rule = r("code.dangerous-html", Category::InsecureCode, Severity::Low);
    pub const DEPS_NOT_FOUND: Rule = r("deps.not-found", Category::Slopsquatting, Severity::High);
    pub const DEPS_TOO_NEW: Rule = r("deps.too-new", Category::Slopsquatting, Severity::Medium);
}

/// Dados extras de achado de dependência (para montar os textos depois).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepInfo {
    pub name: String,
    pub registry: &'static str,
    pub age_days: i64,
}

/// Achado bruto e leve (sem textos; o `id` e os textos vêm na montagem do relatório).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFinding {
    pub rule_id: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub file: String,
    pub line: u32,
    pub snippet: String,
    /// Severidade rebaixada por estar em arquivo de teste/exemplo.
    pub downgraded: bool,
    pub dep: Option<DepInfo>,
}

/// Contagem por severidade e categoria (índices na ordem dos enums).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    pub by_severity: [u64; 4],
    pub by_category: [u64; 4],
}

impl Tally {
    pub fn add(&mut self, sev: Severity, cat: Category) {
        self.by_severity[sev.idx()] += 1;
        self.by_category[cat.idx()] += 1;
    }

    pub fn merge(&mut self, other: &Tally) {
        for i in 0..4 {
            self.by_severity[i] += other.by_severity[i];
            self.by_category[i] += other.by_category[i];
        }
    }

    pub fn total(&self) -> u64 {
        self.by_severity.iter().sum()
    }

    pub fn of(findings: &[RawFinding]) -> Tally {
        let mut t = Tally::default();
        for f in findings {
            t.add(f.severity, f.category);
        }
        t
    }
}

/// Ordem do relatório: severidade, arquivo, linha (e regra, para determinismo).
pub fn cmp_findings(a: &RawFinding, b: &RawFinding) -> CmpOrdering {
    a.severity
        .cmp(&b.severity)
        .then_with(|| a.file.cmp(&b.file))
        .then_with(|| a.line.cmp(&b.line))
        .then_with(|| a.rule_id.cmp(b.rule_id))
}

/// Coletor de um arquivo: retém até 50 (os mais graves) e conta o resto.
pub struct FileSink {
    file: String,
    test_context: bool,
    retained: Vec<RawFinding>,
    overflow: Tally,
}

impl FileSink {
    pub fn new(file: &str) -> Self {
        Self {
            file: file.to_string(),
            test_context: is_test_path(file),
            retained: Vec::new(),
            overflow: Tally::default(),
        }
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn hit(&mut self, rule: Rule, line: u32, snippet: impl FnOnce() -> String) {
        self.hit_dep(rule, line, snippet, None);
    }

    /// Registra um achado; o `snippet` só é calculado se o achado for retido.
    pub fn hit_dep(
        &mut self,
        rule: Rule,
        line: u32,
        snippet: impl FnOnce() -> String,
        dep: Option<DepInfo>,
    ) {
        let downgraded = self.test_context && rule.downgradable();
        let severity = if downgraded {
            rule.severity.downgraded()
        } else {
            rule.severity
        };
        let slot = if self.retained.len() < MAX_PER_FILE {
            None
        } else {
            // índice do retido menos grave (maior Severity)
            let (idx, worst) = self
                .retained
                .iter()
                .enumerate()
                .max_by_key(|(_, f)| f.severity)
                .map(|(i, f)| (i, f.severity))
                .unwrap_or((0, Severity::Critical));
            if severity < worst {
                Some(idx)
            } else {
                self.overflow.add(severity, rule.category);
                return;
            }
        };
        let finding = RawFinding {
            rule_id: rule.id,
            category: rule.category,
            severity,
            file: self.file.clone(),
            line,
            snippet: snippet(),
            downgraded,
            dep,
        };
        match slot {
            None => self.retained.push(finding),
            Some(i) => {
                let old = std::mem::replace(&mut self.retained[i], finding);
                self.overflow.add(old.severity, old.category);
            }
        }
    }

    pub fn finish(self) -> (Vec<RawFinding>, Tally) {
        (self.retained, self.overflow)
    }
}

/// Achados retidos do scan (≤ 500 após `compact`) + contagem do que não foi retido.
#[derive(Debug, Default, Clone)]
pub struct Collected {
    pub retained: Vec<RawFinding>,
    pub overflow: Tally,
}

impl Collected {
    pub fn from_findings(retained: Vec<RawFinding>) -> Self {
        Self {
            retained,
            overflow: Tally::default(),
        }
    }

    pub fn add(&mut self, retained: Vec<RawFinding>, overflow: &Tally) {
        self.retained.extend(retained);
        self.overflow.merge(overflow);
        if self.retained.len() > 2 * MAX_RETAINED {
            self.compact();
        }
    }

    pub fn merge(mut self, other: Collected) -> Collected {
        self.add(other.retained, &other.overflow);
        self
    }

    /// Ordena e mantém só os 500 primeiros; o resto vira contagem.
    pub fn compact(&mut self) {
        self.retained.sort_by(cmp_findings);
        if self.retained.len() > MAX_RETAINED {
            for f in self.retained.drain(MAX_RETAINED..) {
                self.overflow.add(f.severity, f.category);
            }
        }
    }

    /// Contagem de TODOS os achados (retidos + só contados).
    pub fn total(&self) -> Tally {
        let mut t = Tally::of(&self.retained);
        t.merge(&self.overflow);
        t
    }
}

/// Manifesto de dependências encontrado na árvore.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub file: String,
    pub content: String,
}

#[derive(Debug, Default)]
pub struct ScanOutput {
    pub collected: Collected,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub manifests: Vec<Manifest>,
}

impl ScanOutput {
    fn merge(mut self, other: ScanOutput) -> ScanOutput {
        self.collected = self.collected.merge(other.collected);
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        for m in other.manifests {
            if self.manifests.len() < MAX_MANIFESTS {
                self.manifests.push(m);
            }
        }
        self
    }
}

const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "dist", "build", "vendor"];
const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// Aplica todas as regras de conteúdo a um arquivo de texto, no coletor do arquivo.
pub fn scan_into(content: &str, sink: &mut FileSink) {
    unicode::scan_into(content, sink);
    secrets::scan_into(content, sink);
    code::scan_into(content, sink);
}

/// Conveniência (testes): varre um arquivo e devolve os achados retidos.
pub fn scan_text(file: &str, content: &str) -> Vec<RawFinding> {
    let mut sink = FileSink::new(file);
    scan_into(content, &mut sink);
    sink.finish().0
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
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= 3
        && !parts[0].is_empty()
        && parts[1..parts.len() - 1]
            .iter()
            .any(|p| *p == "test" || *p == "spec")
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

/// Caminho com controle ou invisível é pulado (vetor de prompt injection). Se tiver
/// invisível, gera achado `unicode.*` com o caminho renderizado.
fn unsafe_path(rel: &str) -> Option<(Vec<RawFinding>, Tally)> {
    let has_control = rel.chars().any(char::is_control);
    let has_invisible = rel.chars().any(redact::is_invisible);
    if !(has_control || has_invisible) {
        return None;
    }
    let rendered = redact::render_path(rel);
    let mut sink = FileSink::new(&rendered);
    unicode::scan_path(rel, &rendered, &mut sink);
    Some(sink.finish())
}

enum FileResult {
    Scanned {
        retained: Vec<RawFinding>,
        overflow: Tally,
        manifest: Option<Manifest>,
    },
    Skipped(Option<(Vec<RawFinding>, Tally)>),
    Cancelled,
}

/// Varre a árvore em `root` em paralelo com rayon. NÃO respeita .gitignore (o tarball
/// só tem arquivos commitados). Deve ser chamada dentro de `spawn_blocking`.
pub fn scan_tree(root: &Path, max_file_bytes: u64, cancel: &AtomicBool) -> ScanOutput {
    let mut files: Vec<PathBuf> = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .parents(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
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

    let mut out = files
        .par_iter()
        .map(|path| {
            if cancel.load(Ordering::Relaxed) {
                return FileResult::Cancelled;
            }
            scan_one(root, path, max_file_bytes)
        })
        .fold(ScanOutput::default, |mut acc, r| {
            match r {
                FileResult::Scanned {
                    retained,
                    overflow,
                    manifest,
                } => {
                    acc.files_scanned += 1;
                    acc.collected.add(retained, &overflow);
                    if let Some(m) = manifest
                        && acc.manifests.len() < MAX_MANIFESTS
                    {
                        acc.manifests.push(m);
                    }
                }
                FileResult::Skipped(path_findings) => {
                    acc.files_skipped += 1;
                    if let Some((retained, overflow)) = path_findings {
                        acc.collected.add(retained, &overflow);
                    }
                }
                FileResult::Cancelled => {}
            }
            acc
        })
        .reduce(ScanOutput::default, ScanOutput::merge);
    out.collected.compact();
    out.manifests.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

fn scan_one(root: &Path, path: &Path, max_file_bytes: u64) -> FileResult {
    let Some(rel) = relative_path(root, path) else {
        return FileResult::Skipped(None);
    };
    if let Some(path_findings) = unsafe_path(&rel) {
        return FileResult::Skipped(Some(path_findings));
    }
    let too_big = std::fs::symlink_metadata(path).map_or(true, |m| m.len() > max_file_bytes);
    if too_big {
        return FileResult::Skipped(None);
    }
    let Ok(bytes) = std::fs::read(path) else {
        return FileResult::Skipped(None);
    };
    let sniff = &bytes[..bytes.len().min(BINARY_SNIFF_BYTES)];
    if sniff.contains(&0) {
        return FileResult::Skipped(None);
    }
    let content = String::from_utf8_lossy(&bytes);
    let mut sink = FileSink::new(&rel);
    scan_into(&content, &mut sink);
    let (retained, overflow) = sink.finish();
    let manifest = is_manifest(&rel).then(|| Manifest {
        file: rel.clone(),
        content: content.into_owned(),
    });
    FileResult::Scanned {
        retained,
        overflow,
        manifest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_tree_ignora_dirs_e_binarios_mas_nao_o_gitignore() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("src")).expect("mkdir");
        std::fs::create_dir_all(root.join("node_modules/x")).expect("mkdir");
        std::fs::write(root.join(".gitignore"), "*\n").expect("w");
        std::fs::write(root.join("src/app.ts"), "eval(x)\n").expect("w");
        std::fs::write(root.join(".env"), "K=AKIAIOSFODNN7EXAMPLE\n").expect("w");
        std::fs::write(root.join("node_modules/x/i.js"), "eval(x)\n").expect("w");
        std::fs::write(root.join("bin.dat"), b"ab\0cd").expect("w");
        std::fs::write(root.join("grande.txt"), "a".repeat(2000)).expect("w");
        std::fs::write(root.join("package.json"), "{}").expect("w");

        let out = scan_tree(root, 1000, &AtomicBool::new(false));
        let mut files: Vec<&str> = out
            .collected
            .retained
            .iter()
            .map(|f| f.file.as_str())
            .collect();
        files.sort_unstable();
        assert_eq!(files, vec![".env", "src/app.ts"]);
        assert_eq!(out.files_skipped, 2, "binário + grande");
        assert_eq!(
            out.files_scanned, 4,
            ".gitignore, .env, src/app.ts, package.json"
        );
        assert_eq!(out.manifests.len(), 1);
        assert_eq!(out.manifests[0].file, "package.json");
    }

    #[test]
    fn teto_de_50_por_arquivo_conta_o_resto() {
        let mut sink = FileSink::new("a.js");
        scan_into(&"eval(\n".repeat(10_000), &mut sink);
        let (retained, overflow) = sink.finish();
        assert_eq!(retained.len(), 50);
        assert_eq!(overflow.total(), 9_950);
        let mut c = Collected::default();
        c.add(retained, &overflow);
        assert_eq!(c.total().by_severity[Severity::Medium as usize], 10_000);
    }

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
    fn rebaixa_severidade_em_teste_exceto_unicode_e_known_prefix() {
        let content = "const k = \"AKIAIOSFODNN7EXAMPLE\";\nconst r = eval(x);\nel.innerHTML = y;\nconst a\u{200B}b = 1;\n";
        let f = scan_text("tests/unit/app.test.ts", content);
        let got: Vec<(&str, Severity, bool)> = f
            .iter()
            .map(|x| (x.rule_id, x.severity, x.downgraded))
            .collect();
        assert_eq!(
            got,
            vec![
                ("unicode.zero-width", Severity::High, false),
                ("secret.known-prefix", Severity::Critical, false),
                ("code.eval", Severity::Low, true),
                ("code.dangerous-html", Severity::Low, true),
            ]
        );
        // Fora de teste, nada muda.
        let f = scan_text("src/app.ts", content);
        assert!(f.iter().all(|x| !x.downgraded));
    }

    #[test]
    fn caminho_invisivel_gera_achado_renderizado() {
        let r = unsafe_path("src/a\u{200B}b.js").expect("inseguro");
        assert_eq!(r.0.len(), 1);
        assert_eq!(r.0[0].file, "src/a<U+200B>b.js");
        assert_eq!(r.0[0].rule_id, "unicode.zero-width");
        let r = unsafe_path("src/ok\n\nIGNORE.js").expect("inseguro");
        assert!(r.0.is_empty());
        assert!(unsafe_path("src/ok.js").is_none());
    }
}
