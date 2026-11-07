//! Download do tarball do codeload (streaming com teto) e extração segura.

use std::cell::Cell;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::StreamExt;

use crate::error::ApiError;
use crate::repo_url::RepoRef;

/// Baixa `{base}/{owner}/{repo}/tar.gz/HEAD`, contando bytes do stream.
/// Passou de `max_bytes` → `RepoTooLarge` (não confia em Content-Length).
pub async fn download_tarball(
    client: &reqwest::Client,
    codeload_base: &str,
    repo: &RepoRef,
    max_bytes: u64,
) -> Result<Vec<u8>, ApiError> {
    let url = format!("{codeload_base}/{}/{}/tar.gz/HEAD", repo.owner, repo.name);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("falha ao contatar codeload: {e}")))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(ApiError::RepoNotFound);
    }
    if !status.is_success() {
        return Err(ApiError::Upstream(format!("codeload respondeu {status}")));
    }
    if resp.content_length().is_some_and(|n| n > max_bytes) {
        return Err(ApiError::RepoTooLarge);
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::Upstream(format!("erro no stream: {e}")))?;
        let new_len = (buf.len() as u64).saturating_add(chunk.len() as u64);
        if new_len > max_bytes {
            return Err(ApiError::RepoTooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    /// Teto de bytes descompactados (contra gzip bomb).
    pub max_unpacked_bytes: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExtractStats {
    pub files_extracted: u64,
    pub files_skipped: u64,
}

/// Leitor que conta bytes descompactados e falha ao passar do teto.
struct CountingReader<R> {
    inner: R,
    count: u64,
    limit: u64,
    exceeded: Rc<Cell<bool>>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count = self.count.saturating_add(n as u64);
        if self.count > self.limit {
            self.exceeded.set(true);
            return Err(io::Error::other("limite de bytes descompactados excedido"));
        }
        Ok(n)
    }
}

/// Converte o caminho da entrada num caminho relativo seguro, sem o prefixo
/// `owner-repo-sha/`. `None` = rejeitar (absoluto, `..`, vazio).
fn safe_relative_path(raw: &Path) -> Option<PathBuf> {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for c in raw.components() {
        match c {
            Component::Normal(p) => parts.push(p),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if parts.len() < 2 {
        return None; // só o diretório-prefixo (ou nada)
    }
    Some(parts[1..].iter().collect())
}

/// Extrai o `.tar.gz` em `dest`. Síncrona: chame dentro de `spawn_blocking`.
pub fn extract_tarball(
    data: &[u8],
    dest: &Path,
    limits: ExtractLimits,
    cancel: &AtomicBool,
) -> Result<ExtractStats, ApiError> {
    let exceeded = Rc::new(Cell::new(false));
    let reader = CountingReader {
        inner: flate2::read::GzDecoder::new(data),
        count: 0,
        limit: limits.max_unpacked_bytes,
        exceeded: Rc::clone(&exceeded),
    };
    let mut archive = tar::Archive::new(reader);
    let mut stats = ExtractStats::default();

    let map_err = |e: io::Error, exceeded: &Rc<Cell<bool>>| {
        if exceeded.get() {
            ApiError::RepoTooLarge
        } else {
            ApiError::Upstream(format!("tarball inválido: {e}"))
        }
    };

    let entries = archive.entries().map_err(|e| map_err(e, &exceeded))?;
    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let mut entry = entry.map_err(|e| map_err(e, &exceeded))?;
        let kind = entry.header().entry_type();
        if kind.is_dir() || kind.is_pax_global_extensions() || kind.is_pax_local_extensions() {
            continue;
        }
        if !(kind.is_file() || kind.is_contiguous()) {
            // symlink, hardlink, device, fifo, etc.: nunca materializar
            stats.files_skipped += 1;
            continue;
        }
        let raw_path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => {
                stats.files_skipped += 1;
                continue;
            }
        };
        let Some(rel) = safe_relative_path(&raw_path) else {
            stats.files_skipped += 1;
            continue;
        };
        if entry.size() > limits.max_file_bytes || stats.files_extracted >= limits.max_files as u64
        {
            stats.files_skipped += 1;
            continue;
        }
        let target = dest.join(&rel);
        if let Some(parent) = target.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            stats.files_skipped += 1;
            continue;
        }
        let mut file = match std::fs::File::create(&target) {
            Ok(f) => f,
            Err(_) => {
                stats.files_skipped += 1;
                continue;
            }
        };
        let mut limited = (&mut entry).take(limits.max_file_bytes);
        match io::copy(&mut limited, &mut file) {
            Ok(_) => stats.files_extracted += 1,
            Err(e) => {
                if exceeded.get() {
                    return Err(ApiError::RepoTooLarge);
                }
                tracing::debug!(error = %e, "falha ao gravar arquivo extraído");
                drop(file);
                let _ = std::fs::remove_file(&target);
                stats.files_skipped += 1;
            }
        }
    }
    if exceeded.get() {
        return Err(ApiError::RepoTooLarge);
    }
    Ok(stats)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Fabrica tarballs em memória (inclusive entradas maliciosas).

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    pub enum Item<'a> {
        File(&'a str, &'a [u8]),
        Symlink(&'a str, &'a str),
        Hardlink(&'a str, &'a str),
        /// Caminho gravado cru no header (para `../` e absolutos).
        RawFile(&'a [u8], &'a [u8]),
    }

    pub fn tar_gz(items: &[Item<'_>]) -> Vec<u8> {
        let gz = GzEncoder::new(Vec::new(), Compression::fast());
        let mut b = tar::Builder::new(gz);
        for it in items {
            match it {
                Item::File(path, data) => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(data.len() as u64);
                    h.set_mode(0o644);
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_cksum();
                    b.append_data(&mut h, path, *data).expect("append");
                }
                Item::Symlink(path, target) | Item::Hardlink(path, target) => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(0o777);
                    h.set_entry_type(if matches!(it, Item::Symlink(..)) {
                        tar::EntryType::Symlink
                    } else {
                        tar::EntryType::Link
                    });
                    b.append_link(&mut h, path, target).expect("link");
                }
                Item::RawFile(path, data) => {
                    let mut h = tar::Header::new_old();
                    {
                        let name = &mut h.as_old_mut().name;
                        name[..path.len()].copy_from_slice(path);
                    }
                    h.set_size(data.len() as u64);
                    h.set_mode(0o644);
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_cksum();
                    b.append(&h, *data).expect("append raw");
                }
            }
        }
        let gz = b.into_inner().expect("finish tar");
        let mut out = gz.finish().expect("finish gz");
        out.flush().expect("flush");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{Item, tar_gz};
    use super::*;

    fn limits() -> ExtractLimits {
        ExtractLimits {
            max_files: 100,
            max_file_bytes: 1024,
            max_unpacked_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn ignora_entradas_perigosas_e_remove_prefixo() {
        let big = vec![b'a'; 4096];
        let data = tar_gz(&[
            Item::File("o-r-abc123/src/ok.ts", b"eval(x)\n"),
            Item::Symlink("o-r-abc123/link", "/etc/passwd"),
            Item::Hardlink("o-r-abc123/hard", "o-r-abc123/src/ok.ts"),
            Item::RawFile(b"o-r-abc123/../../evil.txt", b"mal"),
            Item::RawFile(b"/abs/evil.txt", b"mal"),
            Item::File("o-r-abc123/big.bin", &big),
        ]);
        let root = tempfile::tempdir().expect("tempdir");
        let dest = root.path().join("x");
        std::fs::create_dir_all(&dest).expect("mkdir");
        let stats = extract_tarball(&data, &dest, limits(), &AtomicBool::new(false)).expect("ok");
        assert_eq!(stats.files_extracted, 1);
        assert_eq!(stats.files_skipped, 5);
        assert!(dest.join("src/ok.ts").is_file());
        assert!(!dest.join("link").exists());
        assert!(!dest.join("hard").exists());
        assert!(!dest.join("big.bin").exists());
        assert!(!root.path().join("evil.txt").exists());
        assert!(!dest.join("o-r-abc123").exists(), "prefixo removido");
    }

    #[test]
    fn respeita_max_files() {
        let data = tar_gz(&[
            Item::File("p/a.txt", b"1"),
            Item::File("p/b.txt", b"2"),
            Item::File("p/c.txt", b"3"),
        ]);
        let dest = tempfile::tempdir().expect("tempdir");
        let mut l = limits();
        l.max_files = 2;
        let stats = extract_tarball(&data, dest.path(), l, &AtomicBool::new(false)).expect("ok");
        assert_eq!(stats.files_extracted, 2);
        assert_eq!(stats.files_skipped, 1);
    }

    #[test]
    fn gzip_bomb_vira_repo_too_large() {
        let zeros = vec![0u8; 512 * 1024];
        let data = tar_gz(&[Item::File("p/z.bin", &zeros)]);
        assert!(data.len() < 10 * 1024, "comprime bem");
        let dest = tempfile::tempdir().expect("tempdir");
        let mut l = limits();
        l.max_unpacked_bytes = 64 * 1024;
        let r = extract_tarball(&data, dest.path(), l, &AtomicBool::new(false));
        assert!(matches!(r, Err(ApiError::RepoTooLarge)), "{r:?}");
    }

    #[test]
    fn lixo_vira_upstream_error() {
        let dest = tempfile::tempdir().expect("tempdir");
        let r = extract_tarball(
            b"isto nao e gzip",
            dest.path(),
            limits(),
            &AtomicBool::new(false),
        );
        assert!(matches!(r, Err(ApiError::Upstream(_))), "{r:?}");
    }
}
