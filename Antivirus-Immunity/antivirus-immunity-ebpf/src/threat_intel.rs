//! Bounded local SHA-256 + CTPH blacklist for executable threat intelligence.

use anyhow::{Context, Result, bail};
use fuzzyhash::FuzzyHash;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
#[cfg(not(target_os = "linux"))]
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

const MAX_DATABASE_ENTRIES: usize = 50_000;
const MAX_SIGNATURE_LEN: usize = 148;
const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_CACHE_ENTRIES: usize = 2048;
const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatMatch {
    pub family: String,
    pub method: MatchMethod,
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchMethod {
    Sha256,
    Ctph(u32),
}

pub struct ThreatIntel {
    entries: Vec<CompiledEntry>,
    exact: HashMap<String, usize>,
    by_block_size: HashMap<u32, Vec<usize>>,
    threshold: u32,
    max_file_bytes: u64,
    cache: HashMap<FileIdentity, Option<ThreatMatch>>,
    cache_order: VecDeque<FileIdentity>,
    cache_capacity: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Database {
    version: u32,
    #[serde(default = "default_threshold")]
    threshold: u32,
    #[serde(default = "default_max_file_bytes")]
    max_file_bytes: u64,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    family: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    ssdeep: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug)]
struct CompiledEntry {
    family: String,
    ssdeep: Option<String>,
    block_size: Option<u32>,
    source: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(not(target_os = "linux"))]
    path: PathBuf,
    size: u64,
    modified_ns: u128,
    #[cfg(target_os = "linux")]
    changed_ns: i128,
    #[cfg(target_os = "linux")]
    device: u64,
    #[cfg(target_os = "linux")]
    inode: u64,
}

fn default_threshold() -> u32 {
    80
}

fn default_max_file_bytes() -> u64 {
    DEFAULT_MAX_FILE_BYTES
}

impl ThreatIntel {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)
            .with_context(|| format!("open threat-intelligence database {}", path.display()))?
            .take(MAX_DATABASE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read threat-intelligence database {}", path.display()))?;
        if bytes.len() as u64 > MAX_DATABASE_BYTES {
            bail!("threat-intelligence database exceeds {MAX_DATABASE_BYTES} bytes");
        }
        let database: Database = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse threat-intelligence database {}", path.display()))?;
        if database.version != 1 {
            bail!(
                "unsupported threat-intelligence database version {}",
                database.version
            );
        }
        if !(50..=100).contains(&database.threshold) {
            bail!("fuzzy threshold must be between 50 and 100");
        }
        if database.max_file_bytes == 0 || database.max_file_bytes > 1024 * 1024 * 1024 {
            bail!("max_file_bytes must be between 1 and 1 GiB");
        }
        if database.entries.len() > MAX_DATABASE_ENTRIES {
            bail!("threat-intelligence database exceeds {MAX_DATABASE_ENTRIES} entries");
        }

        let mut entries = Vec::with_capacity(database.entries.len());
        let mut exact = HashMap::new();
        let mut by_block_size: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut fuzzy_signatures = HashSet::new();
        for entry in database.entries {
            if entry.family.trim().is_empty()
                || entry.family.len() > 128
                || entry.family.chars().any(char::is_control)
            {
                bail!("threat family names must contain 1..128 bytes");
            }
            if entry.sha256.is_none() && entry.ssdeep.is_none() {
                bail!("threat entry {} has no signature", entry.family);
            }
            let sha256 = entry.sha256.map(|hash| hash.to_ascii_lowercase());
            if let Some(hash) = &sha256
                && (hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                bail!("invalid SHA-256 for threat family {}", entry.family);
            }
            if let Some(signature) = &entry.ssdeep
                && signature.len() > MAX_SIGNATURE_LEN
            {
                bail!(
                    "CTPH signature is too long for threat family {}",
                    entry.family
                );
            }
            if entry
                .source
                .as_ref()
                .is_some_and(|source| source.len() > 512 || source.chars().any(char::is_control))
            {
                bail!("source is too long for threat family {}", entry.family);
            }
            let block_size = entry
                .ssdeep
                .as_deref()
                .map(signature_block_size)
                .transpose()
                .with_context(|| format!("invalid CTPH signature for {}", entry.family))?;
            if let Some(signature) = &entry.ssdeep {
                FuzzyHash::compare(signature, signature)
                    .with_context(|| format!("invalid ssdeep signature for {}", entry.family))?;
                if !fuzzy_signatures.insert(signature.clone()) {
                    bail!(
                        "duplicate ssdeep signature for threat family {}",
                        entry.family
                    );
                }
            }
            let index = entries.len();
            if let Some(hash) = sha256
                && exact.insert(hash, index).is_some()
            {
                bail!(
                    "duplicate SHA-256 signature for threat family {}",
                    entry.family
                );
            }
            if let Some(block_size) = block_size {
                by_block_size.entry(block_size).or_default().push(index);
            }
            entries.push(CompiledEntry {
                family: entry.family,
                ssdeep: entry.ssdeep,
                block_size,
                source: entry.source,
            });
        }

        Ok(Self {
            entries,
            exact,
            by_block_size,
            threshold: database.threshold,
            max_file_bytes: database.max_file_bytes,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            cache_capacity: DEFAULT_CACHE_ENTRIES,
        })
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn scan(&mut self, path: &Path) -> Result<Option<ThreatMatch>> {
        if self.entries.is_empty() {
            return Ok(None);
        }
        let file =
            File::open(path).with_context(|| format!("open executable {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("stat executable {}", path.display()))?;
        if !metadata.is_file() || metadata.len() > self.max_file_bytes {
            return Ok(None);
        }
        let identity = file_identity(path, &metadata);
        if let Some(cached) = self.cache.get(&identity) {
            return Ok(cached.clone());
        }

        let wants_exact = !self.exact.is_empty();
        let wants_fuzzy = !self.by_block_size.is_empty();
        let mut reader = ScanReader::new(file.take(self.max_file_bytes + 1), wants_exact);
        let fuzzy_signature = if wants_fuzzy {
            Some(
                FuzzyHash::read(&mut reader)
                    .context("stream executable into ssdeep generator")?
                    .to_string(),
            )
        } else {
            io::copy(&mut reader, &mut io::sink()).context("stream executable into SHA-256")?;
            None
        };
        if reader.bytes > self.max_file_bytes {
            bail!("executable changed size while being scanned");
        }
        let after = reader
            .inner
            .get_ref()
            .metadata()
            .with_context(|| format!("restat executable {}", path.display()))?;
        if file_identity(path, &after) != identity {
            bail!("executable changed identity while being scanned");
        }

        let exact_match = if let Some(digest) = reader.digest.take() {
            let sha256 = hex::encode(digest.finalize());
            self.exact.get(&sha256).copied()
        } else {
            None
        };
        let result = if let Some(index) = exact_match {
            Some(self.match_for(index, MatchMethod::Sha256))
        } else if reader.bytes == 0 {
            None
        } else {
            fuzzy_signature
                .as_deref()
                .and_then(|signature| self.fuzzy_match(signature))
        };
        self.cache_insert(identity, result.clone());
        Ok(result)
    }

    fn fuzzy_match(&self, candidate: &str) -> Option<ThreatMatch> {
        let block_size = signature_block_size(candidate).ok()?;
        let mut candidates = Vec::new();
        for size in [block_size / 2, block_size, block_size.saturating_mul(2)] {
            if let Some(indices) = self.by_block_size.get(&size) {
                candidates.extend(indices.iter().copied());
            }
        }
        candidates.sort_unstable();
        candidates.dedup();

        let mut best: Option<(usize, u32)> = None;
        for index in candidates {
            let entry = &self.entries[index];
            let Some(signature) = &entry.ssdeep else {
                continue;
            };
            let score = FuzzyHash::compare(candidate, signature).unwrap_or(0);
            if score >= self.threshold && best.is_none_or(|(_, previous)| score > previous) {
                best = Some((index, score));
            }
        }
        best.map(|(index, score)| self.match_for(index, MatchMethod::Ctph(score)))
    }

    fn match_for(&self, index: usize, method: MatchMethod) -> ThreatMatch {
        let entry = &self.entries[index];
        debug_assert!(entry.block_size.is_some() || matches!(method, MatchMethod::Sha256));
        ThreatMatch {
            family: entry.family.clone(),
            method,
            source: entry.source.clone(),
        }
    }

    fn cache_insert(&mut self, identity: FileIdentity, result: Option<ThreatMatch>) {
        if self.cache.len() >= self.cache_capacity
            && let Some(oldest) = self.cache_order.pop_front()
        {
            self.cache.remove(&oldest);
        }
        self.cache_order.push_back(identity.clone());
        self.cache.insert(identity, result);
    }
}

struct ScanReader<R> {
    inner: R,
    digest: Option<Sha256>,
    bytes: u64,
}

impl<R> ScanReader<R> {
    fn new(inner: R, sha256: bool) -> Self {
        Self {
            inner,
            digest: sha256.then(Sha256::new),
            bytes: 0,
        }
    }
}

impl<R: Read> Read for ScanReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes = self.bytes.saturating_add(count as u64);
        if let Some(digest) = &mut self.digest {
            digest.update(&buffer[..count]);
        }
        Ok(count)
    }
}

fn file_identity(_path: &Path, metadata: &fs::Metadata) -> FileIdentity {
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    let modified_ns = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    FileIdentity {
        #[cfg(not(target_os = "linux"))]
        path: _path.to_path_buf(),
        size: metadata.len(),
        modified_ns,
        #[cfg(target_os = "linux")]
        changed_ns: i128::from(metadata.ctime()) * 1_000_000_000
            + i128::from(metadata.ctime_nsec()),
        #[cfg(target_os = "linux")]
        device: metadata.dev(),
        #[cfg(target_os = "linux")]
        inode: metadata.ino(),
    }
}

fn signature_block_size(signature: &str) -> Result<u32> {
    let mut parts = signature.split(':');
    let block_size = parts
        .next()
        .context("missing CTPH block size")?
        .parse::<u32>()
        .context("invalid CTPH block size")?;
    let first = parts.next().context("missing first CTPH band")?;
    let second = parts.next().context("missing second CTPH band")?;
    if block_size < 3 || first.is_empty() || second.is_empty() || parts.next().is_some() {
        bail!("malformed CTPH signature");
    }
    Ok(block_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn identical_ctph_scores_one_hundred() {
        let signature =
            FuzzyHash::new(b"bounded harmless test sample bounded harmless test sample".as_slice())
                .to_string();
        assert_eq!(FuzzyHash::compare(&signature, &signature).unwrap(), 100);
    }

    #[test]
    fn ssdeep_generation_matches_reference_vector() {
        assert_eq!(FuzzyHash::new(b"Hello there!").to_string(), "3:aNRn:aNRn");
    }

    #[test]
    fn exact_database_match_and_cache_work() {
        let directory = std::env::temp_dir().join(format!("immunity-intel-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let sample = directory.join("sample.bin");
        File::create(&sample)
            .unwrap()
            .write_all(b"harmless fixture")
            .unwrap();
        let hash = hex::encode(Sha256::digest(b"harmless fixture"));
        let database_path = directory.join("intel.json");
        fs::write(
            &database_path,
            format!(r#"{{"version":1,"entries":[{{"family":"Test.Fixture","sha256":"{hash}"}}]}}"#),
        )
        .unwrap();
        let mut intel = ThreatIntel::load(&database_path).unwrap();
        assert_eq!(intel.entry_count(), 1);
        assert_eq!(
            intel.scan(&sample).unwrap().unwrap().method,
            MatchMethod::Sha256
        );
        assert!(intel.scan(&sample).unwrap().is_some());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn fuzzy_database_match_uses_streaming_standard_signature() {
        let directory = std::env::temp_dir().join(format!("immunity-fuzzy-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let data = b"streamed harmless fuzzy fixture ".repeat(128);
        let sample = directory.join("sample.bin");
        fs::write(&sample, &data).unwrap();
        let signature = FuzzyHash::new(&data).to_string();
        let database_path = directory.join("intel.json");
        fs::write(
            &database_path,
            format!(
                r#"{{"version":1,"entries":[{{"family":"Test.Fuzzy","ssdeep":"{signature}"}}]}}"#
            ),
        )
        .unwrap();
        let mut intel = ThreatIntel::load(&database_path).unwrap();
        assert_eq!(
            intel.scan(&sample).unwrap().unwrap().method,
            MatchMethod::Ctph(100)
        );
        let _ = fs::remove_dir_all(directory);
    }
}
