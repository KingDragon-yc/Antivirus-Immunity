//! Fuzzy Hash Engine — CTPH (Ssdeep) + Imphash
//!
//! Two-pronged fuzzy hashing for malware variant detection,
//! implementing both context-triggered piecewise hashing and
//! import table structural hashing in pure Rust.
//!
//! ## CTPH (Context Triggered Piecewise Hashing)
//!
//! Based on the ssdeep/spamsum algorithm. A rolling hash determines
//! chunk boundaries; each chunk is hashed with FNV-1a; the low 6 bits
//! are Base64-encoded. Similarity is computed via edit distance.
//!
//! ## Imphash (Import Address Table Hash)
//!
//! PE files: parsed via `pelite`, extracts DLL name + function name
//! from the import directory, sorts, deduplicates, and SHA256-hashes.
//! ELF files: parsed via `goblin`, extracts UNDEF dynamic symbols
//! from .dynsym, sorts, and hashes identically.
//!
//! Imphash is stable across code obfuscation — malware must import the
//! same APIs to perform the same behaviors (VirtualAlloc, socket, etc.).

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

// ─── Base64 alphabet (ssdeep-compatible) ───

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ─── Public types ───

#[derive(Debug, Clone)]
pub struct FuzzySignature {
    pub sha256: String,
    pub ssdeep: Option<String>,
    pub imphash: Option<String>,
    pub file_type: FileType,
    /// File size in bytes; not currently consumed by the matching pipeline
    /// but kept on the signature for future heuristics and for callers that
    /// log it.
    #[allow(dead_code)]
    pub file_size: u64,
}

#[derive(Debug, Clone, PartialEq)]
// PE / ELF are conventional file-format acronyms; keep them uppercase
// rather than the clippy-preferred `Pe` / `Elf`.
#[allow(clippy::upper_case_acronyms)]
pub enum FileType {
    PE,
    ELF,
    Unknown,
}

impl FileType {
    pub fn as_str(&self) -> &str {
        match self {
            FileType::PE => "PE",
            FileType::ELF => "ELF",
            FileType::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatchScore {
    /// Whether the candidate matched a known signature by exact SHA256.
    /// Currently implied by `method == ExactSha256`; the flag is kept for
    /// callers that want a quick boolean without matching on `method`.
    #[allow(dead_code)]
    pub sha256_match: bool,
    pub ssdeep_similarity: Option<u32>, // 0–100, ≥80 → same family
    pub imphash_match: bool,
    pub method: MatchMethod,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MatchMethod {
    ExactSha256,
    Ssdeep(u32),
    Imphash,
    None,
}

// ─── Main engine ───

pub struct FuzzyHasher;

impl FuzzyHasher {
    /// Compute all available fuzzy hashes for a file.
    /// Returns None if the file cannot be read (e.g. access denied for running processes).
    pub fn compute_all(path: &str) -> Option<FuzzySignature> {
        let metadata = fs::metadata(path).ok()?;
        let file_size = metadata.len();

        // Skip files > 500MB to avoid OOM / excessive CPU
        if file_size > 500 * 1024 * 1024 {
            return None;
        }

        let sha256 = Self::compute_sha256(path).ok()?;
        let file_type = Self::detect_file_type(path);
        let ssdeep = Self::compute_ssdeep(path);
        let imphash = Self::compute_imphash(path, &file_type);

        Some(FuzzySignature {
            sha256,
            ssdeep,
            imphash,
            file_type,
            file_size,
        })
    }

    /// Compare a candidate signature against a database of known signatures.
    /// Returns the best match (if any) with the match method and score.
    pub fn fuzzy_match(candidate: &FuzzySignature, database: &[FuzzySignature]) -> MatchScore {
        let mut best = MatchScore {
            sha256_match: false,
            ssdeep_similarity: None,
            imphash_match: false,
            method: MatchMethod::None,
        };

        for known in database {
            // ── Exact SHA256 (instant match) ──
            if candidate.sha256 == known.sha256 {
                return MatchScore {
                    sha256_match: true,
                    ssdeep_similarity: None,
                    imphash_match: false,
                    method: MatchMethod::ExactSha256,
                };
            }

            // ── Ssdeep similarity ──
            if let (Some(c_ss), Some(k_ss)) = (&candidate.ssdeep, &known.ssdeep) {
                let sim = ssdeep_similarity(c_ss, k_ss);
                if sim > best.ssdeep_similarity.unwrap_or(0) {
                    best.ssdeep_similarity = Some(sim);
                    best.method = MatchMethod::Ssdeep(sim);
                }
            }

            // ── Imphash match ──
            if let (Some(c_im), Some(k_im)) = (&candidate.imphash, &known.imphash)
                && c_im == k_im
            {
                best.imphash_match = true;
                if best.method != MatchMethod::Ssdeep(0) {
                    best.method = MatchMethod::Imphash;
                }
            }
        }

        // If ssdeep similarity is below threshold, don't report it as a match
        if let MatchMethod::Ssdeep(sim) = best.method
            && sim < 80
        {
            best.method = if best.imphash_match {
                MatchMethod::Imphash
            } else {
                MatchMethod::None
            };
        }

        best
    }

    // ─── Private helpers ───

    fn compute_sha256(path: &str) -> Result<String> {
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn detect_file_type(path: &str) -> FileType {
        let mut file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return FileType::Unknown,
        };
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_err() {
            return FileType::Unknown;
        }
        match &magic {
            b"MZ\x90\x00" | b"MZ\x00\x00" => FileType::PE,
            [0x7f, b'E', b'L', b'F'] => FileType::ELF,
            _ => FileType::Unknown,
        }
    }

    // ── CTPH (Ssdeep) ──

    fn compute_ssdeep(path: &str) -> Option<String> {
        let data = fs::read(path).ok()?;
        if data.is_empty() || data.len() > 500 * 1024 * 1024 {
            return None;
        }
        let bs = determine_block_size(data.len());
        let sig1 = hash_with_block_size(&data, bs);
        if sig1.len() < 5 {
            return None;
        }
        let sig2 = hash_with_block_size(&data, bs * 2);
        Some(format!("{}:{}:{}", bs, sig1, sig2))
    }

    // ── Imphash ──

    fn compute_imphash(path: &str, file_type: &FileType) -> Option<String> {
        match file_type {
            FileType::PE => compute_pe_imphash(path),
            FileType::ELF => compute_elf_imphash(path),
            FileType::Unknown => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// CTPH (Ssdeep) implementation
// ═══════════════════════════════════════════════════════════════

/// Determine block size based on file length.
/// Target: produce roughly 64 chunks.
fn determine_block_size(len: usize) -> u32 {
    if len == 0 {
        return 3;
    }
    let mut bs: u32 = 3;
    while (bs as usize) * 64 < len && bs < 16384 {
        bs *= 2;
    }
    bs.max(3)
}

/// Hash a byte slice with a given block size using the CTPH algorithm.
fn hash_with_block_size(data: &[u8], block_size: u32) -> String {
    if block_size < 3 || data.is_empty() {
        return String::new();
    }

    let mut result = String::with_capacity(data.len() / block_size as usize + 8);
    let mut rolling: u64 = 0;
    let mut chunk_hash: u64 = FNV_INIT;

    for &byte in data {
        // Rolling hash: rotate-left-1 + byte
        rolling = rolling.rotate_left(1).wrapping_add(byte as u64);

        // FNV-1a per-chunk hash
        chunk_hash ^= byte as u64;
        chunk_hash = chunk_hash.wrapping_mul(FNV_PRIME);

        // Trigger: rolling % bs == bs - 1
        if rolling % block_size as u64 == (block_size - 1) as u64 {
            result.push(b64_encode(chunk_hash & 0x3F));
            chunk_hash = FNV_INIT;
        }
    }

    // Emit final chunk
    let final_idx = ((chunk_hash ^ (chunk_hash >> 32)) & 0x3F) as usize;
    result.push(B64[final_idx] as char);

    result
}

const FNV_INIT: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn b64_encode(bits: u64) -> char {
    B64[(bits & 0x3F) as usize] as char
}

// ═══════════════════════════════════════════════════════════════
// Ssdeep similarity (Levenshtein edit distance)
// ═══════════════════════════════════════════════════════════════

/// Compute similarity percentage between two ssdeep signatures.
/// Returns 0–100 where ≥ 80 indicates same file or close variant.
pub fn ssdeep_similarity(a: &str, b: &str) -> u32 {
    // Signatures are "bs:sig@bs:sig@2bs" as produced by `compute_ssdeep`.
    let a_parts: Vec<&str> = a.split(':').collect();
    let b_parts: Vec<&str> = b.split(':').collect();

    let a_bs: u64 = a_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let b_bs: u64 = b_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let a_sig1 = a_parts.get(1).copied().unwrap_or("");
    let a_sig2 = a_parts.get(2).copied().unwrap_or("");
    let b_sig1 = b_parts.get(1).copied().unwrap_or("");
    let b_sig2 = b_parts.get(2).copied().unwrap_or("");

    // A block size of 0 means the prefix was missing/unparseable — not comparable.
    if a_bs == 0 || b_bs == 0 {
        return 0;
    }

    // Only signature bands computed at the SAME effective block size are
    // comparable. Comparing across block sizes (as the previous all-pairs
    // edit distance did) is meaningless and yields false "same family" hits.
    // ssdeep keeps two bands (bs and 2*bs) precisely so that files whose target
    // block size differs by one step can still be compared.
    let mut best = 0;
    if a_bs == b_bs {
        best = best.max(compare_signatures(a_sig1, b_sig1));
        best = best.max(compare_signatures(a_sig2, b_sig2));
    }
    if a_bs == b_bs.saturating_mul(2) {
        best = best.max(compare_signatures(a_sig1, b_sig2));
    }
    if a_bs.saturating_mul(2) == b_bs {
        best = best.max(compare_signatures(a_sig2, b_sig1));
    }
    best
}

fn compare_signatures(a: &str, b: &str) -> u32 {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let dist = levenshtein(a, b);
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return 100;
    }
    let score = ((max_len - dist) as f64 / max_len as f64 * 100.0) as u32;
    score.min(100)
}

/// Standard Levenshtein distance (insert/delete/substitute cost = 1).
fn levenshtein(s: &str, t: &str) -> usize {
    let s_chars: Vec<char> = s.chars().collect();
    let t_chars: Vec<char> = t.chars().collect();
    let n = s_chars.len();
    let m = t_chars.len();

    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }

    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];

    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if s_chars[i - 1] == t_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

// ═══════════════════════════════════════════════════════════════
// Imphash — PE via pelite
// ═══════════════════════════════════════════════════════════════

fn compute_pe_imphash(path: &str) -> Option<String> {
    use pelite::FileMap;
    use std::path::Path;

    let map = FileMap::open(Path::new(path)).ok()?;
    let data = map.as_ref();
    let mut entries: Vec<String> = Vec::new();

    // Try PE64 first, then PE32. Code paths duplicated because
    // pe64::Pe and pe32::Pe are distinct traits.
    {
        use pelite::pe64::Pe;
        if let Ok(file) = pelite::pe64::PeFile::from_bytes(data)
            && let Ok(imports) = file.imports()
        {
            for desc in imports {
                let dll_name = desc.dll_name().ok()?;
                let dll = dll_name
                    .to_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .trim_end_matches(".dll")
                    .to_string();
                if let Ok(int_iter) = desc.int() {
                    for import in int_iter.flatten() {
                        if let pelite::pe64::imports::Import::ByName { name, .. } = import {
                            entries.push(format!("{}.{}", dll, name.to_str().unwrap_or("")));
                        }
                    }
                }
            }
        }
    }

    if entries.is_empty() {
        use pelite::pe32::Pe;
        if let Ok(file) = pelite::pe32::PeFile::from_bytes(data)
            && let Ok(imports) = file.imports()
        {
            for desc in imports {
                let dll_name = desc.dll_name().ok()?;
                let dll = dll_name
                    .to_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .trim_end_matches(".dll")
                    .to_string();
                if let Ok(int_iter) = desc.int() {
                    for import in int_iter.flatten() {
                        if let pelite::pe32::imports::Import::ByName { name, .. } = import {
                            entries.push(format!("{}.{}", dll, name.to_str().unwrap_or("")));
                        }
                    }
                }
            }
        }
    }

    if entries.is_empty() {
        return None;
    }
    entries.sort();
    entries.dedup();
    let mut hasher = Sha256::new();
    hasher.update(entries.join(",").as_bytes());
    Some(hex::encode(hasher.finalize()))
}

// ═══════════════════════════════════════════════════════════════
// Imphash — ELF via goblin
// ═══════════════════════════════════════════════════════════════

fn compute_elf_imphash(path: &str) -> Option<String> {
    use goblin::Object;

    let data = fs::read(path).ok()?;
    let obj = Object::parse(&data).ok()?;

    let elf = match obj {
        Object::Elf(e) => e,
        _ => return None,
    };

    let mut imports: Vec<String> = Vec::new();

    for sym in &elf.dynsyms {
        // goblin 0.9: dynstrtab.get_at() returns Option<&str>
        let sym_name: &str = elf.dynstrtab.get_at(sym.st_name)?;
        if sym.is_import() && !sym_name.is_empty() {
            imports.push(sym_name.to_string());
        }
    }

    if imports.is_empty() {
        return None;
    }

    imports.sort();
    imports.dedup();

    let mut hasher = Sha256::new();
    let joined = imports.join(",");
    hasher.update(joined.as_bytes());
    Some(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── ssdeep similarity ───

    #[test]
    fn ssdeep_identical_signatures_score_100() {
        // Two identical signatures must be 100% similar.
        let sig = "3:abcdefghij:abcdefghij";
        assert_eq!(ssdeep_similarity(sig, sig), 100);
    }

    #[test]
    fn ssdeep_completely_different_score_low() {
        // Different block sizes are only comparable across the bs/2bs bands;
        // totally unrelated content should yield a low score.
        let a = "3:aaaaaaaaaa:aaaaaaaaaa";
        let b = "3:zzzzzzzzzz:zzzzzzzzzz";
        let score = ssdeep_similarity(a, b);
        assert!(score < 50, "expected low similarity, got {score}");
    }

    #[test]
    fn ssdeep_malformed_returns_zero() {
        // Missing block-size prefix must not panic; returns 0.
        assert_eq!(ssdeep_similarity("no-colon-here", "3:x:x"), 0);
        assert_eq!(ssdeep_similarity("", "3:x:x"), 0);
    }

    // ─── block size selection ───

    #[test]
    fn block_size_grows_with_file_length() {
        // Larger files should get larger block sizes (target ~64 chunks).
        // The algorithm doubles bs from 3 until bs*64 >= len or bs hits the
        // guard, so the result is always a power-of-two multiple of 3 and is
        // bounded by the guard value used in determine_block_size.
        let small = determine_block_size(64);
        let large = determine_block_size(1_000_000);
        assert!(small >= 3);
        assert!(large > small, "large file should have bigger block size (small={small}, large={large})");
        // Allow generous headroom over the implementation's guard; the exact
        // ceiling is an internal detail, what matters is monotonicity + lower
        // bound, which the assertions above cover.
        assert!(large <= 32768, "block size unexpectedly large: {large}");
    }

    #[test]
    fn block_size_zero_length_is_minimum() {
        assert_eq!(determine_block_size(0), 3);
    }

    // ─── levenshtein ───

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn levenshtein_empty_both() {
        assert_eq!(levenshtein("", ""), 0);
    }

    // ─── compare_signatures ───

    #[test]
    fn compare_signatures_identical_is_100() {
        assert_eq!(compare_signatures("abcdef", "abcdef"), 100);
    }

    #[test]
    fn compare_signatures_empty_is_zero() {
        assert_eq!(compare_signatures("", "abc"), 0);
        assert_eq!(compare_signatures("abc", ""), 0);
    }

    #[test]
    fn compare_signatures_one_char_diff_high() {
        // 5 chars, 1 substitution -> 80% similarity.
        assert_eq!(compare_signatures("abcde", "abcdf"), 80);
    }

    // ─── FuzzySignature / MatchScore wiring ───

    #[test]
    fn fuzzy_match_exact_sha256() {
        let candidate = FuzzySignature {
            sha256: "deadbeef".to_string(),
            ssdeep: None,
            imphash: None,
            file_type: FileType::Unknown,
            file_size: 0,
        };
        let db = vec![FuzzySignature {
            sha256: "deadbeef".to_string(),
            ssdeep: None,
            imphash: None,
            file_type: FileType::Unknown,
            file_size: 0,
        }];
        let score = FuzzyHasher::fuzzy_match(&candidate, &db);
        assert!(score.sha256_match);
        assert_eq!(score.method, MatchMethod::ExactSha256);
    }

    #[test]
    fn fuzzy_match_no_match_returns_none() {
        let candidate = FuzzySignature {
            sha256: "aaaa".to_string(),
            ssdeep: None,
            imphash: None,
            file_type: FileType::Unknown,
            file_size: 0,
        };
        let db = vec![FuzzySignature {
            sha256: "bbbb".to_string(),
            ssdeep: None,
            imphash: None,
            file_type: FileType::Unknown,
            file_size: 0,
        }];
        let score = FuzzyHasher::fuzzy_match(&candidate, &db);
        assert!(!score.sha256_match);
        assert_eq!(score.method, MatchMethod::None);
    }
}
