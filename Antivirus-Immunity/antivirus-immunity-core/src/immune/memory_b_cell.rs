use crate::immune::danger_theory::DangerLevel;
use crate::immune::fuzzy_hash::{FileType, FuzzyHasher, FuzzySignature, MatchMethod, MatchScore};
use crate::immune::path_validator::{PathValidator, PathVerdict};
use crate::receptor::toll_like_receptor::ProcessInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use yara_x::{Compiler, Rules, Scanner};

const DB_FILE: &str = "immunity_db.json";
const ANTIGENS_FILE: &str = "antigens.yar";

// ═══════════════════════════════════════════════════════════════
// Persistence schema (V2 — multi-hash fuzzy signatures)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzySigRecord {
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ssdeep: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub imphash: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub file_type: String,
    #[serde(default = "default_label")]
    pub labeled: String,
    #[serde(default)]
    pub learned_at: String,
}

fn default_label() -> String {
    "trusted".to_string()
}

#[derive(Serialize, Deserialize)]
struct MemoryBCellStorage {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    signatures: Vec<FuzzySigRecord>,
    /// V1 backward compat — migrated on load
    #[serde(default)]
    trusted_hashes: HashSet<String>,
}

fn default_version() -> u32 {
    2
}

// ═══════════════════════════════════════════════════════════════
// Memory B Cell — Adaptive Immune Memory with Fuzzy Hashing
// ═══════════════════════════════════════════════════════════════

pub struct MemoryBCell {
    signatures: Vec<FuzzySigRecord>,
}

impl MemoryBCell {
    pub fn new() -> Self {
        let signatures = Self::load().unwrap_or_else(|_| {
            println!("[*] Memory B Cell: No existing memory found. Starting fresh.");
            Vec::new()
        });

        if !signatures.is_empty() {
            println!(
                "[+] Memory B Cell: Recalled {} signatures (SHA256 + Ssdeep + Imphash).",
                signatures.len()
            );
        }

        Self { signatures }
    }

    fn load() -> anyhow::Result<Vec<FuzzySigRecord>> {
        let file = File::open(DB_FILE)?;
        let reader = BufReader::new(file);
        let storage: MemoryBCellStorage = serde_json::from_reader(reader)?;

        // V1 migration: convert bare SHA256 hashes to full records
        if (storage.version < 2 || storage.signatures.is_empty())
            && !storage.trusted_hashes.is_empty()
        {
            println!("[*] Memory B Cell: Migrating V1 database to V2 (fuzzy hash)...");
            let records: Vec<FuzzySigRecord> = storage
                .trusted_hashes
                .into_iter()
                .map(|sha| FuzzySigRecord {
                    sha256: sha,
                    ssdeep: None,
                    imphash: None,
                    path: None,
                    file_type: "Unknown".to_string(),
                    labeled: "trusted".to_string(),
                    learned_at: String::new(),
                })
                .chain(storage.signatures)
                .collect();
            println!(
                "[+] Migrated {} records to V2 fuzzy signature format.",
                records.len()
            );
            return Ok(records);
        }

        Ok(storage.signatures)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let storage = MemoryBCellStorage {
            version: 2,
            signatures: self.signatures.clone(),
            trusted_hashes: HashSet::new(),
        };
        let file = File::create(DB_FILE)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &storage)?;
        Ok(())
    }

    /// Learn a new trusted signature with full fuzzy hashes.
    /// Called during learning mode to build the "self" profile.
    pub fn learn(&mut self, hash: String, path: Option<&str>) -> bool {
        // Check if already known by SHA256
        if self.signatures.iter().any(|r| r.sha256 == hash) {
            return false;
        }

        let mut record = FuzzySigRecord {
            sha256: hash,
            ssdeep: None,
            imphash: None,
            path: path.map(|p| p.to_string()),
            file_type: "Unknown".to_string(),
            labeled: "trusted".to_string(),
            learned_at: chrono::Utc::now().to_rfc3339(),
        };

        // Compute fuzzy hashes from the file
        if let Some(p) = path {
            if let Some(fuzzy) = FuzzyHasher::compute_all(p) {
                record.ssdeep = fuzzy.ssdeep;
                record.imphash = fuzzy.imphash;
                record.file_type = fuzzy.file_type.as_str().to_string();
            }
        }

        self.signatures.push(record);
        true
    }

    /// Exact SHA256 match — fast path for known hashes.
    /// Backward-compatible with the old API.
    pub fn is_trusted(&self, hash: &str) -> bool {
        self.signatures.iter().any(|r| r.sha256 == hash)
    }

    /// Multi-method fuzzy hash check against the trusted signature database.
    ///
    /// Computes all available hashes for the file at `path`, then matches
    /// against stored signatures using:
    ///   1. Exact SHA256 — instant verdict
    ///   2. Ssdeep similarity (≥80% → same family)
    ///   3. Imphash exact match (same import table → same family)
    pub fn fuzzy_check(&self, path: &str) -> MatchScore {
        let candidate = match FuzzyHasher::compute_all(path) {
            Some(c) => c,
            None => {
                return MatchScore {
                    sha256_match: false,
                    ssdeep_similarity: None,
                    imphash_match: false,
                    method: MatchMethod::None,
                }
            }
        };

        // Exact SHA256 check first (fast path)
        if self.is_trusted(&candidate.sha256) {
            return MatchScore {
                sha256_match: true,
                ssdeep_similarity: None,
                imphash_match: false,
                method: MatchMethod::ExactSha256,
            };
        }

        // Build database of FuzzySignatures from our records
        let db: Vec<FuzzySignature> = self
            .signatures
            .iter()
            .map(|r| FuzzySignature {
                sha256: r.sha256.clone(),
                ssdeep: r.ssdeep.clone(),
                imphash: r.imphash.clone(),
                file_type: match r.file_type.as_str() {
                    "PE" => FileType::PE,
                    "ELF" => FileType::ELF,
                    _ => FileType::Unknown,
                },
                file_size: 0,
            })
            .collect();

        FuzzyHasher::fuzzy_match(&candidate, &db)
    }

    /// Query the full set of signatures (for listing/audit)
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

// ═══════════════════════════════════════════════════════════════
// Immune System — evaluation pipeline
// ═══════════════════════════════════════════════════════════════

pub struct ImmuneSystem {
    memory_b_cell: MemoryBCell,
    path_validator: PathValidator,
    yara_rules: Option<Rules>,
}

/// The assessment result from the immune system evaluation pipeline.
#[derive(Debug)]
pub enum Assessment {
    Safe,
    Critical(String),
    Suspicious(String),
    Unknown,
    NeedsAiReview(String),
}

impl ImmuneSystem {
    pub fn new() -> Self {
        let yara_rules = Self::load_antigens().ok();
        if yara_rules.is_some() {
            println!("[+] Immune System: Antigen database (YARA) loaded.");
        } else {
            println!("[!] Warning: Failed to load antigen database ('antigens.yar').");
        }

        let memory = MemoryBCell::new();
        println!(
            "[+] Immune System: {} signatures in adaptive memory (SHA256 + Ssdeep + Imphash).",
            memory.signature_count()
        );

        Self {
            memory_b_cell: memory,
            path_validator: PathValidator::new(),
            yara_rules,
        }
    }

    fn load_antigens() -> anyhow::Result<Rules> {
        let source = std::fs::read_to_string(ANTIGENS_FILE)?;
        let mut compiler = Compiler::new();
        compiler.add_source(source.as_str())?;
        let rules = compiler.build();
        Ok(rules)
    }

    pub fn learn_self(&mut self, processes: &[ProcessInfo]) {
        println!("[*] Learning phase active. Building fuzzy immune memory...");
        let mut count = 0;
        for p in processes {
            if let Some(hash) = &p.hash {
                if self.memory_b_cell.learn(hash.clone(), p.path.as_deref()) {
                    count += 1;
                }
            }
        }

        if count > 0 {
            match self.memory_b_cell.save() {
                Ok(_) => println!(
                    "[+] Learned {} new signatures (SHA256 + Ssdeep + Imphash). Memory saved.",
                    count
                ),
                Err(e) => eprintln!("[-] Failed to consolidate memory: {}", e),
            }
        } else {
            println!("[*] No new signatures to learn.");
        }
    }

    /// Multi-layered evaluation pipeline:
    /// 1. YARA scan (blacklist) — immediate conviction
    /// 2. Path validation (MHC check) — imposter detection
    /// 3. SHA256 exact match (fast path) — known trusted hash
    /// 4. Fuzzy hash matching (Ssdeep + Imphash) — variant detection
    /// 5. Danger level correlation — context-aware escalation
    /// 6. Heuristics — catch remaining edge cases
    pub fn evaluate(&self, process: &ProcessInfo, danger_level: &DangerLevel) -> Assessment {
        // ========================================
        // LAYER 1: YARA Scan (Antigen Detection — Blacklist)
        // ========================================
        if let Some(rules) = &self.yara_rules {
            if let Some(path) = &process.path {
                if let Ok(scan_results) = Scanner::new(rules).scan_file(path) {
                    let matching_rules: Vec<_> = scan_results.matching_rules().collect();
                    if !matching_rules.is_empty() {
                        let names: Vec<String> = matching_rules
                            .iter()
                            .map(|r| r.identifier().to_string())
                            .collect();
                        return Assessment::Critical(format!(
                            "Antigen Detected: {}",
                            names.join(", ")
                        ));
                    }
                }
            }
        }

        // ========================================
        // LAYER 2: Path Validation (MHC Check)
        // ========================================
        let path_verdict = self
            .path_validator
            .validate(&process.name, process.path.as_deref());

        match &path_verdict {
            PathVerdict::Imposter { expected, actual } => {
                return Assessment::Critical(format!(
                    "PATH IMPOSTER: '{}' expected in [{}] but found in '{}'",
                    process.name, expected, actual
                ));
            }
            PathVerdict::NoPath => {
                // clippy wants to fold this `if` into the match arm as a guard,
                // but that would change control flow: an unmatched guard falls
                // through to `_ => {}`, skipping the downstream YARA/fuzzy/danger
                // layers. Keep the explicit `if` so NoPath continues to evaluate
                // the rest of the pipeline when the condition is false.
                #[allow(clippy::collapsible_match)]
                if process.pid > 4
                    && matches!(danger_level, DangerLevel::High | DangerLevel::Critical)
                {
                    return Assessment::Suspicious(
                        "Unable to determine path during high danger state".to_string(),
                    );
                }
            }
            _ => {}
        }

        // ========================================
        // LAYER 3: SHA256 Exact Match (Fast Path)
        // ========================================
        if let Some(hash) = &process.hash {
            if self.memory_b_cell.is_trusted(hash) {
                if matches!(
                    path_verdict,
                    PathVerdict::Verified | PathVerdict::TrustedLocation
                ) {
                    return Assessment::Safe;
                }
                if let PathVerdict::UnknownLocation { ref path } = path_verdict {
                    return Assessment::NeedsAiReview(format!(
                        "Trusted hash but running from unusual location: {}",
                        path
                    ));
                }
                return Assessment::Safe;
            }
        }

        // ========================================
        // LAYER 4: Fuzzy Hash Matching (Ssdeep + Imphash)
        // ========================================
        if let Some(ref path) = process.path {
            let match_score = self.memory_b_cell.fuzzy_check(path);
            match match_score.method {
                MatchMethod::ExactSha256 => {
                    // Already handled in LAYER 3, but defensive
                    return Assessment::Safe;
                }
                MatchMethod::Ssdeep(similarity) => {
                    // Same binary family with high confidence
                    let reason = format!(
                        "Ssdeep {}% similarity to known trusted binary — likely legitimate update",
                        similarity
                    );
                    if matches!(
                        path_verdict,
                        PathVerdict::Verified | PathVerdict::TrustedLocation
                    ) {
                        return Assessment::Safe;
                    }
                    return Assessment::NeedsAiReview(reason);
                }
                MatchMethod::Imphash => {
                    // Same import table — same software family, different code
                    let reason =
                        "Import table matches known trusted software — possible variant or update"
                            .to_string();
                    if matches!(
                        path_verdict,
                        PathVerdict::Verified | PathVerdict::TrustedLocation
                    ) {
                        return Assessment::Safe;
                    }
                    return Assessment::NeedsAiReview(reason);
                }
                MatchMethod::None => {
                    // No fuzzy match — fall through to danger level correlation
                }
            }
        }

        // ========================================
        // LAYER 5: Danger Level Correlation
        // ========================================
        match danger_level {
            DangerLevel::Critical => {
                if matches!(path_verdict, PathVerdict::UnknownLocation { .. }) {
                    return Assessment::Suspicious(format!(
                        "Unknown process during CRITICAL danger state: {}",
                        process.name
                    ));
                }
            }
            DangerLevel::High => {
                if matches!(path_verdict, PathVerdict::UnknownLocation { .. }) {
                    return Assessment::NeedsAiReview(format!(
                        "Unknown process during HIGH danger state: {}",
                        process.name
                    ));
                }
            }
            _ => {}
        }

        // ========================================
        // LAYER 6: Heuristics & AI Handoff
        // ========================================
        if let PathVerdict::Verified | PathVerdict::TrustedLocation = path_verdict {
            if matches!(danger_level, DangerLevel::Normal | DangerLevel::Elevated) {
                return Assessment::Unknown;
            }
            return Assessment::NeedsAiReview(format!(
                "Unrecognized process in trusted location during elevated danger: {}",
                process.name
            ));
        }

        if process.hash.is_some() {
            return Assessment::NeedsAiReview(format!(
                "Unknown signature from non-standard location: {}",
                process.path.as_deref().unwrap_or("N/A")
            ));
        }

        Assessment::Unknown
    }

    pub fn get_yara_matches(&self, file_path: &str) -> Vec<String> {
        if let Some(rules) = &self.yara_rules {
            if let Ok(results) = Scanner::new(rules).scan_file(file_path) {
                return results
                    .matching_rules()
                    .map(|r| r.identifier().to_string())
                    .collect();
            }
        }
        Vec::new()
    }

    pub fn is_hash_trusted(&self, hash: &str) -> bool {
        self.memory_b_cell.is_trusted(hash)
    }

    pub fn get_path_verdict_string(&self, name: &str, path: Option<&str>) -> String {
        format!("{:?}", self.path_validator.validate(name, path))
    }
}
