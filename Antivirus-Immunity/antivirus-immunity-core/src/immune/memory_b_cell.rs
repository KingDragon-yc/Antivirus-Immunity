use crate::receptor::toll_like_receptor::ProcessInfo;
use crate::immune::path_validator::{PathValidator, PathVerdict};
use crate::immune::danger_theory::DangerLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use yara_x::{Compiler, Rules, Scanner};

const DB_FILE: &str = "immunity_db.json";
const ANTIGENS_FILE: &str = "antigens.yar";

#[derive(Serialize, Deserialize)]
struct MemoryBCellStorage {
    trusted_hashes: HashSet<String>,
}

/// Memory B Cell: Responsible for remembering trusted antigens (hashes).
pub struct MemoryBCell {
    trusted_hashes: HashSet<String>,
}

impl MemoryBCell {
    pub fn new() -> Self {
        let trusted_hashes = Self::load().unwrap_or_else(|_| {
            println!("[*] Memory B Cell: No existing memory found. Starting fresh.");
            HashSet::new()
        });

        if !trusted_hashes.is_empty() {
            println!(
                "[+] Memory B Cell: Recalled {} trusted signatures.",
                trusted_hashes.len()
            );
        }

        Self { trusted_hashes }
    }

    fn load() -> anyhow::Result<HashSet<String>> {
        let file = File::open(DB_FILE)?;
        let reader = std::io::BufReader::new(file);
        let memory: MemoryBCellStorage = serde_json::from_reader(reader)?;
        Ok(memory.trusted_hashes)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let memory = MemoryBCellStorage {
            trusted_hashes: self.trusted_hashes.clone(),
        };
        let file = File::create(DB_FILE)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &memory)?;
        Ok(())
    }

    pub fn learn(&mut self, hash: String) -> bool {
        self.trusted_hashes.insert(hash)
    }

    pub fn is_trusted(&self, hash: &str) -> bool {
        self.trusted_hashes.contains(hash)
    }
}

pub struct ImmuneSystem {
    memory_b_cell: MemoryBCell,
    path_validator: PathValidator,
    yara_rules: Option<Rules>,
}

/// The assessment result from the immune system evaluation pipeline.
/// Now includes much richer context for downstream consumers.
#[derive(Debug)]
pub enum Assessment {
    /// Process is verified safe (trusted hash + verified path)
    Safe,
    /// Confirmed malware (YARA match)
    Critical(String),
    /// Anomaly detected (path imposter, unknown signature, etc.)
    Suspicious(String),
    /// Not enough information to classify — candidate for AI deep analysis
    Unknown,
    /// Needs AI Cortex deep analysis (ambiguous signals)
    NeedsAiReview(String),
}

impl ImmuneSystem {
    pub fn new() -> Self {
        // Load YARA rules (Antigens)
        let yara_rules = Self::load_antigens().ok();
        if yara_rules.is_some() {
            println!("[+] Immune System: Antigen database (YARA) loaded.");
        } else {
            println!("[!] Warning: Failed to load antigen database ('antigens.yar').");
        }

        Self {
            memory_b_cell: MemoryBCell::new(),
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
        println!("[*] Learning phase active. Memory B Cells are recording antigens...");
        let mut count = 0;
        for p in processes {
            if let Some(hash) = &p.hash {
                if self.memory_b_cell.learn(hash.clone()) {
                    count += 1;
                }
            }
        }

        if count > 0 {
            match self.memory_b_cell.save() {
                Ok(_) => println!(
                    "[+] Learned {} new trusted signatures. Memory saved.",
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
    /// 3. Memory B Cell (adaptive immunity) — trusted hash check
    /// 4. Danger level correlation — context-aware escalation
    /// 5. Heuristics — catch remaining edge cases
    pub fn evaluate(&self, process: &ProcessInfo, danger_level: &DangerLevel) -> Assessment {
        // ========================================
        // LAYER 1: YARA Scan (Antigen Detection — Blacklist)
        // This is the highest priority — known malware signatures
        // ========================================
        if let Some(rules) = &self.yara_rules {
            if let Some(path) = &process.path {
                match Scanner::new(rules).scan_file(path) {
                    Ok(scan_results) => {
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
                    Err(_) => {}
                }
            }
        }

        // ========================================
        // LAYER 2: Path Validation (MHC Check)
        // Critical system process impersonation is HIGH confidence malware
        // ========================================
        let path_verdict = self.path_validator.validate(
            &process.name,
            process.path.as_deref(),
        );

        match &path_verdict {
            PathVerdict::Imposter { expected, actual } => {
                // A process claims to be e.g. svchost.exe but runs from wrong path
                // This is CRITICAL — almost certainly malware
                return Assessment::Critical(format!(
                    "PATH IMPOSTER: '{}' expected in [{}] but found in '{}'",
                    process.name, expected, actual
                ));
            }
            PathVerdict::NoPath => {
                // Can't determine path for non-system PID — suspicious
                if process.pid > 4 {
                    // Don't flag System (PID 4) or Idle (PID 0)
                    // If danger level is high, escalate
                    if matches!(danger_level, DangerLevel::High | DangerLevel::Critical) {
                        return Assessment::Suspicious(
                            "Unable to determine path during high danger state".to_string(),
                        );
                    }
                }
            }
            _ => {} // Verified, TrustedLocation, UnknownLocation — continue evaluation
        }

        // ========================================
        // LAYER 3: Memory B Cell Check (Adaptive Immunity)
        // Trusted hash = previously learned as "self"
        // ========================================
        if let Some(hash) = &process.hash {
            if self.memory_b_cell.is_trusted(hash) {
                // Even trusted processes get flagged if path doesn't match
                if matches!(path_verdict, PathVerdict::Verified | PathVerdict::TrustedLocation) {
                    return Assessment::Safe;
                }
                // Trusted hash but unusual location — needs attention
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
        // LAYER 4: Danger Level Correlation
        // During high system stress, be more aggressive with unknowns
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
        // LAYER 5: Heuristics & AI Handoff
        // Ambiguous cases are sent to AI Cortex for deep analysis
        // ========================================
        if let PathVerdict::Verified | PathVerdict::TrustedLocation = path_verdict {
            // In a trusted directory but no hash match — likely legitimate new/updated software
            // Safe under normal conditions, review under elevated danger
            if matches!(danger_level, DangerLevel::Normal | DangerLevel::Elevated) {
                return Assessment::Unknown;
            }
            return Assessment::NeedsAiReview(format!(
                "Unrecognized process in trusted location during elevated danger: {}",
                process.name
            ));
        }

        // Unknown location + unknown hash = candidate for AI review
        if process.hash.is_some() {
            return Assessment::NeedsAiReview(format!(
                "Unknown signature from non-standard location: {}",
                process.path.as_deref().unwrap_or("N/A")
            ));
        }

        Assessment::Unknown
    }

    /// Get YARA match details for a specific file (used by AI context building)
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

    /// Check if a hash is in the trusted database
    pub fn is_hash_trusted(&self, hash: &str) -> bool {
        self.memory_b_cell.is_trusted(hash)
    }

    /// Get path verdict string for AI context
    pub fn get_path_verdict_string(&self, name: &str, path: Option<&str>) -> String {
        format!("{:?}", self.path_validator.validate(name, path))
    }
}

