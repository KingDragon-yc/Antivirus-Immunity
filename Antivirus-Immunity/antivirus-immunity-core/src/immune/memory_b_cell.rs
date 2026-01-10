use crate::receptor::toll_like_receptor::ProcessInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
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
    whitelist_names: HashSet<String>, // Innate immunity (Hardcoded names)
    yara_rules: Option<Rules>,
}

#[derive(Debug)]
pub enum Assessment {
    Safe,
    Critical(String),   // Confirmed Malware (YARA match)
    Suspicious(String), // Anomaly (Whitelist mismatch)
    Unknown,
}

impl ImmuneSystem {
    pub fn new() -> Self {
        let mut whitelist_names = HashSet::new();
        // Basic Windows Processes (Naive Innate Immunity)
        whitelist_names.insert("svchost.exe".to_string());
        whitelist_names.insert("explorer.exe".to_string());
        whitelist_names.insert("System".to_string());
        whitelist_names.insert("Registry".to_string());
        whitelist_names.insert("smss.exe".to_string());
        whitelist_names.insert("csrss.exe".to_string());
        whitelist_names.insert("wininit.exe".to_string());
        whitelist_names.insert("services.exe".to_string());
        whitelist_names.insert("lsass.exe".to_string());
        whitelist_names.insert("winlogon.exe".to_string());

        // Load YARA rules (Antigens)
        let yara_rules = Self::load_antigens().ok();
        if yara_rules.is_some() {
            println!("[+] Immune System: Antigen database (YARA) loaded.");
        } else {
            println!("[!] Warning: Failed to load antigen database ('antigens.yar').");
        }

        Self {
            memory_b_cell: MemoryBCell::new(),
            whitelist_names,
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

    pub fn evaluate(&self, process: &ProcessInfo) -> Assessment {
        // 1. Memory B Cell Check (Adaptive Immunity - Whitelist)
        if let Some(hash) = &process.hash {
            if self.memory_b_cell.is_trusted(hash) {
                return Assessment::Safe;
            }
        }

        // 2. YARA Scan (Antigen Detection - Blacklist)
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

        // 3. Innate Immunity (Name Check)
        if self.whitelist_names.contains(&process.name) {
            if process.hash.is_some() {
                return Assessment::Suspicious(
                    "Known name but unknown signature (Potential Imposter)".to_string(),
                );
            }
            return Assessment::Safe;
        }

        // 4. Heuristics
        if process.path.is_none() && process.pid > 4 {
            return Assessment::Unknown;
        }

        Assessment::Unknown
    }
}
