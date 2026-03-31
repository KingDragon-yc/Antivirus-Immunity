#![allow(dead_code)]
//! Quarantine Module — 隔离区管理
//!
//! 生物学类比：淋巴结隔离 (Lymph Node Sequestration)
//! 当免疫系统发现可疑病原体时，不一定立即杀死，而是先将其
//! 运送到淋巴结进行隔离和进一步分析。
//!
//! 本模块提供文件隔离功能——将可疑文件移动到隔离目录，
//! 记录隔离元数据，支持后续释放或永久删除。

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const QUARANTINE_DIR: &str = "quarantine";
const QUARANTINE_DB: &str = "quarantine/manifest.json";

/// Metadata for a quarantined item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique ID for this quarantine action
    pub id: String,
    /// Original file path before quarantine
    pub original_path: String,
    /// Path within quarantine directory
    pub quarantine_path: String,
    /// SHA256 hash of the file
    pub hash: Option<String>,
    /// Reason for quarantine
    pub reason: String,
    /// Associated process info
    pub process_name: String,
    pub process_pid: u32,
    /// Timestamp of quarantine action
    pub quarantined_at: DateTime<Utc>,
    /// Whether the file has been released or deleted
    pub status: QuarantineStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuarantineStatus {
    Active,
    Released,
    Deleted,
}

/// Quarantine manifest — persisted list of all quarantine actions
#[derive(Debug, Serialize, Deserialize)]
struct QuarantineManifest {
    entries: Vec<QuarantineEntry>,
}

pub struct Quarantine {
    dir: PathBuf,
    entries: Vec<QuarantineEntry>,
}

impl Quarantine {
    pub fn new() -> Result<Self> {
        let dir = PathBuf::from(QUARANTINE_DIR);
        fs::create_dir_all(&dir)?;

        let entries = Self::load_manifest().unwrap_or_default();
        let active_count = entries
            .iter()
            .filter(|e| e.status == QuarantineStatus::Active)
            .count();

        if active_count > 0 {
            println!(
                "[+] Quarantine: {} files currently in isolation.",
                active_count
            );
        }

        Ok(Self { dir, entries })
    }

    /// Quarantine a file: move it to the quarantine directory
    pub fn isolate(
        &mut self,
        file_path: &str,
        hash: Option<String>,
        reason: &str,
        process_name: &str,
        process_pid: u32,
    ) -> Result<QuarantineEntry> {
        let source = Path::new(file_path);
        if !source.exists() {
            return Err(anyhow::anyhow!("File does not exist: {}", file_path));
        }

        let id = Uuid::new_v4().to_string();
        let extension = source
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();

        // Quarantine file is stored with UUID name + .quarantine extension
        // to prevent accidental execution
        let quarantine_filename = format!("{}.{}.quarantine", id, extension);
        let quarantine_path = self.dir.join(&quarantine_filename);

        // Move file to quarantine
        fs::copy(source, &quarantine_path)
            .with_context(|| format!("Failed to copy {} to quarantine", file_path))?;

        // Remove original (best effort — may fail due to file locks)
        if let Err(e) = fs::remove_file(source) {
            eprintln!(
                "    [!] Warning: Could not remove original file (may be locked): {}",
                e
            );
        }

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: file_path.to_string(),
            quarantine_path: quarantine_path.to_string_lossy().to_string(),
            hash,
            reason: reason.to_string(),
            process_name: process_name.to_string(),
            process_pid,
            quarantined_at: Utc::now(),
            status: QuarantineStatus::Active,
        };

        self.entries.push(entry.clone());
        self.save_manifest()?;

        Ok(entry)
    }

    /// Release a file from quarantine back to its original location
    pub fn release(&mut self, quarantine_id: &str) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == quarantine_id && e.status == QuarantineStatus::Active)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No active quarantine entry found with ID: {}",
                    quarantine_id
                )
            })?;

        let qpath = Path::new(&entry.quarantine_path);
        let original = Path::new(&entry.original_path);

        if qpath.exists() {
            // Ensure parent directory exists
            if let Some(parent) = original.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(qpath, original)?;
            fs::remove_file(qpath)?;
        }

        entry.status = QuarantineStatus::Released;
        self.save_manifest()?;
        Ok(())
    }

    /// Permanently delete a quarantined file
    pub fn purge(&mut self, quarantine_id: &str) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == quarantine_id && e.status == QuarantineStatus::Active)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No active quarantine entry found with ID: {}",
                    quarantine_id
                )
            })?;

        let qpath = Path::new(&entry.quarantine_path);
        if qpath.exists() {
            fs::remove_file(qpath)?;
        }

        entry.status = QuarantineStatus::Deleted;
        self.save_manifest()?;
        Ok(())
    }

    /// List all active quarantine entries
    pub fn list_active(&self) -> Vec<&QuarantineEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == QuarantineStatus::Active)
            .collect()
    }

    fn load_manifest() -> Result<Vec<QuarantineEntry>> {
        let data = fs::read_to_string(QUARANTINE_DB)?;
        let manifest: QuarantineManifest = serde_json::from_str(&data)?;
        Ok(manifest.entries)
    }

    fn save_manifest(&self) -> Result<()> {
        let manifest = QuarantineManifest {
            entries: self.entries.clone(),
        };
        let data = serde_json::to_string_pretty(&manifest)?;
        fs::write(QUARANTINE_DB, data)?;
        Ok(())
    }
}
