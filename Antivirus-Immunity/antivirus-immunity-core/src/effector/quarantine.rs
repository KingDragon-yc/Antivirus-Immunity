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
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use windows::Win32::Storage::FileSystem::{REPLACE_FILE_FLAGS, ReplaceFileW};
use windows::core::PCWSTR;

const QUARANTINE_DIR: &str = "quarantine";

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
    db_path: PathBuf,
    entries: Vec<QuarantineEntry>,
}

impl Quarantine {
    pub fn new() -> Result<Self> {
        let dir = PathBuf::from(QUARANTINE_DIR);
        Self::with_dir(dir)
    }

    pub fn with_dir(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        let db_path = dir.join(".qdb");

        let entries = match Self::load_manifest(&db_path) {
            Ok(entries) => entries,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                Vec::new()
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "Quarantine manifest {} is unreadable; refusing to forget existing entries",
                        db_path.display()
                    )
                });
            }
        };
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

        Ok(Self {
            dir,
            db_path,
            entries,
        })
    }

    /// Quarantine a file: move it to the quarantine directory.
    ///
    /// Uses `fs::rename` (MoveFileExW on Windows) as primary strategy.
    /// Windows allows renaming/moving a running executable within the same volume,
    /// even when delete is blocked by mandatory file locking. This is the
    /// "移星换斗" (swap stars for a fighting post) technique:
    /// move the file before killing the process, so the malware cannot re-launch itself.
    ///
    /// Falls back to copy+delete if rename fails (e.g. cross-volume move).
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

        // Step 1: Attempt atomic rename (MoveFileExW on Windows).
        // On the same volume, this succeeds even if the file is locked by a running process.
        Self::move_verified(source, &quarantine_path)
            .with_context(|| format!("Failed to remove original while isolating {}", file_path))?;

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
        if let Err(save_err) = self.save_manifest() {
            self.entries.pop();
            let rollback = Self::move_verified(&quarantine_path, source);
            return match rollback {
                Ok(()) => Err(save_err).context("Manifest write failed; isolation rolled back"),
                Err(rollback_err) => Err(anyhow::anyhow!(
                    "Manifest write failed ({save_err}); rollback also failed ({rollback_err}); quarantined file may be orphaned at {}",
                    quarantine_path.display()
                )),
            };
        }

        Ok(entry)
    }

    /// Release a file from quarantine back to its original location
    pub fn release(&mut self, quarantine_id: &str) -> Result<()> {
        let index = self
            .entries
            .iter()
            .position(|e| e.id == quarantine_id && e.status == QuarantineStatus::Active)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No active quarantine entry found with ID: {}",
                    quarantine_id
                )
            })?;

        let qpath = PathBuf::from(&self.entries[index].quarantine_path);
        let original = PathBuf::from(&self.entries[index].original_path);

        if !qpath.exists() {
            return Err(anyhow::anyhow!(
                "Quarantined file is missing; refusing to mark entry released: {}",
                qpath.display()
            ));
        }
        if original.exists() {
            return Err(anyhow::anyhow!(
                "Original path already exists; refusing to overwrite it: {}",
                original.display()
            ));
        }
        if let Some(parent) = original.parent() {
            fs::create_dir_all(parent)?;
        }
        Self::move_verified(&qpath, &original)?;

        self.entries[index].status = QuarantineStatus::Released;
        if let Err(save_err) = self.save_manifest() {
            self.entries[index].status = QuarantineStatus::Active;
            let rollback = Self::move_verified(&original, &qpath);
            return match rollback {
                Ok(()) => Err(save_err).context("Manifest write failed; release rolled back"),
                Err(rollback_err) => Err(anyhow::anyhow!(
                    "Manifest write failed ({save_err}); release rollback failed ({rollback_err})"
                )),
            };
        }
        Ok(())
    }

    /// Permanently delete a quarantined file
    pub fn purge(&mut self, quarantine_id: &str) -> Result<()> {
        let index = self
            .entries
            .iter()
            .position(|e| e.id == quarantine_id && e.status == QuarantineStatus::Active)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No active quarantine entry found with ID: {}",
                    quarantine_id
                )
            })?;

        let qpath = PathBuf::from(&self.entries[index].quarantine_path);
        if !qpath.exists() {
            return Err(anyhow::anyhow!(
                "Quarantined file is missing; refusing to mark entry deleted: {}",
                qpath.display()
            ));
        }
        let tombstone = self
            .dir
            .join(format!(".purging-{}", self.entries[index].id));
        Self::move_verified(&qpath, &tombstone)?;

        self.entries[index].status = QuarantineStatus::Deleted;
        if let Err(save_err) = self.save_manifest() {
            self.entries[index].status = QuarantineStatus::Active;
            let rollback = Self::move_verified(&tombstone, &qpath);
            return match rollback {
                Ok(()) => Err(save_err).context("Manifest write failed; purge rolled back"),
                Err(rollback_err) => Err(anyhow::anyhow!(
                    "Manifest write failed ({save_err}); purge rollback failed ({rollback_err})"
                )),
            };
        }
        if let Err(delete_err) = fs::remove_file(&tombstone) {
            self.entries[index].status = QuarantineStatus::Active;
            let _ = Self::move_verified(&tombstone, &qpath);
            let _ = self.save_manifest();
            return Err(delete_err).context("Failed to delete quarantined file; purge rolled back");
        }
        Ok(())
    }

    /// List all active quarantine entries
    pub fn list_active(&self) -> Vec<&QuarantineEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == QuarantineStatus::Active)
            .collect()
    }

    fn load_manifest(db_path: &Path) -> Result<Vec<QuarantineEntry>> {
        let encoded = fs::read_to_string(db_path)?;
        let data = hex::decode(encoded.trim())
            .map_err(|e| anyhow::anyhow!("Failed to decode quarantine manifest: {}", e))?;
        let json = String::from_utf8(data)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in quarantine manifest: {}", e))?;
        let manifest: QuarantineManifest = serde_json::from_str(&json)?;
        Ok(manifest.entries)
    }

    fn save_manifest(&self) -> Result<()> {
        let manifest = QuarantineManifest {
            entries: self.entries.clone(),
        };
        let data = serde_json::to_string_pretty(&manifest)?;
        let encoded = hex::encode(data.as_bytes());
        let temp_path = self.dir.join(format!(".qdb.{}.tmp", Uuid::new_v4()));
        let mut temp = fs::File::create(&temp_path)?;
        use std::io::Write;
        temp.write_all(encoded.as_bytes())?;
        temp.sync_all()?;
        drop(temp);

        let replace_result = if self.db_path.exists() {
            replace_file(&self.db_path, &temp_path)
        } else {
            fs::rename(&temp_path, &self.db_path).map_err(anyhow::Error::from)
        };
        if let Err(e) = replace_result {
            let _ = fs::remove_file(&temp_path);
            return Err(e).context("Failed to atomically replace quarantine manifest");
        }
        Ok(())
    }

    /// Move a file and report success only when the source is gone. Cross-volume
    /// moves use copy+delete, but a delete failure removes the copy and returns
    /// an error so callers never record a false quarantine success.
    fn move_verified(source: &Path, destination: &Path) -> Result<()> {
        match fs::rename(source, destination) {
            Ok(()) => Ok(()),
            Err(rename_err) => {
                fs::copy(source, destination).with_context(|| {
                    format!(
                        "Failed to copy {} to {} after rename failed: {}",
                        source.display(),
                        destination.display(),
                        rename_err
                    )
                })?;
                if let Err(delete_err) = fs::remove_file(source) {
                    let _ = fs::remove_file(destination);
                    return Err(anyhow::anyhow!(
                        "Copied file but could not remove source {}: {}",
                        source.display(),
                        delete_err
                    ));
                }
                Ok(())
            }
        }
    }
}

fn replace_file(destination: &Path, replacement: &Path) -> Result<()> {
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let replacement_wide: Vec<u16> = replacement
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        ReplaceFileW(
            PCWSTR(destination_wide.as_ptr()),
            PCWSTR(replacement_wide.as_ptr()),
            PCWSTR::null(),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_quarantine() -> PathBuf {
        std::env::temp_dir().join(format!("immunity-quarantine-{}", Uuid::new_v4()))
    }

    #[test]
    fn corrupted_manifest_is_rejected_instead_of_forgotten() {
        let dir = temp_quarantine();
        fs::create_dir_all(&dir).expect("create test quarantine");
        fs::write(dir.join(".qdb"), "not-hex").expect("write corrupt manifest");

        assert!(Quarantine::with_dir(dir.clone()).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn release_refuses_missing_quarantined_file() {
        let dir = temp_quarantine();
        let source = dir.with_extension("source.exe");
        fs::write(&source, b"sample").expect("write source");
        let mut quarantine = Quarantine::with_dir(dir.clone()).expect("create quarantine");
        let entry = quarantine
            .isolate(source.to_str().expect("utf8"), None, "test", "sample", 1)
            .expect("isolate");
        fs::remove_file(&entry.quarantine_path).expect("remove quarantined file");

        assert!(quarantine.release(&entry.id).is_err());
        assert_eq!(quarantine.list_active().len(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn repeated_manifest_updates_remain_reloadable() {
        let dir = temp_quarantine();
        let source_a = dir.with_extension("a.exe");
        let source_b = dir.with_extension("b.exe");
        fs::write(&source_a, b"a").expect("write source a");
        fs::write(&source_b, b"b").expect("write source b");
        let mut quarantine = Quarantine::with_dir(dir.clone()).expect("create quarantine");
        quarantine
            .isolate(source_a.to_str().expect("utf8"), None, "a", "a", 1)
            .expect("first isolate");
        quarantine
            .isolate(source_b.to_str().expect("utf8"), None, "b", "b", 2)
            .expect("second isolate");
        drop(quarantine);

        let reloaded = Quarantine::with_dir(dir.clone()).expect("reload manifest");
        assert_eq!(reloaded.list_active().len(), 2);
        let _ = fs::remove_dir_all(dir);
    }
}
