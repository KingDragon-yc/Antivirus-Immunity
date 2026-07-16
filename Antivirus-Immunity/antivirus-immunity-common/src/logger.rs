//! Logger — 跨平台结构化日志系统 (JSONL)
//!
//! 生物学类比：免疫记忆日志 (Immunological Memory Log)
//! 以 JSONL 格式记录所有安全事件，便于 SIEM 集成和事后审计。
//! 支持自动轮转（50MB/文件）。

use crate::event::SecurityEvent;
use anyhow::Result;
use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

const LOG_DIR: &str = "logs";
const MAX_LOG_SIZE: u64 = 50 * 1024 * 1024; // 50MB
const MAX_ROTATED_LOGS: usize = 10;

#[derive(Clone)]
pub struct Logger {
    log_dir: PathBuf,
    current_log: PathBuf,
    /// When true, file logging is unavailable and events are silently dropped.
    disabled: bool,
}

impl Logger {
    pub fn new() -> Result<Self> {
        Self::with_dir(LOG_DIR)
    }

    pub fn with_dir(dir: &str) -> Result<Self> {
        let log_dir = PathBuf::from(dir);
        fs::create_dir_all(&log_dir)?;
        let current_log = log_dir.join("immunity.jsonl");
        #[cfg(unix)]
        {
            fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700))?;
            if current_log.exists() {
                fs::set_permissions(&current_log, fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(Self {
            log_dir,
            current_log,
            disabled: false,
        })
    }

    /// Construct a no-op logger that drops all events. Used as a graceful
    /// fallback when the log directory cannot be created, so the engine keeps
    /// running instead of panicking on a second failing `new()` call.
    pub fn disabled() -> Self {
        Self {
            log_dir: PathBuf::from(LOG_DIR),
            current_log: PathBuf::from(LOG_DIR).join("immunity.jsonl"),
            disabled: true,
        }
    }

    /// Log a security event
    pub fn log(&self, event: &SecurityEvent) {
        if self.disabled {
            return;
        }

        if let Ok(metadata) = fs::metadata(&self.current_log)
            && metadata.len() > MAX_LOG_SIZE
        {
            let _ = self.rotate();
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        if let Ok(json) = serde_json::to_string(event)
            && let Ok(mut file) = options.open(&self.current_log)
        {
            let _ = writeln!(file, "{}", json);
        }
    }

    /// Rotate log files when size limit exceeded
    fn rotate(&self) -> Result<()> {
        let ts = Utc::now().format("%Y%m%d_%H%M%S_%3f");
        let rotated = self.log_dir.join(format!("immunity_{}.jsonl", ts));
        fs::rename(&self.current_log, rotated)?;
        self.prune_rotated()?;
        Ok(())
    }

    fn prune_rotated(&self) -> Result<()> {
        let mut rotated: Vec<PathBuf> = fs::read_dir(&self.log_dir)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("immunity_") && name.ends_with(".jsonl"))
            })
            .collect();
        rotated.sort_unstable();
        let remove_count = rotated.len().saturating_sub(MAX_ROTATED_LOGS);
        for path in rotated.into_iter().take(remove_count) {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotated_logs_are_bounded() {
        let directory = std::env::temp_dir().join(format!("immunity-logs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let logger = Logger::with_dir(directory.to_str().unwrap()).unwrap();
        for index in 0..12 {
            fs::write(
                directory.join(format!("immunity_20260101_000000_{index:03}.jsonl")),
                b"fixture",
            )
            .unwrap();
        }
        logger.prune_rotated().unwrap();
        let remaining = fs::read_dir(&directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .count();
        assert_eq!(remaining, MAX_ROTATED_LOGS);
        let _ = fs::remove_dir_all(directory);
    }
}
