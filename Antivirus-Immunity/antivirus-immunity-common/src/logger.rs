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
use std::path::PathBuf;

const LOG_DIR: &str = "logs";
const MAX_LOG_SIZE: u64 = 50 * 1024 * 1024; // 50MB

pub struct Logger {
    log_dir: PathBuf,
    current_log: PathBuf,
}

impl Logger {
    pub fn new() -> Result<Self> {
        Self::with_dir(LOG_DIR)
    }

    pub fn with_dir(dir: &str) -> Result<Self> {
        let log_dir = PathBuf::from(dir);
        fs::create_dir_all(&log_dir)?;
        let current_log = log_dir.join("immunity.jsonl");
        Ok(Self {
            log_dir,
            current_log,
        })
    }

    /// Log a security event
    pub fn log(&self, event: &SecurityEvent) {
        if let Ok(metadata) = fs::metadata(&self.current_log) {
            if metadata.len() > MAX_LOG_SIZE {
                let _ = self.rotate();
            }
        }

        if let Ok(json) = serde_json::to_string(event) {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.current_log)
            {
                let _ = writeln!(file, "{}", json);
            }
        }
    }

    /// Rotate log files when size limit exceeded
    fn rotate(&self) -> Result<()> {
        let ts = Utc::now().format("%Y%m%d_%H%M%S");
        let rotated = self.log_dir.join(format!("immunity_{}.jsonl", ts));
        fs::rename(&self.current_log, rotated)?;
        Ok(())
    }
}
