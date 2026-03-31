//! antivirus-immunity-common — 跨平台共享模块
//!
//! 包含 Windows 和 Linux 版本共享的核心类型与工具：
//! - SecurityEvent / Logger (JSONL 结构化日志)
//! - AI Cortex (Ollama 本地 LLM 接口)
//! - Process / Event 通用类型定义
//! - 哈希缓存

pub mod ai_cortex;
pub mod event;
pub mod hash_cache;
pub mod logger;
