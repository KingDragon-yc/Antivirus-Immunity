#![allow(dead_code)]
//! Danger Theory Engine — 危险信号理论引擎
//!
//! 生物学类比：危险理论 (Danger Theory) 由 Polly Matzinger 提出，
//! 认为免疫系统的激活不仅依赖"自我/非自我"识别，更依赖"危险信号"——
//! 即受损细胞释放的警报分子 (DAMPs)。
//!
//! 在本系统中，我们监测的"危险信号"包括：
//! - CPU 使用率突然飙升 (可能是挖矿或加密)
//! - 短时间内大量文件被修改/重命名 (勒索软件行为)
//! - 内存使用异常
//! - 大量新进程短时间内创建 (Fork bomb / 进程注入)

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use sysinfo::System;

/// Danger signal severity level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DangerLevel {
    /// No abnormal signals detected
    Normal,
    /// Minor anomalies, increased monitoring warranted
    Elevated,
    /// Significant danger signals, heightened immune response needed
    High,
    /// Critical system stress, immediate response required
    Critical,
}

/// A single danger signal event
#[derive(Debug, Clone)]
pub struct DangerSignal {
    pub signal_type: SignalType,
    pub level: DangerLevel,
    pub description: String,
    pub timestamp: Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SignalType {
    CpuSpike,
    MemoryPressure,
    ProcessFlood,
    // Future: FileRenameStorm, NetworkAnomaly, RegistryFlood
}

/// Configuration thresholds for danger detection
#[derive(Debug, Clone)]
pub struct DangerThresholds {
    /// CPU usage percentage above which triggers alert
    pub cpu_elevated: f32,
    pub cpu_high: f32,
    pub cpu_critical: f32,
    /// Memory usage percentage thresholds
    pub mem_elevated: f64,
    pub mem_high: f64,
    pub mem_critical: f64,
    /// Number of new processes in the observation window that triggers alert
    pub proc_flood_elevated: usize,
    pub proc_flood_high: usize,
    pub proc_flood_critical: usize,
    /// Time window for process flood detection
    pub proc_flood_window: Duration,
}

impl Default for DangerThresholds {
    fn default() -> Self {
        Self {
            cpu_elevated: 70.0,
            cpu_high: 85.0,
            cpu_critical: 95.0,
            mem_elevated: 80.0,
            mem_high: 90.0,
            mem_critical: 95.0,
            proc_flood_elevated: 20,
            proc_flood_high: 50,
            proc_flood_critical: 100,
            proc_flood_window: Duration::from_secs(10),
        }
    }
}

/// The Danger Theory engine that monitors system-level stress signals.
/// Think of this as the body's inflammatory response system.
pub struct DangerTheoryEngine {
    sys: System,
    thresholds: DangerThresholds,
    /// Recent process creation timestamps for flood detection
    recent_process_events: VecDeque<Instant>,
    /// History of danger signals for trend analysis
    signal_history: VecDeque<DangerSignal>,
    /// Current aggregate danger level
    current_level: DangerLevel,
    /// Last time CPU was refreshed
    last_cpu_refresh: Option<Instant>,
}

impl DangerTheoryEngine {
    pub fn new() -> Self {
        Self::with_thresholds(DangerThresholds::default())
    }

    pub fn with_thresholds(thresholds: DangerThresholds) -> Self {
        Self {
            sys: System::new_all(),
            thresholds,
            recent_process_events: VecDeque::new(),
            signal_history: VecDeque::new(),
            current_level: DangerLevel::Normal,
            last_cpu_refresh: None,
        }
    }

    /// Record that a new process was detected (for flood detection)
    pub fn record_process_creation(&mut self) {
        self.recent_process_events.push_back(Instant::now());
    }

    /// Perform a full danger assessment. Call this periodically in the main loop.
    pub fn assess(&mut self) -> Vec<DangerSignal> {
        let mut signals = Vec::new();

        // Refresh system info (CPU needs two refreshes with a gap for meaningful values)
        let now = Instant::now();
        let should_read_cpu = self
            .last_cpu_refresh
            .map(|t| now.duration_since(t) > Duration::from_millis(500))
            .unwrap_or(true);

        self.sys.refresh_memory();
        self.sys.refresh_cpu_usage();
        self.last_cpu_refresh = Some(now);

        if should_read_cpu {
            // 1. CPU Check
            let cpu_usage = self.sys.global_cpu_usage();
            if cpu_usage >= self.thresholds.cpu_critical {
                signals.push(DangerSignal {
                    signal_type: SignalType::CpuSpike,
                    level: DangerLevel::Critical,
                    description: format!(
                        "CPU at {:.1}% — possible cryptominer or encryption activity",
                        cpu_usage
                    ),
                    timestamp: now,
                });
            } else if cpu_usage >= self.thresholds.cpu_high {
                signals.push(DangerSignal {
                    signal_type: SignalType::CpuSpike,
                    level: DangerLevel::High,
                    description: format!("CPU at {:.1}% — elevated processing detected", cpu_usage),
                    timestamp: now,
                });
            } else if cpu_usage >= self.thresholds.cpu_elevated {
                signals.push(DangerSignal {
                    signal_type: SignalType::CpuSpike,
                    level: DangerLevel::Elevated,
                    description: format!("CPU at {:.1}% — above normal baseline", cpu_usage),
                    timestamp: now,
                });
            }
        }

        // 2. Memory Check
        let total_mem = self.sys.total_memory() as f64;
        let used_mem = self.sys.used_memory() as f64;
        if total_mem > 0.0 {
            let mem_pct = (used_mem / total_mem) * 100.0;
            if mem_pct >= self.thresholds.mem_critical {
                signals.push(DangerSignal {
                    signal_type: SignalType::MemoryPressure,
                    level: DangerLevel::Critical,
                    description: format!("Memory at {:.1}% — extreme memory pressure", mem_pct),
                    timestamp: now,
                });
            } else if mem_pct >= self.thresholds.mem_high {
                signals.push(DangerSignal {
                    signal_type: SignalType::MemoryPressure,
                    level: DangerLevel::High,
                    description: format!("Memory at {:.1}% — high memory usage", mem_pct),
                    timestamp: now,
                });
            } else if mem_pct >= self.thresholds.mem_elevated {
                signals.push(DangerSignal {
                    signal_type: SignalType::MemoryPressure,
                    level: DangerLevel::Elevated,
                    description: format!("Memory at {:.1}% — above normal", mem_pct),
                    timestamp: now,
                });
            }
        }

        // 3. Process Flood Check
        // Prune old events outside the window
        let window_start = now - self.thresholds.proc_flood_window;
        while self
            .recent_process_events
            .front()
            .map_or(false, |t| *t < window_start)
        {
            self.recent_process_events.pop_front();
        }
        let proc_count = self.recent_process_events.len();
        if proc_count >= self.thresholds.proc_flood_critical {
            signals.push(DangerSignal {
                signal_type: SignalType::ProcessFlood,
                level: DangerLevel::Critical,
                description: format!(
                    "{} new processes in {:.0}s — possible fork bomb or mass injection",
                    proc_count,
                    self.thresholds.proc_flood_window.as_secs_f64()
                ),
                timestamp: now,
            });
        } else if proc_count >= self.thresholds.proc_flood_high {
            signals.push(DangerSignal {
                signal_type: SignalType::ProcessFlood,
                level: DangerLevel::High,
                description: format!(
                    "{} new processes in {:.0}s — abnormal spawning rate",
                    proc_count,
                    self.thresholds.proc_flood_window.as_secs_f64()
                ),
                timestamp: now,
            });
        } else if proc_count >= self.thresholds.proc_flood_elevated {
            signals.push(DangerSignal {
                signal_type: SignalType::ProcessFlood,
                level: DangerLevel::Elevated,
                description: format!(
                    "{} new processes in {:.0}s — above normal rate",
                    proc_count,
                    self.thresholds.proc_flood_window.as_secs_f64()
                ),
                timestamp: now,
            });
        }

        // Update aggregate danger level
        self.current_level = self.aggregate_level(&signals);

        // Store in history (keep last 1000)
        for s in &signals {
            self.signal_history.push_back(s.clone());
        }
        while self.signal_history.len() > 1000 {
            self.signal_history.pop_front();
        }

        signals
    }

    /// Get the current aggregate danger level
    pub fn current_level(&self) -> &DangerLevel {
        &self.current_level
    }

    /// Determine overall danger level from a set of signals
    fn aggregate_level(&self, signals: &[DangerSignal]) -> DangerLevel {
        let mut max_level = DangerLevel::Normal;
        for s in signals {
            match s.level {
                DangerLevel::Critical => return DangerLevel::Critical,
                DangerLevel::High => max_level = DangerLevel::High,
                DangerLevel::Elevated => {
                    if max_level == DangerLevel::Normal {
                        max_level = DangerLevel::Elevated;
                    }
                }
                _ => {}
            }
        }
        max_level
    }

    /// Get a summary string for display
    pub fn status_summary(&self) -> String {
        let level_str = match &self.current_level {
            DangerLevel::Normal => "🟢 NORMAL",
            DangerLevel::Elevated => "🟡 ELEVATED",
            DangerLevel::High => "🟠 HIGH",
            DangerLevel::Critical => "🔴 CRITICAL",
        };
        format!("Danger Level: {}", level_str)
    }
}
