//! Resource Awareness — 硬件感知与 Lite 模式
//!
//! 生物学类比：新陈代谢调节 (Metabolic Regulation)
//! 当营养不足时，生物体会进入"节能模式"，关闭非必要的代谢通路。
//! 本模块检测当前主机的硬件资源（CPU、内存），当资源不足时自动切换
//! 到 Lite 模式 —— 仅保留核心 eBPF 进程监控，关闭重量级分析（AI、
//! 文件深度扫描、网络全量捕获等）。
//!
//! 适用场景：1C1G / 2C2G 的轻量云实例

/// 硬件概况
#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub cpu_count: usize,
    pub memory_mb: u64,
    pub kernel_version: String,
    pub hostname: String,
}

impl HardwareProfile {
    /// 判断是否应切换到 Lite 模式
    /// 阈值: < 2 核 或 < 4096 MB 内存 视为轻量实例
    pub fn should_use_lite_mode(&self, memory_budget_mb: u64) -> bool {
        self.cpu_count < 2 || self.memory_mb < 4096 || memory_budget_mb < 50
    }
}

/// 检测当前硬件环境
pub fn detect_hardware() -> HardwareProfile {
    let cpu_count = detect_cpu_count();
    let memory_mb = detect_memory_mb();
    let kernel_version = detect_kernel_version();
    let hostname = detect_hostname();

    HardwareProfile {
        cpu_count,
        memory_mb,
        kernel_version,
        hostname,
    }
}

fn detect_cpu_count() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.matches("processor").count())
            .unwrap_or(1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}

fn detect_memory_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                for line in s.lines() {
                    if line.starts_with("MemTotal:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(kb_str) = parts.get(1) {
                            return kb_str.parse::<u64>().ok().map(|kb| kb / 1024);
                        }
                    }
                }
                None
            })
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: assume 4GB
        4096
    }
}

fn detect_kernel_version() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .split_whitespace()
            .nth(2)
            .unwrap_or("unknown")
            .to_string()
    }
    #[cfg(not(target_os = "linux"))]
    {
        "non-linux".to_string()
    }
}

fn detect_hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/hostname")
            .unwrap_or_default()
            .trim()
            .to_string()
    }
    #[cfg(not(target_os = "linux"))]
    {
        "localhost".to_string()
    }
}
