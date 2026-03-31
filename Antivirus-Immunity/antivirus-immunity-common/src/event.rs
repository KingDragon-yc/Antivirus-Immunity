//! Common Event Types — 跨平台安全事件定义
//!
//! 统一的事件类型，供 Windows (ToolHelp32) 和 Linux (eBPF) 后端共用。
//! eBPF 探针在内核态产生原始事件，用户态将其转换为此处定义的通用格式。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 通用进程信息 — 平台无关
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub hash: Option<String>,
    /// Linux: 从 /proc/<pid>/cmdline 读取的完整命令行
    pub cmdline: Option<String>,
    /// Linux: uid/gid
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Linux: 容器上下文（cgroup id / namespace id）
    pub container_id: Option<String>,
    pub namespace_pid: Option<u32>,
}

/// eBPF 原始事件类型 — 内核探针产生
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeEventType {
    /// 进程启动 (tracepoint/syscalls/sys_enter_execve)
    ProcessExec,
    /// 进程退出
    ProcessExit,
    /// TCP 外联 (kprobe/tcp_connect)
    TcpConnect,
    /// UDP 发送 (kprobe/udp_sendmsg)
    UdpSend,
    /// 文件打开 (LSM/security_file_open)
    FileOpen,
    /// inode 创建 (LSM/security_inode_create)
    InodeCreate,
    /// 提权检测 (kprobe/commit_creds)
    CredChange,
}

/// 网络事件上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub comm: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub protocol: String,
    pub container_id: Option<String>,
}

/// 文件系统事件上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub pid: u32,
    pub comm: String,
    pub file_path: String,
    pub operation: FileOperation,
    pub blocked: bool,
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileOperation {
    Open,
    Create,
    Write,
    Delete,
    Rename,
}

/// 提权事件上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredChangeEvent {
    pub pid: u32,
    pub comm: String,
    pub old_uid: u32,
    pub new_uid: u32,
    pub old_euid: u32,
    pub new_euid: u32,
    pub container_id: Option<String>,
}

/// 安全事件 — 所有子系统最终输出的统一格式
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: Severity,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub container_id: Option<String>,
    pub detail: String,
    pub action_taken: Option<String>,
    pub ai_verdict: Option<String>,
    pub danger_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    ProcessExec,
    ProcessTerminated,
    ThreatDetected,
    ThreatBlocked,
    NetworkBlocked,
    FileAccessBlocked,
    PrivilegeEscalation,
    ContainerEscape,
    DangerSignal,
    AiAnalysis,
    SystemStart,
    SystemStop,
    LearningComplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// 评估结果 — 免疫决策层输出
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Assessment {
    /// 安全 — 可信哈希 + 路径验证通过
    Safe,
    /// 确认恶意 — YARA 命中 / 路径伪装 / 已知恶意行为
    Critical(String),
    /// 可疑 — 需要关注但不确定
    Suspicious(String),
    /// 未知 — 信息不足
    Unknown,
    /// 需要 AI 深度分析
    NeedsAiReview(String),
    /// eBPF LSM 已直接阻断（返回 -EPERM）
    Blocked(String),
}

/// 响应动作
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    /// 仅记录
    Log,
    /// 监控 — 提高关注等级
    Monitor,
    /// 终止进程 (kill -9)
    Terminate,
    /// 隔离文件 + 终止
    QuarantineAndTerminate,
    /// eBPF 内核级阻断（返回 -EPERM，不杀进程）
    BlockAccess,
}

/// 危险等级
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DangerLevel {
    Normal,
    Elevated,
    High,
    Critical,
}
