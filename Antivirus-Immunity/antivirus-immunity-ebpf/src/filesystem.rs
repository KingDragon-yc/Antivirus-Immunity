//! Filesystem Guard — 文件系统护栏
//!
//! 生物学类比：上皮屏障 (Epithelial Barrier)
//! 皮肤和黏膜是抵御病原体的第一道防线，某些区域严格禁止通过。
//! 本模块通过 LSM hooks 保护关键文件和目录不被恶意篡改。
//!
//! eBPF hooks (plan):
//! - LSM/security_file_open: 拦截文件打开操作
//! - LSM/security_inode_create: 拦截文件创建
//! - kprobe/vfs_write: 监控文件写入

/// 文件操作类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    Open,
    Create,
    Write,
    Rename,
    Delete,
    Chmod,
    Chown,
    Link,
    Unlink,
    Mount,
}

/// 访问判定
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny(String),
    AuditOnly(String),
}

/// 受保护路径规则
#[derive(Debug, Clone)]
pub struct ProtectedPath {
    pub path: String,
    pub description: String,
    pub deny_operations: Vec<FileOperation>,
    pub allow_processes: Vec<String>,
    pub is_recursive: bool,
}

/// 文件系统护栏
pub struct FilesystemGuard {
    protected_paths: Vec<ProtectedPath>,
    /// 审计日志: (path, operation, pid, comm, decision)
    audit_log: Vec<AuditEntry>,
    max_audit_entries: usize,
    /// 统计
    total_checks: u64,
    denied_count: u64,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub path: String,
    pub operation: FileOperation,
    pub pid: u32,
    pub comm: String,
    pub decision: String,
    pub timestamp: std::time::Instant,
}

impl FilesystemGuard {
    pub fn new() -> Self {
        let mut guard = Self {
            protected_paths: Vec::new(),
            audit_log: Vec::new(),
            max_audit_entries: 10_000,
            total_checks: 0,
            denied_count: 0,
        };
        guard.load_default_rules();
        guard
    }

    /// 加载默认保护规则（面向 Linux 服务器）
    fn load_default_rules(&mut self) {
        self.protected_paths = vec![
            // 身份 & 认证
            ProtectedPath {
                path: "/etc/shadow".to_string(),
                description: "密码 shadow 文件".to_string(),
                deny_operations: vec![
                    FileOperation::Open,
                    FileOperation::Write,
                    FileOperation::Delete,
                ],
                allow_processes: vec![
                    "passwd".to_string(),
                    "useradd".to_string(),
                    "usermod".to_string(),
                ],
                is_recursive: false,
            },
            ProtectedPath {
                path: "/etc/passwd".to_string(),
                description: "用户数据库".to_string(),
                deny_operations: vec![FileOperation::Write, FileOperation::Delete],
                allow_processes: vec![
                    "passwd".to_string(),
                    "useradd".to_string(),
                    "usermod".to_string(),
                ],
                is_recursive: false,
            },
            ProtectedPath {
                path: "/etc/sudoers".to_string(),
                description: "sudo 配置".to_string(),
                deny_operations: vec![FileOperation::Write, FileOperation::Delete],
                allow_processes: vec!["visudo".to_string()],
                is_recursive: false,
            },
            // SSH
            ProtectedPath {
                path: "/root/.ssh/".to_string(),
                description: "root SSH 密钥目录".to_string(),
                deny_operations: vec![
                    FileOperation::Create,
                    FileOperation::Write,
                    FileOperation::Delete,
                ],
                allow_processes: vec!["ssh-keygen".to_string(), "sshd".to_string()],
                is_recursive: true,
            },
            // 系统启动
            ProtectedPath {
                path: "/etc/crontab".to_string(),
                description: "系统 cron 任务".to_string(),
                deny_operations: vec![FileOperation::Write, FileOperation::Create],
                allow_processes: vec!["crontab".to_string()],
                is_recursive: false,
            },
            ProtectedPath {
                path: "/etc/cron.d/".to_string(),
                description: "cron 配置目录".to_string(),
                deny_operations: vec![
                    FileOperation::Create,
                    FileOperation::Write,
                    FileOperation::Delete,
                ],
                allow_processes: vec!["crontab".to_string()],
                is_recursive: true,
            },
            // 内核
            ProtectedPath {
                path: "/proc/sysrq-trigger".to_string(),
                description: "SysRq 触发器（可导致系统崩溃）".to_string(),
                deny_operations: vec![FileOperation::Write, FileOperation::Open],
                allow_processes: vec![],
                is_recursive: false,
            },
            ProtectedPath {
                path: "/proc/kcore".to_string(),
                description: "内核内存映像".to_string(),
                deny_operations: vec![FileOperation::Open],
                allow_processes: vec![],
                is_recursive: false,
            },
            // 容器运行时
            ProtectedPath {
                path: "/var/run/docker.sock".to_string(),
                description: "Docker 套接字（容器逃逸入口）".to_string(),
                deny_operations: vec![FileOperation::Open, FileOperation::Write],
                allow_processes: vec!["dockerd".to_string(), "containerd".to_string()],
                is_recursive: false,
            },
            // 系统库
            ProtectedPath {
                path: "/lib/x86_64-linux-gnu/".to_string(),
                description: "系统共享库目录".to_string(),
                deny_operations: vec![
                    FileOperation::Write,
                    FileOperation::Create,
                    FileOperation::Delete,
                ],
                allow_processes: vec![
                    "apt".to_string(),
                    "dpkg".to_string(),
                    "yum".to_string(),
                    "rpm".to_string(),
                ],
                is_recursive: true,
            },
        ];
    }

    /// 检查文件访问是否允许
    pub fn check_access(
        &mut self,
        path: &str,
        operation: FileOperation,
        pid: u32,
        comm: &str,
    ) -> AccessDecision {
        self.total_checks += 1;

        for rule in &self.protected_paths {
            let matches = if rule.is_recursive {
                path.starts_with(&rule.path)
            } else {
                path == rule.path
            };

            if !matches {
                continue;
            }

            if !rule.deny_operations.contains(&operation) {
                continue;
            }

            // 检查白名单进程
            if rule.allow_processes.iter().any(|p| comm.contains(p)) {
                let decision = AccessDecision::AuditOnly(format!(
                    "Whitelisted process '{}' accessing protected path '{}'",
                    comm, rule.path
                ));
                self.record_audit(path, operation, pid, comm, &decision);
                return decision;
            }

            // 拒绝
            self.denied_count += 1;
            let decision = AccessDecision::Deny(format!(
                "BLOCKED: {} on '{}' by '{}' (pid:{}) — {}",
                format!("{:?}", operation),
                path,
                comm,
                pid,
                rule.description
            ));
            self.record_audit(path, operation, pid, comm, &decision);
            return decision;
        }

        AccessDecision::Allow
    }

    /// 添加自定义保护规则
    pub fn add_rule(&mut self, rule: ProtectedPath) {
        self.protected_paths.push(rule);
    }

    /// 清除所有自定义规则（保留默认规则）
    pub fn reset_rules(&mut self) {
        self.protected_paths.clear();
        self.load_default_rules();
    }

    /// 记录审计
    fn record_audit(
        &mut self,
        path: &str,
        operation: FileOperation,
        pid: u32,
        comm: &str,
        decision: &AccessDecision,
    ) {
        let entry = AuditEntry {
            path: path.to_string(),
            operation,
            pid,
            comm: comm.to_string(),
            decision: format!("{:?}", decision),
            timestamp: std::time::Instant::now(),
        };
        self.audit_log.push(entry);
        if self.audit_log.len() > self.max_audit_entries {
            self.audit_log.drain(0..self.max_audit_entries / 2);
        }
    }

    /// 获取最近的审计条目
    pub fn recent_audit(&self, count: usize) -> &[AuditEntry] {
        let start = if self.audit_log.len() > count {
            self.audit_log.len() - count
        } else {
            0
        };
        &self.audit_log[start..]
    }

    /// 获取统计信息
    pub fn stats(&self) -> String {
        format!(
            "Filesystem Guard: {} rules, {} checks, {} denied, {} audit entries",
            self.protected_paths.len(),
            self.total_checks,
            self.denied_count,
            self.audit_log.len()
        )
    }
}
