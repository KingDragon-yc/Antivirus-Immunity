//! Policy Engine — 安全策略引擎
//!
//! 生物学类比：适应性免疫记忆 + 危险理论
//! 根据预设策略和运行时上下文，对探针事件进行研判。
//!
//! 策略配置文件 (profiles):
//! - server: 标准服务器防护
//! - container: Docker/K8s 容器重点防护
//! - ai-agent: AI Agent 沙盒护栏（宽松执行 + 严格边界）

use crate::probe::{ProbeType, RawProbeEvent};
use antivirus_immunity_common::event::{ResponseAction, Severity};
use std::collections::HashSet;

/// 策略评估结果
#[derive(Debug, Clone)]
pub struct PolicyVerdict {
    pub action: ResponseAction,
    pub severity: Severity,
    pub reason: String,
}

/// 安全策略引擎
pub struct PolicyEngine {
    profile: String,
    mode: String,
    protected_paths: HashSet<String>,
    whitelist_comms: HashSet<String>,
    /// 已知恶意的目标地址/端口（挖矿池、C2 etc.）
    blacklist_networks: Vec<NetworkRule>,
}

#[derive(Debug, Clone)]
struct NetworkRule {
    description: String,
    port: Option<u16>,
    addr_pattern: Option<String>,
}

impl PolicyEngine {
    pub fn new(
        profile: &str,
        mode: &str,
        protected_paths: Vec<String>,
        _whitelist_path: Option<&str>,
    ) -> Self {
        let mut whitelist_comms = HashSet::new();
        // Default whitelist — common legitimate cloud processes
        for comm in &[
            "sshd",
            "systemd",
            "dockerd",
            "containerd",
            "containerd-shim",
            "kubelet",
            "kube-proxy",
            "etcd",
            "nginx",
            "apache2",
            "httpd",
            "mysqld",
            "postgres",
            "redis-server",
            "mongod",
            "node",
            "python3",
            "python",
            "java",
            "go",
            "cron",
            "rsyslogd",
            "journald",
            "NetworkManager",
        ] {
            whitelist_comms.insert(comm.to_string());
        }

        // AI Agent profile adds more permissive entries
        if profile == "ai-agent" {
            for comm in &[
                "pip", "pip3", "npm", "npx", "cargo", "rustc", "gcc", "g++", "make", "cmake",
                "git", "curl", "wget",
            ] {
                whitelist_comms.insert(comm.to_string());
            }
        }

        let blacklist_networks = vec![
            NetworkRule {
                description: "Common mining pool port (stratum)".to_string(),
                port: Some(3333),
                addr_pattern: None,
            },
            NetworkRule {
                description: "Mining pool port (stratum+ssl)".to_string(),
                port: Some(4444),
                addr_pattern: None,
            },
            NetworkRule {
                description: "Mining pool port".to_string(),
                port: Some(14444),
                addr_pattern: None,
            },
            NetworkRule {
                description: "Common C2 / reverse shell port".to_string(),
                port: Some(4445),
                addr_pattern: None,
            },
        ];

        Self {
            profile: profile.to_string(),
            mode: mode.to_string(),
            protected_paths: protected_paths.into_iter().collect(),
            whitelist_comms,
            blacklist_networks,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.whitelist_comms.len() + self.blacklist_networks.len()
    }

    pub fn protected_path_count(&self) -> usize {
        self.protected_paths.len()
    }

    /// 评估一个探针事件
    pub fn evaluate(
        &self,
        event: &RawProbeEvent,
        container_id: Option<&str>,
        parent_chain: &[String],
    ) -> PolicyVerdict {
        match &event.event_type {
            ProbeType::Execve => self.evaluate_exec(event, container_id, parent_chain),

            ProbeType::TcpConnect { dst_addr, dst_port } => {
                self.evaluate_network(event, dst_addr, *dst_port, container_id)
            }

            ProbeType::UdpSend { dst_addr, dst_port } => {
                self.evaluate_network(event, dst_addr, *dst_port, container_id)
            }

            ProbeType::FileOpen { file_path } | ProbeType::InodeCreate { file_path } => {
                self.evaluate_file_access(event, file_path, container_id)
            }

            ProbeType::CredChange { old_uid, new_uid } => {
                self.evaluate_cred_change(event, *old_uid, *new_uid, container_id)
            }

            ProbeType::Exit => PolicyVerdict {
                action: ResponseAction::Log,
                severity: Severity::Info,
                reason: "Process exit".to_string(),
            },
        }
    }

    /// 评估进程执行事件
    fn evaluate_exec(
        &self,
        event: &RawProbeEvent,
        container_id: Option<&str>,
        parent_chain: &[String],
    ) -> PolicyVerdict {
        // Whitelisted?
        if self.whitelist_comms.contains(&event.comm) {
            return PolicyVerdict {
                action: ResponseAction::Log,
                severity: Severity::Info,
                reason: "Whitelisted process".to_string(),
            };
        }

        // AI Agent profile: check if parent chain is legitimate
        if self.profile == "ai-agent" {
            let has_agent_parent = parent_chain
                .iter()
                .any(|p| p.contains("python") || p.contains("node") || p.contains("agent"));
            if has_agent_parent {
                // AI Agent spawning sub-processes — expected behavior
                return PolicyVerdict {
                    action: ResponseAction::Monitor,
                    severity: Severity::Low,
                    reason: "AI Agent child process — monitoring boundary".to_string(),
                };
            }
        }

        // Inside a container?
        if container_id.is_some() {
            // Suspicious: reverse shell-like patterns
            if event.comm == "sh" || event.comm == "bash" || event.comm == "dash" {
                if parent_chain
                    .iter()
                    .any(|p| p.contains("python") || p.contains("perl") || p.contains("ruby"))
                {
                    return PolicyVerdict {
                        action: if self.mode == "enforce" {
                            ResponseAction::Terminate
                        } else {
                            ResponseAction::Monitor
                        },
                        severity: Severity::High,
                        reason: "Shell spawned from scripting runtime inside container".to_string(),
                    };
                }
            }
        }

        // Unknown process — default
        PolicyVerdict {
            action: ResponseAction::Monitor,
            severity: Severity::Medium,
            reason: format!("Unknown process: {}", event.comm),
        }
    }

    /// 评估网络事件
    fn evaluate_network(
        &self,
        event: &RawProbeEvent,
        dst_addr: &str,
        dst_port: u16,
        _container_id: Option<&str>,
    ) -> PolicyVerdict {
        // Check blacklisted ports
        for rule in &self.blacklist_networks {
            if let Some(port) = rule.port {
                if port == dst_port {
                    return PolicyVerdict {
                        action: if self.mode == "enforce" {
                            ResponseAction::BlockAccess
                        } else {
                            ResponseAction::Monitor
                        },
                        severity: Severity::Critical,
                        reason: format!(
                            "{}:{} — {}: {}",
                            dst_addr, dst_port, rule.description, event.comm,
                        ),
                    };
                }
            }
        }

        // Reverse shell detection: outbound to unusual ports with shell parent
        if dst_port > 1024 && (event.comm == "bash" || event.comm == "sh" || event.comm == "nc") {
            return PolicyVerdict {
                action: if self.mode == "enforce" {
                    ResponseAction::BlockAccess
                } else {
                    ResponseAction::Monitor
                },
                severity: Severity::High,
                reason: format!(
                    "Possible reverse shell: {} connecting to {}:{}",
                    event.comm, dst_addr, dst_port,
                ),
            };
        }

        PolicyVerdict {
            action: ResponseAction::Log,
            severity: Severity::Info,
            reason: format!("Network: {} → {}:{}", event.comm, dst_addr, dst_port),
        }
    }

    /// 评估文件访问事件
    fn evaluate_file_access(
        &self,
        event: &RawProbeEvent,
        file_path: &str,
        _container_id: Option<&str>,
    ) -> PolicyVerdict {
        // Check protected paths
        for protected in &self.protected_paths {
            if file_path.starts_with(protected.as_str()) {
                // In AI Agent profile: BLOCK but don't KILL
                let action = if self.mode == "enforce" {
                    ResponseAction::BlockAccess
                } else {
                    ResponseAction::Monitor
                };

                return PolicyVerdict {
                    action,
                    severity: Severity::Critical,
                    reason: format!(
                        "SENSITIVE FILE ACCESS: {} tried to access {}",
                        event.comm, file_path,
                    ),
                };
            }
        }

        PolicyVerdict {
            action: ResponseAction::Log,
            severity: Severity::Info,
            reason: format!("File: {} accessed {}", event.comm, file_path),
        }
    }

    /// 评估提权事件
    fn evaluate_cred_change(
        &self,
        event: &RawProbeEvent,
        old_uid: u32,
        new_uid: u32,
        container_id: Option<&str>,
    ) -> PolicyVerdict {
        // uid changed to 0 (root) — potential privilege escalation
        if new_uid == 0 && old_uid != 0 {
            let severity = if container_id.is_some() {
                Severity::Critical // Inside container = possible escape
            } else {
                Severity::High
            };

            let reason = if container_id.is_some() {
                format!(
                    "CONTAINER PRIVILEGE ESCALATION: {} (uid {} → root)",
                    event.comm, old_uid,
                )
            } else {
                format!(
                    "PRIVILEGE ESCALATION: {} (uid {} → root)",
                    event.comm, old_uid,
                )
            };

            return PolicyVerdict {
                action: if self.mode == "enforce" {
                    ResponseAction::Terminate
                } else {
                    ResponseAction::Monitor
                },
                severity,
                reason,
            };
        }

        PolicyVerdict {
            action: ResponseAction::Log,
            severity: Severity::Info,
            reason: format!("Cred change: {} uid {} → {}", event.comm, old_uid, new_uid),
        }
    }
}
