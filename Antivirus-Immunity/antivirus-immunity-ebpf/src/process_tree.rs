//! Process Tree — 进程族谱追踪
//!
//! 生物学类比：抗原呈递 (Antigen Presentation)
//! 免疫系统需要追踪抗原的来源链。本模块构建进程父子关系图谱，
//! 用于：
//! - 区分 AI Agent 合法子进程 vs 外部入侵
//! - 追溯攻击链（从 nginx → sh → wget → malware）
//! - 容器逃逸检测（容器内进程的父进程不在容器内）

use std::collections::HashMap;

/// 进程族谱
pub struct ProcessTree {
    /// pid → (ppid, comm)
    tree: HashMap<u32, (u32, String)>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            tree: HashMap::new(),
        }
    }

    /// 记录一个进程的父子关系
    pub fn record(&mut self, pid: u32, ppid: u32, comm: &str) {
        self.tree.insert(pid, (ppid, comm.to_string()));
    }

    /// 清理已退出的进程
    pub fn remove(&mut self, pid: u32) {
        self.tree.remove(&pid);
    }

    /// 获取进程祖先链（最多 16 层，防止循环）
    pub fn get_ancestry(&self, pid: u32) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = pid;
        let mut depth = 0;

        while depth < 16 {
            if let Some((ppid, comm)) = self.tree.get(&current) {
                chain.push(format!("{} ({})", comm, current));
                if *ppid == 0 || *ppid == current {
                    break;
                }
                current = *ppid;
            } else {
                // Try to read from /proc as fallback (read-only, no cache mutation)
                #[cfg(target_os = "linux")]
                {
                    if let Some((ppid, comm)) = Self::read_proc_parent(current) {
                        chain.push(format!("{} ({})", comm, current));
                        if ppid == 0 || ppid == current {
                            break;
                        }
                        current = ppid;
                    } else {
                        break;
                    }
                }
                #[cfg(not(target_os = "linux"))]
                break;
            }
            depth += 1;
        }

        chain.reverse();
        chain
    }

    #[cfg(target_os = "linux")]
    fn read_proc_parent(pid: u32) -> Option<(u32, String)> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string();

        // Parse ppid from /proc/pid/stat
        let parts: Vec<&str> = stat.splitn(5, ' ').collect();
        let ppid = parts.get(3)?.parse().ok()?;

        Some((ppid, comm))
    }
}
