//! Container Context — Docker/K8s 容器上下文感知
//!
//! 生物学类比：组织定位 (Tissue Homing)
//! 免疫细胞能够感知自己处于哪个组织器官中，并据此调整行为。
//! 本模块通过读取 cgroup/namespace 信息，将进程映射到具体的容器/Pod。

use std::collections::HashMap;

/// 支持的容器运行时
#[derive(Debug, Clone)]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    Podman,
    None,
}

pub struct ContainerContext {
    runtime: ContainerRuntime,
    /// PID → Container ID cache
    pid_cache: HashMap<u32, String>,
}

impl ContainerContext {
    /// 自动检测当前系统的容器运行时
    pub fn detect() -> Self {
        let runtime = Self::detect_runtime();
        Self {
            runtime,
            pid_cache: HashMap::new(),
        }
    }

    fn detect_runtime() -> ContainerRuntime {
        #[cfg(target_os = "linux")]
        {
            use std::path::Path;
            if Path::new("/var/run/docker.sock").exists() {
                return ContainerRuntime::Docker;
            }
            if Path::new("/run/containerd/containerd.sock").exists() {
                return ContainerRuntime::Containerd;
            }
            if Path::new("/run/podman/podman.sock").exists() {
                return ContainerRuntime::Podman;
            }
        }
        ContainerRuntime::None
    }

    pub fn runtime_name(&self) -> &str {
        match &self.runtime {
            ContainerRuntime::Docker => "Docker",
            ContainerRuntime::Containerd => "containerd (K8s)",
            ContainerRuntime::Podman => "Podman",
            ContainerRuntime::None => "None (bare metal)",
        }
    }

    /// 通过 /proc/<pid>/cgroup 解析容器 ID
    pub fn resolve_container(&self, pid: u32) -> Option<String> {
        // Check cache first
        if let Some(id) = self.pid_cache.get(&pid) {
            return Some(id.clone());
        }

        #[cfg(target_os = "linux")]
        {
            return self.parse_cgroup_container_id(pid);
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_cgroup_container_id(&self, pid: u32) -> Option<String> {
        let cgroup_content = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;

        for line in cgroup_content.lines() {
            // Docker cgroup format: 0::/docker/<container_id>
            // K8s:                  0::/kubepods/besteffort/pod<id>/<container_id>
            // containerd:           0::/system.slice/containerd.service/kubepods/.../<id>
            if let Some(docker_pos) = line.find("/docker/") {
                let id_start = docker_pos + "/docker/".len();
                let id = &line[id_start..];
                if id.len() >= 12 {
                    return Some(id[..12].to_string());
                }
            }

            // kubepods path — last segment is container ID
            if line.contains("kubepods") {
                if let Some(last_slash) = line.rfind('/') {
                    let segment = &line[last_slash + 1..];
                    if segment.len() >= 12 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(segment[..12].to_string());
                    }
                }
            }
        }

        None
    }
}
