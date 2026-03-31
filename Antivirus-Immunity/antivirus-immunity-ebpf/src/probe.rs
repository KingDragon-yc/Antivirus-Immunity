//! Probe Manager — eBPF 探针管理
//!
//! 生物学类比：Toll 样受体 (TLR) — 先天免疫的传感器
//! 
//! 在完整 Linux 构建中，此模块负责：
//! 1. 加载 CO-RE eBPF 对象 (.bpf.o)
//! 2. Attach 到内核挂载点 (tracepoints, kprobes, LSM hooks)
//! 3. 通过 BPF Ring Buffer 接收内核事件
//!
//! 在开发/回退模式下，通过 /proc 轮询模拟事件流。

use anyhow::Result;
use std::collections::HashSet;

/// 从内核探针接收的原始事件
#[derive(Debug, Clone)]
pub struct RawProbeEvent {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub path: String,
    pub event_type: ProbeType,
    pub detail: String,
    /// Cgroup ID for container mapping
    pub cgroup_id: u64,
    /// PID namespace ID
    pub ns_pid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeType {
    Execve,
    Exit,
    TcpConnect { dst_addr: String, dst_port: u16 },
    UdpSend { dst_addr: String, dst_port: u16 },
    FileOpen { file_path: String },
    InodeCreate { file_path: String },
    CredChange { old_uid: u32, new_uid: u32 },
}

pub struct ProbeManager {
    lite_mode: bool,
    known_pids: HashSet<u32>,
    // In production: BPF object handles, ring buffer consumer, maps
    // bpf_obj: Option<libbpf_rs::Object>,
    // ring_buf: Option<libbpf_rs::RingBuffer>,
}

impl ProbeManager {
    pub fn new(lite_mode: bool) -> Result<Self> {
        // In production Linux build:
        // 1. Open the compiled BPF object
        //    let obj = libbpf_rs::ObjectBuilder::default()
        //        .open_file("probes/immunity.bpf.o")?
        //        .load()?;
        // 2. Attach probes
        //    obj.prog("handle_execve")?.attach()?;
        //    obj.prog("handle_tcp_connect")?.attach()?;
        //    if !lite_mode {
        //        obj.prog("handle_file_open")?.attach()?;
        //        obj.prog("handle_cred_change")?.attach()?;
        //    }
        // 3. Set up ring buffer
        //    let ring_buf = libbpf_rs::RingBufferBuilder::new()
        //        .add(obj.map("events")?, callback)?
        //        .build()?;

        Ok(Self {
            lite_mode,
            known_pids: HashSet::new(),
        })
    }

    /// Poll for new events.
    /// In production: ring_buf.poll(timeout)
    /// In dev mode: /proc-based polling
    pub fn poll_events(&mut self) -> Result<Vec<RawProbeEvent>> {
        // Development fallback: read from /proc
        self.poll_proc_fallback()
    }

    /// /proc-based fallback for development on non-eBPF systems
    fn poll_proc_fallback(&mut self) -> Result<Vec<RawProbeEvent>> {
        #[allow(unused_mut)]
        let mut events = Vec::new();
        #[allow(unused_mut)]
        let mut current_pids = HashSet::new();

        // Read /proc to discover running processes
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Ok(pid) = name_str.parse::<u32>() {
                        current_pids.insert(pid);
                        if !self.known_pids.contains(&pid) {
                            // New process detected
                            let comm = Self::read_proc_comm(pid);
                            let path = Self::read_proc_exe(pid);
                            let ppid = Self::read_proc_ppid(pid);
                            let cgroup_id = Self::read_proc_cgroup_id(pid);

                            events.push(RawProbeEvent {
                                pid,
                                ppid,
                                comm: comm.clone(),
                                path: path.clone(),
                                event_type: ProbeType::Execve,
                                detail: format!("exec: {} ({})", comm, path),
                                cgroup_id,
                                ns_pid: pid,
                            });
                        }
                    }
                }
            }
        }

        // On non-Linux (development): generate empty
        #[cfg(not(target_os = "linux"))]
        {
            // No-op on Windows/macOS dev machines
        }

        self.known_pids = current_pids;
        Ok(events)
    }

    #[cfg(target_os = "linux")]
    fn read_proc_comm(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    #[cfg(target_os = "linux")]
    fn read_proc_exe(pid: u32) -> String {
        std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    #[cfg(target_os = "linux")]
    fn read_proc_ppid(pid: u32) -> u32 {
        std::fs::read_to_string(format!("/proc/{}/stat", pid))
            .ok()
            .and_then(|s| {
                // /proc/pid/stat format: pid (comm) state ppid ...
                let parts: Vec<&str> = s.splitn(5, ' ').collect();
                parts.get(3)?.parse().ok()
            })
            .unwrap_or(0)
    }

    #[cfg(target_os = "linux")]
    fn read_proc_cgroup_id(pid: u32) -> u64 {
        // Read cgroup path to derive container ID
        std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
            .ok()
            .and_then(|s| {
                // Hash the cgroup path as a rough ID
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                s.hash(&mut hasher);
                Some(hasher.finish())
            })
            .unwrap_or(0)
    }
}
