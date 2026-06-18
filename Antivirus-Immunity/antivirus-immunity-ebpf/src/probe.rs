//! Probe Manager — eBPF 探针管理
//!
//! 生物学类比：Toll 样受体 (TLR) — 先天免疫的传感器
//!
//! 在完整 Linux 构建中，此模块负责：
//! 1. 加载 CO-RE eBPF 对象 (.bpf.o)
//! 2. Attach 到内核挂载点 (tracepoints, kprobes, LSM hooks)
//! 3. 通过 BPF Ring Buffer 接收内核事件
//!
//! Fallback 优先级（自动降级）:
//!   1. eBPF Ring Buffer (生产模式)
//!   2. Netlink Connector (无 eBPF，内核推送，零轮询，毫秒级延迟)
//!   3. /proc 轮询 (最终兜底，兼容非常老的内核)

#[cfg(target_os = "linux")]
use crate::netlink_connector::NetlinkConnector;
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
    /// Netlink Connector socket — preferred fallback for non-eBPF systems.
    /// If None, falls through to /proc polling.
    #[cfg(target_os = "linux")]
    netlink: Option<NetlinkConnector>,
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

        // Try to initialize Netlink Connector for zero-polling process events
        #[cfg(target_os = "linux")]
        let netlink = NetlinkConnector::new().ok();
        #[cfg(not(target_os = "linux"))]
        let _netlink: Option<()> = None;

        #[cfg(target_os = "linux")]
        {
            if netlink.is_some() {
                println!(
                    "[+] ProbeManager: Netlink Connector initialized (zero-polling process events)"
                );
            } else {
                println!("[!] ProbeManager: Netlink Connector unavailable, falling back to /proc polling");
            }
        }

        Ok(Self {
            lite_mode,
            known_pids: HashSet::new(),
            #[cfg(target_os = "linux")]
            netlink,
        })
    }

    /// Poll for new events.
    /// Priority: eBPF Ring Buffer → Netlink Connector → /proc polling
    pub fn poll_events(&mut self) -> Result<Vec<RawProbeEvent>> {
        // In production: ring_buf.poll(timeout)
        // For now: try Netlink first, fall back to /proc

        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut nl) = self.netlink {
                match nl.recv_events() {
                    Ok(events) if !events.is_empty() => {
                        return Ok(events);
                    }
                    Ok(_) => {
                        // Netlink returned empty (timeout) — return empty, don't fall back
                        return Ok(Vec::new());
                    }
                    Err(e) => {
                        eprintln!("    [!] Netlink error: {}. Falling back to /proc.", e);
                        // Netlink broke — disable it and fall through
                        self.netlink = None;
                    }
                }
            }
        }

        // Final fallback: /proc-based polling (legacy, TOCTOU-prone)
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

    // /proc helpers now delegate to `crate::procfs` so the (comm-aware)
    // /proc/<pid>/stat parser lives in one place and the ppid-parse bug
    // (incorrect when comm contains spaces) is fixed once for all callers.
    #[cfg(target_os = "linux")]
    fn read_proc_comm(pid: u32) -> String {
        crate::procfs::read_comm(pid)
    }

    #[cfg(target_os = "linux")]
    fn read_proc_exe(pid: u32) -> String {
        crate::procfs::read_exe(pid)
    }

    #[cfg(target_os = "linux")]
    fn read_proc_ppid(pid: u32) -> u32 {
        crate::procfs::read_ppid(pid)
    }

    #[cfg(target_os = "linux")]
    fn read_proc_cgroup_id(pid: u32) -> u64 {
        // NOTE: DefaultHasher is not stable across runs (randomized seed);
        // suitable only as a single-process de-dup key. See procfs/TODO.
        std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
            .ok()
            .map(|s| {
                // Hash the cgroup path as a rough ID
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                s.hash(&mut hasher);
                hasher.finish()
            })
            .unwrap_or(0)
    }
}
