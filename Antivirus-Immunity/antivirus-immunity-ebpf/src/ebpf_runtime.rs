//! CO-RE loaders for the always-on process probes and optional kernel guards.

use crate::kernel_policy::{KernelPolicy, NetworkCidr, deny_mask, normalize_path};
use crate::metrics::Metrics;
use crate::probe::{NetworkDirection, ProbeType, RawProbeEvent};
use anyhow::{Context, Result, bail};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{
    AsRawLibbpf, MapCore, MapFlags, ProgramAttachType, RingBufferBuilder, TC_EGRESS, TcHook,
    TcHookBuilder,
};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::os::fd::AsFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/probes.skel.rs"));
}

mod guard_generated {
    include!(concat!(env!("OUT_DIR"), "/guard.skel.rs"));
}

use generated::ProbesSkelBuilder;
use guard_generated::GuardSkelBuilder;

const WIRE_EVENT_SIZE: usize = 328;
const COMM_OFFSET: usize = 52;
const COMM_LEN: usize = 16;
const PATH_OFFSET: usize = COMM_OFFSET + COMM_LEN;
const PATH_LEN: usize = 256;
const EVENT_EXEC: u32 = 1;
const EVENT_EXIT: u32 = 2;
const EVENT_NETWORK_BLOCKED: u32 = 3;
const EVENT_FILE_BLOCKED: u32 = 4;

#[derive(Debug, Clone, Default)]
pub struct RuntimeStatus {
    pub core_attached: bool,
    pub lsm_attached: bool,
    pub xdp_interfaces: Vec<String>,
    pub tc_interfaces: Vec<String>,
    pub degradations: Vec<String>,
}

/// Owns the worker that keeps all BPF objects, links and TC hooks alive.
pub struct EbpfRuntime {
    receiver: mpsc::Receiver<RawProbeEvent>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    status: RuntimeStatus,
}

impl EbpfRuntime {
    pub fn start(policy: KernelPolicy, metrics: Arc<Metrics>) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::sync_channel(4096);
        let (init_tx, init_rx) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("immunity-ebpf-ringbuf".to_owned())
            .spawn(move || {
                if let Err(error) = run_worker(event_tx, worker_stop, &init_tx, policy, metrics) {
                    let _ = init_tx.try_send(Err(format!("{error:#}")));
                    eprintln!("[!] eBPF worker stopped: {error:#}");
                }
            })
            .context("spawn eBPF ring-buffer worker")?;

        match init_rx.recv_timeout(Duration::from_secs(15)) {
            Ok(Ok(status)) => Ok(Self {
                receiver: event_rx,
                stop,
                worker: Some(worker),
                status,
            }),
            Ok(Err(error)) => {
                stop.store(true, Ordering::Release);
                let _ = worker.join();
                bail!("initialize CO-RE probes: {error}")
            }
            Err(error) => {
                stop.store(true, Ordering::Release);
                let _ = worker.join();
                bail!("timed out waiting for eBPF initialization: {error}")
            }
        }
    }

    pub fn status(&self) -> &RuntimeStatus {
        &self.status
    }

    pub fn drain_events(&self) -> Result<Vec<RawProbeEvent>> {
        let first = match self.receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => event,
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(Vec::new()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("eBPF ring-buffer worker disconnected")
            }
        };
        let mut events = vec![first];
        loop {
            match self.receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(mpsc::TryRecvError::Empty) => return Ok(events),
                Err(mpsc::TryRecvError::Disconnected) => {
                    bail!("eBPF ring-buffer worker disconnected")
                }
            }
        }
    }
}

impl Drop for EbpfRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_worker(
    event_tx: mpsc::SyncSender<RawProbeEvent>,
    stop: Arc<AtomicBool>,
    init_tx: &mpsc::SyncSender<Result<RuntimeStatus, String>>,
    policy: KernelPolicy,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let mut core_object = MaybeUninit::uninit();
    let open_core = ProbesSkelBuilder::default()
        .open(&mut core_object)
        .context("open embedded process BPF object")?;
    let mut core = open_core
        .load()
        .context("load process BPF object (requires CAP_BPF and a BTF-enabled kernel)")?;
    core.attach().context("attach exec/exit tracepoints")?;

    let mut status = RuntimeStatus {
        core_attached: true,
        ..RuntimeStatus::default()
    };
    let needs_network = !policy.networks.is_empty() || !policy.blocked_ports.is_empty();
    let needs_lsm = !policy.protected_paths.is_empty();
    let lsm_available = bpf_lsm_available();
    let tcx_available = kernel_at_least(6, 6);

    let mut guard_object = MaybeUninit::uninit();
    let guard = if !needs_network && !needs_lsm {
        None
    } else {
        match GuardSkelBuilder::default().open(&mut guard_object) {
            Err(error) => {
                status
                    .degradations
                    .push(format!("kernel guard open failed: {error:#}"));
                None
            }
            Ok(mut open) => {
                if needs_network {
                    open.progs.xdp_ingress_guard.set_autoattach(false);
                    open.progs.tc_egress_guard.set_autoattach(false);
                } else {
                    open.progs.xdp_ingress_guard.set_autoload(false);
                    open.progs.tc_egress_guard.set_autoload(false);
                }
                if needs_network && tcx_available {
                    open.progs
                        .tc_egress_guard
                        .set_attach_type(ProgramAttachType::TcxEgress);
                }
                if !needs_lsm || !lsm_available {
                    open.progs.file_open_guard.set_autoload(false);
                }
                match open.load() {
                    Err(error) => {
                        status
                            .degradations
                            .push(format!("kernel guard load failed: {error:#}"));
                        None
                    }
                    Ok(mut loaded) => match apply_policy(&loaded, &policy) {
                        Err(error) => {
                            status
                                .degradations
                                .push(format!("kernel policy map update failed: {error:#}"));
                            None
                        }
                        Ok(()) => {
                            if needs_lsm && lsm_available {
                                match loaded.attach() {
                                    Ok(()) => status.lsm_attached = true,
                                    Err(error) => status
                                        .degradations
                                        .push(format!("BPF LSM attach failed: {error}")),
                                }
                            } else if needs_lsm {
                                status
                                    .degradations
                                    .push("kernel boot LSM list does not include bpf".to_owned());
                            }
                            Some(loaded)
                        }
                    },
                }
            }
        }
    };

    let interfaces = if needs_network {
        expand_interfaces(&policy.interfaces)?
    } else {
        Vec::new()
    };
    let mut xdp_links = Vec::new();
    let mut tcx_links = Vec::new();
    let mut tc_hooks: Vec<LegacyTcHook> = Vec::new();

    if needs_network && let Some(guard) = guard.as_ref() {
        for interface in &interfaces {
            let Some(ifindex) = interface_index(interface) else {
                status
                    .degradations
                    .push(format!("interface {interface:?} was not found"));
                continue;
            };
            match guard.progs.xdp_ingress_guard.attach_xdp(ifindex) {
                Ok(link) => {
                    xdp_links.push(link);
                    status.xdp_interfaces.push(interface.clone());
                }
                Err(error) => status
                    .degradations
                    .push(format!("XDP attach on {interface} failed: {error}")),
            }

            let tcx_result = if tcx_available {
                Some(attach_tcx(&guard.progs.tc_egress_guard, ifindex))
            } else {
                None
            };
            match tcx_result {
                Some(Ok(link)) => {
                    tcx_links.push(link);
                    status.tc_interfaces.push(interface.clone());
                }
                Some(Err(error)) => {
                    status.degradations.push(format!(
                        "TCX egress attach on {interface} failed: {error:#}"
                    ));
                    if policy.allow_legacy_tc {
                        attach_legacy_tc(
                            guard.progs.tc_egress_guard.as_fd(),
                            ifindex,
                            interface,
                            &mut tc_hooks,
                            &mut status,
                        );
                    }
                }
                None if policy.allow_legacy_tc => attach_legacy_tc(
                    guard.progs.tc_egress_guard.as_fd(),
                    ifindex,
                    interface,
                    &mut tc_hooks,
                    &mut status,
                ),
                None => status.degradations.push(format!(
                    "TC egress on {interface} requires kernel 6.6 TCX or allow_legacy_tc=true"
                )),
            }
        }
    }

    let xdp_complete =
        needs_network && !interfaces.is_empty() && status.xdp_interfaces.len() == interfaces.len();
    let tc_complete =
        needs_network && !interfaces.is_empty() && status.tc_interfaces.len() == interfaces.len();
    let network_incomplete = needs_network && (!xdp_complete || !tc_complete);
    let lsm_incomplete = needs_lsm && !status.lsm_attached;
    if policy.fail_closed && (network_incomplete || lsm_incomplete) {
        bail!("fail_closed policy requested, but one or more kernel guards could not attach");
    }

    metrics.set_attach_status(true, xdp_complete, tc_complete, status.lsm_attached);

    let callback_metrics = Arc::clone(&metrics);
    let guard_callback_metrics = Arc::clone(&metrics);
    let core_tx = event_tx.clone();
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&core.maps.events, move |bytes| {
            deliver_event(bytes, &core_tx, &callback_metrics);
            0
        })
        .context("register process ring-buffer callback")?;
    if let Some(guard) = guard.as_ref() {
        builder
            .add(&guard.maps.guard_events, move |bytes| {
                deliver_event(bytes, &event_tx, &guard_callback_metrics);
                0
            })
            .context("register guard ring-buffer callback")?;
    }
    let ring_buffer = builder.build().context("build ring-buffer consumer")?;

    init_tx
        .send(Ok(status))
        .context("report successful eBPF initialization")?;

    let mut last_stats = Instant::now();
    while !stop.load(Ordering::Acquire) {
        ring_buffer
            .poll(Duration::from_millis(100))
            .context("poll BPF ring buffers")?;
        if last_stats.elapsed() >= Duration::from_secs(1) {
            let core_stats = read_percpu_stats::<2>(&core.maps.core_stats);
            let mut stats = guard
                .as_ref()
                .map(|guard| read_percpu_stats::<5>(&guard.maps.guard_stats))
                .unwrap_or_default();
            stats[0] = stats[0].saturating_add(core_stats[0]);
            stats[1] = stats[1].saturating_add(core_stats[1]);
            metrics.update_kernel_stats(stats);
            last_stats = Instant::now();
        }
    }

    drop(xdp_links);
    drop(tcx_links);
    Ok(())
}

struct TcxLink(NonNull<libbpf_sys::bpf_link>);

impl Drop for TcxLink {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_link__destroy(self.0.as_ptr());
        }
    }
}

struct LegacyTcHook(TcHook);

impl Drop for LegacyTcHook {
    fn drop(&mut self) {
        let _ = self.0.detach();
    }
}

fn attach_tcx(program: &libbpf_rs::Program<'_>, ifindex: i32) -> Result<TcxLink> {
    let options = libbpf_sys::bpf_tcx_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_tcx_opts>() as u64,
        ..Default::default()
    };
    let pointer = unsafe {
        libbpf_sys::bpf_program__attach_tcx(program.as_libbpf_object().as_ptr(), ifindex, &options)
    };
    let error = unsafe { libbpf_sys::libbpf_get_error(pointer.cast()) };
    if error != 0 {
        bail!(std::io::Error::from_raw_os_error((-error) as i32));
    }
    NonNull::new(pointer)
        .map(TcxLink)
        .context("libbpf returned a null TCX link")
}

fn attach_legacy_tc(
    program_fd: std::os::fd::BorrowedFd<'_>,
    ifindex: i32,
    interface: &str,
    hooks: &mut Vec<LegacyTcHook>,
    status: &mut RuntimeStatus,
) {
    let mut builder = TcHookBuilder::new(program_fd);
    builder
        .ifindex(ifindex)
        .replace(false)
        .handle(1)
        .priority(1);
    let mut hook = builder.hook(TC_EGRESS);
    match hook.create().and_then(|mut created| created.attach()) {
        Ok(attached) => {
            hooks.push(LegacyTcHook(attached));
            status.tc_interfaces.push(interface.to_owned());
            status.degradations.push(format!(
                "TC on {interface} uses persistent legacy attach; configure service cleanup"
            ));
        }
        Err(error) => status.degradations.push(format!(
            "legacy TC egress attach on {interface} failed: {error}"
        )),
    }
}

fn deliver_event(bytes: &[u8], sender: &mpsc::SyncSender<RawProbeEvent>, metrics: &Metrics) {
    match parse_wire_event(bytes) {
        Ok(event) => {
            if sender.try_send(event).is_err() {
                metrics.queue_dropped();
            }
        }
        Err(error) => eprintln!("[!] Dropped malformed BPF event: {error:#}"),
    }
}

fn apply_policy(guard: &guard_generated::GuardSkel<'_>, policy: &KernelPolicy) -> Result<()> {
    for network in &policy.networks {
        match network {
            NetworkCidr::V4 { prefix, address } => {
                let mut key = [0_u8; 8];
                key[..4].copy_from_slice(&prefix.to_ne_bytes());
                key[4..].copy_from_slice(address);
                guard
                    .maps
                    .ipv4_blacklist
                    .update(&key, &[1], MapFlags::ANY)?;
            }
            NetworkCidr::V6 { prefix, address } => {
                let mut key = [0_u8; 20];
                key[..4].copy_from_slice(&prefix.to_ne_bytes());
                key[4..].copy_from_slice(address);
                guard
                    .maps
                    .ipv6_blacklist
                    .update(&key, &[1], MapFlags::ANY)?;
            }
        }
    }
    for port in &policy.blocked_ports {
        guard
            .maps
            .blocked_ports
            .update(&port.to_ne_bytes(), &[1], MapFlags::ANY)?;
    }
    for (index, rule) in policy.protected_paths.iter().enumerate() {
        let path = normalize_path(&rule.path);
        let mut key = [0_u8; 4 + PATH_LEN];
        let prefix_bytes = path.len() + usize::from(!rule.recursive);
        key[..4].copy_from_slice(&((prefix_bytes * 8) as u32).to_ne_bytes());
        key[4..4 + path.len()].copy_from_slice(path.as_bytes());
        let mut value = [0_u8; 12];
        let rule_id = (index as u32) + 1;
        value[..4].copy_from_slice(&rule_id.to_ne_bytes());
        value[4..8].copy_from_slice(&deny_mask(&rule.deny).to_ne_bytes());
        value[8..10].copy_from_slice(&(path.len() as u16).to_ne_bytes());
        value[10] = u8::from(rule.recursive);
        guard
            .maps
            .protected_paths
            .update(&key, &value, MapFlags::ANY)?;
    }

    // Activate enforcement only after every rule was inserted successfully.
    let key = 0_u32.to_ne_bytes();
    let mut value = [0_u8; 16];
    value[..4].copy_from_slice(&u32::from(policy.enforce).to_ne_bytes());
    value[4..8].copy_from_slice(&u32::from(policy.fail_closed).to_ne_bytes());
    value[8..].copy_from_slice(&policy.generation.to_ne_bytes());
    guard.maps.policy.update(&key, &value, MapFlags::ANY)?;
    Ok(())
}

fn read_percpu_stats<const N: usize>(map: &impl MapCore) -> [u64; N] {
    let mut result = [0_u64; N];
    for (index, target) in result.iter_mut().enumerate() {
        if let Ok(Some(per_cpu)) = map.lookup_percpu(&(index as u32).to_ne_bytes(), MapFlags::ANY) {
            *target = per_cpu
                .iter()
                .filter_map(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
                .map(u64::from_ne_bytes)
                .fold(0_u64, u64::saturating_add);
        }
    }
    result
}

fn bpf_lsm_available() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .is_ok_and(|list| list.split(',').any(|name| name.trim() == "bpf"))
}

fn kernel_at_least(required_major: u32, required_minor: u32) -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    let mut components = release.trim().split(['.', '-']);
    let Some(major) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    let Some(minor) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    (major, minor) >= (required_major, required_minor)
}

fn expand_interfaces(configured: &[String]) -> Result<Vec<String>> {
    let mut interfaces: Vec<String> = configured
        .iter()
        .filter(|name| name.as_str() != "auto")
        .cloned()
        .collect();
    if configured.iter().any(|name| name == "auto") {
        if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
            interfaces.extend(default_ipv4_interfaces(&routes));
        }
        if let Ok(routes) = std::fs::read_to_string("/proc/net/ipv6_route") {
            interfaces.extend(default_ipv6_interfaces(&routes));
        }
    }
    if configured.iter().any(|name| name == "auto") && interfaces.is_empty() {
        for entry in std::fs::read_dir("/sys/class/net").context("enumerate network interfaces")? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name != "lo" {
                interfaces.push(name);
            }
        }
    }
    interfaces.sort();
    interfaces.dedup();
    Ok(interfaces)
}

fn default_ipv4_interfaces(routes: &str) -> Vec<String> {
    routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() > 7 && fields[1] == "00000000" && fields[7] == "00000000")
                .then(|| fields[0].to_owned())
        })
        .collect()
}

fn default_ipv6_interfaces(routes: &str) -> Vec<String> {
    routes
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() >= 10 && fields[0].bytes().all(|byte| byte == b'0') && fields[1] == "00")
                .then(|| fields[9].to_owned())
        })
        .collect()
}

fn interface_index(name: &str) -> Option<i32> {
    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index as i32)
}

fn parse_wire_event(bytes: &[u8]) -> Result<RawProbeEvent> {
    if bytes.len() != WIRE_EVENT_SIZE {
        bail!(
            "unexpected event size {}, expected {WIRE_EVENT_SIZE}",
            bytes.len()
        );
    }
    let cgroup_id = read_u64(bytes, 8)?;
    let pid = read_u32(bytes, 16)?;
    let ppid = read_u32(bytes, 20)?;
    let ns_pid = read_u32(bytes, 32)?;
    let event_type = read_u32(bytes, 36)?;
    let arg0 = read_u32(bytes, 40)?;
    let port = read_u16(bytes, 48)?;
    let reserved = read_u16(bytes, 50)?;
    let enforced = read_u32(bytes, 324)? != 0;
    let kernel_comm = read_c_string(&bytes[COMM_OFFSET..COMM_OFFSET + COMM_LEN]);
    let path = read_c_string(&bytes[PATH_OFFSET..PATH_OFFSET + PATH_LEN]);

    let (comm, event_type, detail) = match event_type {
        EVENT_EXEC => {
            let comm = if kernel_comm.is_empty() {
                path.rsplit('/')
                    .find(|part| !part.is_empty())
                    .unwrap_or_default()
                    .to_owned()
            } else {
                kernel_comm
            };
            let detail = format!("exec: {comm} ({path})");
            (comm, ProbeType::Execve, detail)
        }
        EVENT_EXIT => {
            let detail = format!("exit: {kernel_comm}");
            (kernel_comm, ProbeType::Exit, detail)
        }
        EVENT_NETWORK_BLOCKED => {
            let ipv6 = reserved & 0x100 != 0;
            let (source, destination) = if ipv6 {
                let source: [u8; 16] = bytes[PATH_OFFSET..PATH_OFFSET + 16].try_into()?;
                let destination: [u8; 16] = bytes[PATH_OFFSET + 16..PATH_OFFSET + 32].try_into()?;
                (
                    Ipv6Addr::from(source).to_string(),
                    Ipv6Addr::from(destination).to_string(),
                )
            } else {
                (
                    format!("{}.{}.{}.{}", bytes[40], bytes[41], bytes[42], bytes[43]),
                    format!("{}.{}.{}.{}", bytes[44], bytes[45], bytes[46], bytes[47]),
                )
            };
            let direction = if reserved & 0xff == 1 {
                NetworkDirection::Ingress
            } else {
                NetworkDirection::Egress
            };
            let outcome = if enforced { "block" } else { "policy match" };
            let detail = format!(
                "kernel network {outcome}: {source} -> {destination}:{port} ({direction:?})"
            );
            (
                kernel_comm,
                ProbeType::NetworkBlocked {
                    source,
                    destination,
                    port,
                    direction,
                    enforced,
                },
                detail,
            )
        }
        EVENT_FILE_BLOCKED => {
            let outcome = if enforced { "block" } else { "policy match" };
            let detail = format!("kernel file {outcome}: {path} (operation mask {arg0:#x})");
            (
                kernel_comm,
                ProbeType::FileBlocked {
                    file_path: path.clone(),
                    operation_mask: arg0,
                    enforced,
                },
                detail,
            )
        }
        other => bail!("unknown BPF event type {other}"),
    };
    let path = if matches!(&event_type, ProbeType::NetworkBlocked { .. }) {
        String::new()
    } else {
        path
    };
    Ok(RawProbeEvent {
        pid,
        ppid,
        comm,
        path,
        event_type,
        detail,
        cgroup_id,
        ns_pid,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = bytes
        .get(offset..offset + 2)
        .context("u16 field outside BPF event")?;
    Ok(u16::from_ne_bytes(raw.try_into()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .context("u32 field outside BPF event")?;
    Ok(u32::from_ne_bytes(raw.try_into()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw = bytes
        .get(offset..offset + 8)
        .context("u64 field outside BPF event")?;
    Ok(u64::from_ne_bytes(raw.try_into()?))
}

fn read_c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exec_and_guard_events_without_struct_casts() {
        let mut bytes = [0_u8; WIRE_EVENT_SIZE];
        bytes[8..16].copy_from_slice(&42_u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&123_u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[32..36].copy_from_slice(&123_u32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&EVENT_EXEC.to_ne_bytes());
        bytes[COMM_OFFSET..COMM_OFFSET + 4].copy_from_slice(b"bash");
        bytes[PATH_OFFSET..PATH_OFFSET + 9].copy_from_slice(b"/bin/bash");
        let event = parse_wire_event(&bytes).unwrap();
        assert_eq!(event.comm, "bash");
        assert_eq!(event.event_type, ProbeType::Execve);

        bytes[36..40].copy_from_slice(&EVENT_FILE_BLOCKED.to_ne_bytes());
        bytes[40..44].copy_from_slice(&2_u32.to_ne_bytes());
        let event = parse_wire_event(&bytes).unwrap();
        assert!(matches!(event.event_type, ProbeType::FileBlocked { .. }));
    }

    #[test]
    fn rejects_truncated_and_unknown_events() {
        assert!(parse_wire_event(&[0; WIRE_EVENT_SIZE - 1]).is_err());
        let mut bytes = [0_u8; WIRE_EVENT_SIZE];
        bytes[36..40].copy_from_slice(&99_u32.to_ne_bytes());
        assert!(parse_wire_event(&bytes).is_err());
    }

    #[test]
    fn parses_default_route_interfaces() {
        let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 01020304 0003 0 0 10 00000000\ndocker0 000011AC 00000000 0001 0 0 0 0000FFFF\n";
        assert_eq!(default_ipv4_interfaces(ipv4), vec!["eth0"]);

        let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000000 00000000 00000001 eth1\n";
        assert_eq!(default_ipv6_interfaces(ipv6), vec!["eth1"]);
    }
}
