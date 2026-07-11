//! Real CO-RE probe loader and ring-buffer consumer.

use crate::probe::{ProbeType, RawProbeEvent};
use anyhow::{Context, Result, bail};
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/probes.skel.rs"));
}

use generated::ProbesSkelBuilder;

const WIRE_EVENT_SIZE: usize = 328;
const COMM_OFFSET: usize = 52;
const COMM_LEN: usize = 16;
const PATH_OFFSET: usize = COMM_OFFSET + COMM_LEN;
const PATH_LEN: usize = 256;
const EVENT_EXEC: u32 = 1;
const EVENT_EXIT: u32 = 2;

/// Owns the worker that keeps the libbpf object, attached links and ring
/// buffer alive. The worker-to-manager channel is bounded so userspace cannot
/// grow without limit when policy evaluation is slower than the kernel.
pub struct EbpfRuntime {
    receiver: mpsc::Receiver<RawProbeEvent>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl EbpfRuntime {
    pub fn start() -> Result<Self> {
        let (event_tx, event_rx) = mpsc::sync_channel(4096);
        let (init_tx, init_rx) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);

        let worker = thread::Builder::new()
            .name("immunity-ebpf-ringbuf".to_owned())
            .spawn(move || {
                if let Err(error) = run_worker(event_tx, worker_stop, &init_tx) {
                    // This succeeds only when initialization failed. Once the
                    // caller received Ok, init_rx is dropped and runtime
                    // failures are instead observed as event-channel closure.
                    let _ = init_tx.try_send(Err(format!("{error:#}")));
                    eprintln!("[!] eBPF worker stopped: {error:#}");
                }
            })
            .context("spawn eBPF ring-buffer worker")?;

        match init_rx.recv_timeout(Duration::from_secs(15)) {
            Ok(Ok(())) => Ok(Self {
                receiver: event_rx,
                stop,
                worker: Some(worker),
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

    pub fn drain_events(&self) -> Result<Vec<RawProbeEvent>> {
        // Preserve the old Netlink source's blocking behavior. Without this
        // bounded wait, ProbeManager's synchronous loop would spin at 100% CPU
        // whenever the eBPF source is healthy but idle.
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
    init_tx: &mpsc::SyncSender<Result<(), String>>,
) -> Result<()> {
    let mut open_object = MaybeUninit::uninit();
    let open_skel = ProbesSkelBuilder::default()
        .open(&mut open_object)
        .context("open embedded BPF object")?;
    let mut skel = open_skel
        .load()
        .context("load BPF object (requires root/CAP_BPF and a BTF-enabled Linux kernel)")?;
    skel.attach()
        .context("attach execve and sched_process_exit tracepoints")?;

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |bytes| {
            match parse_wire_event(bytes) {
                Ok(event) => {
                    // Dropping under sustained overload is preferable to
                    // blocking a libbpf callback and stalling ring consumption.
                    let _ = event_tx.try_send(event);
                }
                Err(error) => eprintln!("[!] Dropped malformed BPF event: {error:#}"),
            }
            0
        })
        .context("register events ring-buffer callback")?;
    let ring_buffer = builder.build().context("build ring-buffer consumer")?;

    init_tx
        .send(Ok(()))
        .context("report successful eBPF initialization")?;

    while !stop.load(Ordering::Acquire) {
        ring_buffer
            .poll(Duration::from_millis(100))
            .context("poll BPF ring buffer")?;
    }
    Ok(())
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
    let kernel_comm = read_c_string(&bytes[COMM_OFFSET..COMM_OFFSET + COMM_LEN]);
    let path = read_c_string(&bytes[PATH_OFFSET..PATH_OFFSET + PATH_LEN]);

    let (comm, event_type, detail) = match event_type {
        EVENT_EXEC => {
            // sys_enter_execve runs before the kernel updates task->comm.
            // Prefer the basename of the requested executable so downstream
            // policy does not see the caller's stale name (usually "bash").
            let comm = path
                .rsplit('/')
                .find(|part| !part.is_empty())
                .unwrap_or(&kernel_comm)
                .to_owned();
            let detail = format!("exec: {comm} ({path})");
            (comm, ProbeType::Execve, detail)
        }
        EVENT_EXIT => {
            let detail = format!("exit: {kernel_comm}");
            (kernel_comm, ProbeType::Exit, detail)
        }
        other => bail!("unknown BPF event type {other}"),
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
    fn parses_exec_event_without_struct_casts() {
        let mut bytes = [0_u8; WIRE_EVENT_SIZE];
        bytes[8..16].copy_from_slice(&42_u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&123_u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[32..36].copy_from_slice(&123_u32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&EVENT_EXEC.to_ne_bytes());
        bytes[COMM_OFFSET..COMM_OFFSET + 4].copy_from_slice(b"bash");
        bytes[PATH_OFFSET..PATH_OFFSET + 9].copy_from_slice(b"/bin/bash");

        let event = parse_wire_event(&bytes).unwrap();
        assert_eq!(event.pid, 123);
        assert_eq!(event.ppid, 7);
        assert_eq!(event.cgroup_id, 42);
        assert_eq!(event.comm, "bash");
        assert_eq!(event.path, "/bin/bash");
        assert_eq!(event.event_type, ProbeType::Execve);
    }

    #[test]
    fn rejects_truncated_and_unknown_events() {
        assert!(parse_wire_event(&[0; WIRE_EVENT_SIZE - 1]).is_err());

        let mut bytes = [0_u8; WIRE_EVENT_SIZE];
        bytes[36..40].copy_from_slice(&99_u32.to_ne_bytes());
        assert!(parse_wire_event(&bytes).is_err());
    }
}
