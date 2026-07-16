//! Tiny dependency-free Prometheus exporter for the low-resource agent.

use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

const MAX_HTTP_CONNECTIONS: usize = 64;
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct Metrics {
    events_processed: AtomicU64,
    userspace_queue_dropped: AtomicU64,
    fallback_count: AtomicU64,
    threat_matches: AtomicU64,
    kernel_events_emitted: AtomicU64,
    kernel_ringbuf_dropped: AtomicU64,
    xdp_blocked: AtomicU64,
    tc_blocked: AtomicU64,
    lsm_blocked: AtomicU64,
    core_attached: AtomicBool,
    xdp_attached: AtomicBool,
    tc_attached: AtomicBool,
    lsm_attached: AtomicBool,
}

impl Metrics {
    pub fn event_processed(&self) {
        self.events_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn queue_dropped(&self) {
        self.userspace_queue_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fallback(&self) {
        self.fallback_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn threat_match(&self) {
        self.threat_matches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_attach_status(&self, core: bool, xdp: bool, tc: bool, lsm: bool) {
        self.core_attached.store(core, Ordering::Relaxed);
        self.xdp_attached.store(xdp, Ordering::Relaxed);
        self.tc_attached.store(tc, Ordering::Relaxed);
        self.lsm_attached.store(lsm, Ordering::Relaxed);
    }

    pub fn update_kernel_stats(&self, values: [u64; 5]) {
        self.kernel_events_emitted
            .store(values[0], Ordering::Relaxed);
        self.kernel_ringbuf_dropped
            .store(values[1], Ordering::Relaxed);
        self.xdp_blocked.store(values[2], Ordering::Relaxed);
        self.tc_blocked.store(values[3], Ordering::Relaxed);
        self.lsm_blocked.store(values[4], Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let mut output = String::with_capacity(2048);
        metric(
            &mut output,
            "immunity_events_processed_total",
            "Userspace security events processed.",
            self.events_processed.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_userspace_queue_dropped_total",
            "Events dropped because the bounded userspace queue was full.",
            self.userspace_queue_dropped.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_probe_fallback_total",
            "Probe source fallbacks after an eBPF or Netlink failure.",
            self.fallback_count.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_threat_intel_matches_total",
            "Executable matches from the local threat-intelligence database.",
            self.threat_matches.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_kernel_events_emitted_total",
            "Security events emitted by eBPF programs.",
            self.kernel_events_emitted.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_kernel_ringbuf_dropped_total",
            "Security events dropped in kernel due to Ring Buffer pressure.",
            self.kernel_ringbuf_dropped.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_xdp_blocked_total",
            "Ingress packets dropped by XDP.",
            self.xdp_blocked.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_tc_blocked_total",
            "Egress packets dropped by TC.",
            self.tc_blocked.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "immunity_lsm_blocked_total",
            "File operations denied by BPF LSM.",
            self.lsm_blocked.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "core",
            self.core_attached.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "xdp",
            self.xdp_attached.load(Ordering::Relaxed),
        );
        gauge(&mut output, "tc", self.tc_attached.load(Ordering::Relaxed));
        gauge(
            &mut output,
            "lsm",
            self.lsm_attached.load(Ordering::Relaxed),
        );
        output
    }

    pub async fn serve(self: Arc<Self>, address: String) -> Result<()> {
        let listener = TcpListener::bind(&address)
            .await
            .with_context(|| format!("bind Prometheus endpoint {address}"))?;
        let connections = Arc::new(Semaphore::new(MAX_HTTP_CONNECTIONS));
        loop {
            let (mut stream, _) = listener.accept().await?;
            let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                // Bound task and socket growth under slow-connection floods.
                continue;
            };
            let metrics = Arc::clone(&self);
            tokio::spawn(async move {
                let _permit = permit;
                let mut request = [0_u8; 1024];
                let length = match timeout(HTTP_READ_TIMEOUT, stream.read(&mut request)).await {
                    Ok(Ok(length)) if length > 0 => length,
                    _ => return,
                };
                let first_line = String::from_utf8_lossy(&request[..length]);
                let (status, content_type, body) = if first_line.starts_with("GET /metrics ") {
                    ("200 OK", "text/plain; version=0.0.4", metrics.render())
                } else if first_line.starts_with("GET /healthz ") {
                    ("200 OK", "text/plain", "ok\n".to_owned())
                } else if first_line.starts_with("GET /readyz ") {
                    if metrics.core_attached.load(Ordering::Relaxed) {
                        ("200 OK", "text/plain", "ready\n".to_owned())
                    } else {
                        (
                            "503 Service Unavailable",
                            "text/plain",
                            "not ready\n".to_owned(),
                        )
                    }
                } else {
                    ("404 Not Found", "text/plain", "not found\n".to_owned())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }
}

fn metric(output: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} counter");
    let _ = writeln!(output, "{name} {value}");
}

fn gauge(output: &mut String, probe: &str, attached: bool) {
    let _ = writeln!(
        output,
        "immunity_probe_attached{{probe=\"{probe}\"}} {}",
        u8::from(attached)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_has_stable_names_and_values() {
        let metrics = Metrics::default();
        metrics.event_processed();
        metrics.set_attach_status(true, false, true, false);
        let output = metrics.render();
        assert!(output.contains("immunity_events_processed_total 1"));
        assert!(output.contains("immunity_probe_attached{probe=\"core\"} 1"));
        assert!(output.contains("immunity_probe_attached{probe=\"xdp\"} 0"));
    }
}
