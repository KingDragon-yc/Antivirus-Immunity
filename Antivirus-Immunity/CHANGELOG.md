# Changelog

## 0.7.0 - 2026-07-15

- Added independently degradable CO-RE guard object with XDP ingress, TC/TCX egress, and BPF LSM file-open enforcement.
- Added versioned, bounded kernel policy maps for IPv4/IPv6 CIDRs, ports, and protected path prefixes; spoofable Linux comm allowlists are rejected.
- Added TCX link lifecycle on Linux 6.6+ and explicit opt-in for persistent legacy TC attachment.
- Added low-cardinality Prometheus metrics for attach state, fallbacks, queue pressure, kernel Ring Buffer loss, and blocked operations.
- Added a bounded, cached SHA-256 + CTPH threat-intelligence blacklist for executed files.
- Added Docker, Kubernetes DaemonSet/sidecar examples, ServiceMonitor, and hardened systemd deployment assets.
- Linux CI is the release gate; the tag workflow publishes x86_64 archives, checksums, SBOM/provenance, and amd64/arm64 images.

## 0.5.0

- Added real libbpf-rs CO-RE exec/exit probes and bounded Ring Buffer consumption.
