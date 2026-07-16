Antivirus-Immunity v0.7.0 is the first Linux-focused release for cloud server and Kubernetes node fleets.

The release adds real XDP ingress and TC/TCX egress policy enforcement, a BPF LSM file-open guard, bounded Prometheus telemetry, and a cached SHA-256/CTPH threat-intelligence blacklist. Kernel guard capabilities attach independently and report explicit degradation instead of silently claiming protection.

Start in `monitor` mode. Before enabling `enforce`, replace the documentation-only CIDRs in `kernel-policy.json`, verify the target interface name, confirm `bpf` appears in `/sys/kernel/security/lsm` when file enforcement is required, and alert on `immunity_probe_attached` plus both queue-drop metrics.

Linux 6.6+ uses TCX links so egress policy disappears automatically when the agent exits. Older kernels require the explicit `allow_legacy_tc` opt-in and service-level cleanup supplied in the systemd unit.

Known limits: the BPF LSM guard enforces new `file_open` operations; pre-existing file descriptors and unlink/rename/create metadata hooks are outside v0.7.0. Its path LPM handles resolved paths up to 255 bytes, while longer paths and deep recursive descendants fail open. The destructive LSM verification needs a native kernel booted with `lsm=...,bpf`; WSL kernels without active BPF LSM can compile the program and validate XDP/TC, then skip that test explicitly.
