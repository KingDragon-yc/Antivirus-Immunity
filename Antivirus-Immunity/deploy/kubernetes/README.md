# Kubernetes deployment

The recommended fleet topology is `daemonset.yaml`: one privileged agent per node, `hostPID` enabled, a 32 MiB memory request, and Prometheus scraping on port 9090. Edit the ConfigMap before deployment; the bundled CIDR list is empty and the agent starts in `monitor` mode.

```bash
kubectl apply -f deploy/kubernetes/daemonset.yaml
kubectl rollout status daemonset/antivirus-immunity
kubectl port-forward service/antivirus-immunity-metrics 9090:9090
curl http://127.0.0.1:9090/metrics
```

Apply `servicemonitor.yaml` only when the Prometheus Operator CRDs are installed.

`sidecar-patch.yaml` is a Pod-template fragment for dedicated, strongly isolated workloads. It needs `hostPID` and a privileged container because loading global BPF programs is a node-level operation. Running one copy in every ordinary application Pod duplicates probes and raises memory use and policy-conflict risk; node vendors should use the DaemonSet unless their admission controller also supplies per-cgroup scoping.

Before changing `--mode monitor` to `--mode enforce`:

1. Populate a reviewed network rule, then confirm `immunity_probe_attached{probe="xdp"}` and `tc` are `1`; confirm `lsm` is `1` when protected paths are configured. Empty rule classes deliberately stay detached to remove hot-path overhead.
2. `auto` selects default-route uplinks and falls back to non-loopback interfaces only when route discovery is unavailable. Use explicit names for unusual routing topologies.
3. Populate only reviewed CIDRs and threat signatures. The bundled threat database is empty.
4. Alert on both Ring Buffer and userspace queue drop metrics.
5. Keep `allow_legacy_tc=false` on Linux 6.6+. Older kernels may opt in only with reliable service cleanup.
6. Keep `allow_processes` empty. Linux task names are caller-controlled and are deliberately not accepted as an enforcement bypass.
7. Treat both JSON inputs as enforcement code: mount them read-only and permit updates only from the node-security control plane. A large threat feed will exceed the Kubernetes ConfigMap size limit; deliver it through a read-only CSI/PVC/host volume and restart the DaemonSet after an atomic replacement.

The v0.7 file guard covers new `file_open` operations. It rejects read opens when a rule contains `open`, and write-capable opens when it contains `write`. The path LPM is limited by the kernel's 2048-bit prefix ceiling: resolved paths longer than 255 bytes, including deep descendants of a recursive rule, fail open. File descriptors opened before the agent attached, plus unlink/rename/create metadata operations, are also outside this first-release hook and should remain protected by normal Unix permissions, read-only mounts, or an admission policy.
