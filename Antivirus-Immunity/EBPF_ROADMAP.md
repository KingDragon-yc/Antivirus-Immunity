# eBPF 接入路线图

## 当前状态

M1 与 M2 已完成并在 WSL2 6.6 内核上做过端到端验证：

- `libbpf-cargo 0.26.2` 在 `build.rs` 中编译 `bpf/probes.bpf.c` 并生成、嵌入 skeleton。
- `libbpf-rs 0.26.2` 在运行时执行 CO-RE 重定位，加载并附加 `sched_process_exec` 与 `sched_process_exit` tracepoint。
- 两个探针经 256 KiB `BPF_MAP_TYPE_RINGBUF` 发送固定 328 字节 ABI 事件。
- 用户态逐字段校验和解码事件，不对不可信字节做 C/Rust struct 强转。
- libbpf 对象、links 与 Ring Buffer 由同一个后台线程持有；4096 项有界队列隔离内核消费与策略处理。
- eBPF 初始化或运行失败时，依次降级到 Netlink Connector 和 `/proc`。
- Linux CI 安装 clang、LLVM、libelf 和 zlib 开发依赖并构建 eBPF crate。

验收命令：

```bash
cargo test --package antivirus-immunity-ebpf
cargo build --package antivirus-immunity-ebpf
sudo ./target/debug/immunity-ebpf --mode monitor --ai false
```

运行日志必须出现：

```text
ProbeManager: CO-RE eBPF probes attached; consuming kernel events via Ring Buffer
```

## M3：网络阻断与 BPF LSM 文件护栏（v0.6 已实现）

已实现 XDP 入站、TCX/TC 出站阻断，IPv4/IPv6 LPM 与端口 map，BPF LSM `file_open` 路径策略，下发完成后再启用 enforcement，以及内核/用户态双层丢事件计数。核心观测与护栏使用不同 BPF 对象，LSM 不可用时不会撤销 exec/exit。

仍需在生产内核矩阵验证 BPF LSM（WSL 默认未把 `bpf` 加入启动 LSM 列表）、多网络命名空间和高 fork/exec 压力。XDP/TC 事件没有可靠进程上下文，当前按接口、地址与端口策略执行。

## M4：生产化（v0.7 第一阶段已实现）

已实现 fail-open/fail-closed、版本化启动策略、策略完全写入后再启用、systemd/Docker/Kubernetes 资产、Prometheus attach/fallback/丢事件指标，以及 tag 驱动的 x86_64 压缩包与 amd64/arm64 容器发布流程。

发布流水线会先完成 Linux 测试、安全公告审计、双架构镜像构建、SBOM/构建来源证明和 Cosign 无密钥签名，再原子化创建 GitHub Release。v0.7 后续加固清单包括：原生 BPF LSM 内核矩阵、ARM64 实机 attach、seccomp profile、策略热更新/回滚和长期压力数据。

## 已知边界

- XDP/TCX/TC 与 BPF LSM 已有真实内核程序；运行时逐项报告 attach 状态，配置存在不代表目标内核已激活对应能力。
- `sched_process_exec` 仅在成功执行后产生事件；用户态优先使用内核更新后的 task comm，并保留可执行文件路径。
- `ns_pid` 当前仍等于宿主 PID；精确 PID namespace 映射属于 M3/M4。
- WSL2 已验证 CO-RE、Ring Buffer、XDP 和 TCX attach/自动清理；其默认 LSM 启动列表不含 `bpf`，LSM 拒绝路径必须在原生测试内核验证。
