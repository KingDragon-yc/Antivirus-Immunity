# eBPF 接入路线图

## 当前状态

M1 与 M2 已完成并在 WSL2 6.6 内核上做过端到端验证：

- `libbpf-cargo 0.26.2` 在 `build.rs` 中编译 `bpf/probes.bpf.c` 并生成、嵌入 skeleton。
- `libbpf-rs 0.26.2` 在运行时执行 CO-RE 重定位，加载并附加 `sys_enter_execve` 与 `sched_process_exit` tracepoint。
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

## M3：网络观测与 BPF LSM 文件护栏

尚未实现，不能视为现有能力：

- TCP/UDP 出站连接观测，优先采用稳定 tracepoint/fentry，必要时才使用 kprobe。
- BPF LSM 文件打开/创建观测及策略 map 下发。
- 对不支持 `CONFIG_BPF_LSM` 的内核逐探针降级，不能因可选 hook 失败而撤销 exec/exit 探针。
- 为 Ring Buffer/用户态有界队列增加丢事件计数和可观测性。
- IPv6、网络命名空间、容器 cgroup 和高 fork/exec 压力测试。

## M4：内核阻断与生产化

尚未实现：

- LSM/XDP/TC 内核级阻断与 fail-open/fail-closed 策略。
- 策略 map 的原子更新、版本化和回滚。
- systemd 单元、最小 capability、seccomp 与文件权限加固。
- 原生 Linux 多内核矩阵、Docker/Kubernetes 与 ARM64 验证。
- Prometheus 指标，包括 Ring Buffer 丢失、队列溢出、探针 attach 状态和 fallback 次数。

## 已知边界

- 当前真实 eBPF 能力仅覆盖进程执行与退出；README 中的网络/文件策略代码不等同于内核探针或阻断已经实现。
- `sys_enter_execve` 发生在 task comm 更新前，用户态使用 filename basename 作为 exec 事件的进程名。
- `ns_pid` 当前仍等于宿主 PID；精确 PID namespace 映射属于 M3/M4。
- WSL2 足以验证加载、CO-RE 与 Ring Buffer，但发布前仍需原生 Linux 多内核测试。
