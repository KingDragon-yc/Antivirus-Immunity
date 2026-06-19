# 🛣️ eBPF 接入路线图（解决"画饼"问题）

> **现状**：`antivirus-immunity-ebpf` 声称是 eBPF 引擎，但 `libbpf-rs` 依赖被注释、`bpf/probes.bpf.c` 从未编译加载、运行时实际走 Netlink Connector + /proc 轮询。README 虽诚实标注"规划中"，但代码里的接入骨架全是注释，属于典型的"画饼"。
>
> 本文档是把 eBPF 从"规划"变成"可用"的工程计划。分 4 个里程碑，每个都可独立交付、独立验证。

---

## 背景：为什么现在没接入（而非"忘了"）

eBPF 的 CO-RE（Compile Once, Run Everywhere）需要一套**构建时工具链**，而项目当前的 CI/本地环境不具备：

| 依赖 | 用途 | 现状 |
|------|------|------|
| `clang` (≥14) | 把 `.bpf.c` 编译成 BPF 字节码 `.o` | CI 未装 |
| `libbpf` (≥1.0) | BPF 程序加载/attach 的 C 库 | CI 未装 |
| `bpftool` | 生成 BTF 骨架（skeleton）用于 CO-RE | CI 未装 |
| `libbpf-rs` / `libbpf-cargo` | Rust 绑定 + 构建脚本集成 | Cargo.toml 里被注释 |

所以"画饼"不是设计缺陷，是**环境工程债**——代码骨架（`probe.rs` 的注释块）已经写好了，缺的是把它激活的构建管线。

---

## 里程碑 M1：构建管线打通（不接业务，先能编译加载）

**目标**：让 `cargo build` 能编译 `probes.bpf.c` 并生成 skeleton，`immunity-ebpf` 启动时成功 attach 一个最小探针（不消费事件，只证明链路通）。

### 工作项

1. **CI 装 eBPF 工具链**（`.github/workflows/ci.yml` Linux job）：
   ```yaml
   - name: Install eBPF toolchain
     run: |
       sudo apt-get install -y clang libbpf-dev bpftool linux-headers-$(uname -r)
   ```

2. **取消注释 libbpf 依赖**（`antivirus-immunity-ebpf/Cargo.toml`）：
   ```toml
   libbpf-rs = "0.24"
   libbpf-cargo = "0.24"   # 提供 build.rs 集成,自动编译 .bpf.c
   ```

3. **加 `build.rs`**：用 `libbpf-cargo` 的 `Libbpf` 构建器，把 `bpf/probes.bpf.c` 编成 `immunity.bpf.o` 并生成 skeleton header。

4. **取消注释 `probe.rs` 的 ObjectBuilder/attach 代码**，先只 attach `handle_execve` 一个 tracepoint。

5. **启动验证**：`cargo run --bin immunity-ebpf`，确认日志打印 `[+] ProbeManager: eBPF probes attached (execve)` 而非现在的 Netlink fallback。

### 验收

- ❑ Linux CI 能编译 ebpf crate（含 .bpf.c）
- ❑ `immunity-ebpf` 启动时显示 eBPF 已 attach（不是 Netlink fallback）
- ❑ `bpftool prog show` 能看到加载的 BPF 程序

### 风险

- `libbpf-cargo` 的 build.rs 与 edition 2024 / resolver 3 的兼容性（预期无问题，但需验证）
- GitHub runner 的 `linux-headers` 版本可能与 BTF 不匹配；备选：用 `vmlinux.h` from BTFHub

---

## 里程碑 M2：Ring Buffer 事件消费（替换 Netlink）

**目标**：BPF 探针产生的事件通过 ring buffer 传到用户态，`ProbeManager::poll_events` 优先读 ring buffer，Netlink 降级为 fallback。

### 工作项

1. **定义共享 map**（`probes.bpf.c`）：声明一个 `struct { __uint(type, BPF_MAP_TYPE_RINGBUF); ... } events SEC(".maps");`

2. **定义事件结构体**（用户态和内核态共用，放 common crate 或 ebpf 内）：
   ```c
   struct event_t {
       u32 pid, ppid;
       char comm[16], path[256];
       u8 type;   // EXEC / EXIT / TCP / FILE / CRED
       // ...网络/文件子字段
   };
   ```

3. **探针里填充并提交事件**：`handle_execve` 用 `bpf_get_current_pid_tgid` + `bpf_probe_read_user_str` 读 comm/path，`bpf_ringbuf_output(&events, &e, sizeof(e), 0);`

4. **用户态消费**（`probe.rs`）：取消注释 `RingBufferBuilder` 代码，注册 callback 把 ring buffer 事件转成现有的 `RawProbeEvent`（复用已有结构体，下游 `policy.evaluate` 不用改）。

5. **优先级路由**：`poll_events()` 先 `ring_buf.poll(timeout)`，有事件就返回；ring buffer 不可用才退回 Netlink。

### 验收

- ❑ 跑一个进程，用户态收到 `RawProbeEvent{ event_type: Execve }` 来自 ring buffer（而非 Netlink）
- ❑ 杀掉探针（`bpftool prog detach`）后，自动降级到 Netlink，不崩溃

### 风险

- `bpf_probe_read_user_str` 读 `argv[0]` 的路径在某些内核版本受限；备选：只读 comm，路径仍走 `/proc/<pid>/exe`（TOCTOU 但可接受）
- ring buffer 大小（默认 4MB）在高 fork 风暴下可能丢事件；需调参 + 监控 `BPF_RB_LOST`

---

## 里程碑 M3：LSM / 网络探针接入（文件护栏 + 出站连接监控）

**目标**：激活 `security_file_open`（LSM）和 `tcp_connect`/`udp_sendmsg`（kprobe），让 README 宣称的"文件护栏"和"挖矿池/C2 端口检测"真正工作。

### 工作项

1. **文件护栏（LSM）**：
   - `probes.bpf.c` 加 `SEC("lsm/security_file_open")`，对 `protected_paths` 命中且进程不在白名单时返回 `-EPERM`
   - 用户态通过 ring buffer 收到 `FileOpen` 事件，记 `FileAccessBlocked`
   - **激活 `ResponseAction::BlockAccess`**：现在它只 `println!`，改成真正由 LSM 在内核态阻断（事件是"已阻断"的通知，不是"请求阻断"）

2. **网络监控（kprobe）**：
   - `SEC("kprobe/tcp_connect")` 捕获出站连接，提取 `dst_addr`/`dst_port`
   - 用户态 `policy.rs` 的 `evaluate_network`（目前是死代码）接入：命中挖矿池端口（3333/4444/...）或 C2 端口列表 → 标记
   - 目前 `policy.rs` 的 `TcpConnect`/`UdpSend` arm 不可达，M3 后可达

3. **删除死代码模块**：`filesystem.rs` / `network.rs` 现在是占位（从未被调用），M3 让 LSM/网络事件真正流入后，把这两个模块的逻辑合并进 `policy.rs` 并删除占位文件。

### 验收

- ❑ 尝试 `cat /etc/shadow`（非 root）被阻断，日志记 `FileAccessBlocked`
- ❑ `nc -v example.com 3333`（挖矿池端口）触发 `NetworkBlocked` 事件
- ❑ `filesystem.rs` / `network.rs` 被删除，无编译警告

### 风险

- LSM 钩子需要内核 ≥ 5.7 且 `CONFIG_BPF_LSM=y`；旧内核降级为"仅告警不阻断"
- kprobe 符号名跨内核版本会变（`tcp_v4_connect` vs `tcp_connect`）；用 `kprobe/tcp_v4_connect` + `kprobe/tcp_v6_connect` 双覆盖

---

## 里程碑 M4：容器/AI-Agent 场景强化 + 文档收敛

**目标**：让 eBPF 引擎在 Docker/K8s 和 AI Agent 沙盒场景真正可用，README 撤掉"规划中"标注。

### 工作项

1. **容器上下文精确化**：
   - 替换 `read_proc_cgroup_id` 的 `DefaultHasher`（不稳定）为内核的 `bpf_get_current_cgroup_id()`（64bit 真实 ID）
   - cgroup v1 兼容（目前只解析 v2 的 `0::/` 路径）

2. **AI Agent 沙盒策略**：
   - `policy.rs` 的 `ai-agent` profile 实质化：检测 Agent 进程的子进程尝试访问 `~/.ssh`、`/var/run/docker.sock`、`/etc/passwd` 等越界行为
   - 配合 M3 的 LSM 阻断

3. **资源自适应**：
   - Lite 模式（< 2C4G）下只保留 execve 探针，关闭 LSM/网络（降低 eBPF map 内存）

4. **文档更新**：
   - README 实现状态表：eBPF 探针从"🚧 规划中"改为"✅ 可用"
   - 删除 `probe.rs` 里大段注释代码
   - USER_MANUAL 增加 ebpf 引擎章节（或独立 `EBPF_MANUAL.md`）

### 验收

- ❑ Docker 容器内进程事件能正确关联到容器 ID
- ❑ AI Agent 进程访问 `~/.ssh` 被 LSM 阻断
- ❑ README 不再有"规划中"字样（针对 eBPF 部分）

---

## 实施建议

| 里程碑 | 工作量 | 前置 | 建议时机 |
|--------|--------|------|---------|
| **M1 构建管线** | 1-2 天 | CI 装 clang/libbpf | **立即**（解锁后续一切） |
| **M2 Ring Buffer** | 3-5 天 | M1 | M1 合并后 |
| **M3 LSM/网络** | 5-8 天 | M2 | M2 稳定后 |
| **M4 容器/收敛** | 3-5 天 | M3 | M3 验证后 |

**每个里程碑独立 PR，独立 CI 验证，可单独回滚。** M1 完成后"画饼"指控即不成立（探针真实加载运行），M2-M4 是能力深化。

## 关键决策点（需 maintainer 拍板）

1. **libbpf-rs 版本**：0.24 还是更新版？需确认与 edition 2024 的兼容。
2. **最低内核版本**：5.4（BTF）还是 5.7+（LSM）？影响 M3 的可用性范围。
3. **是否保留 Netlink 作为永久 fallback**：建议保留（老内核/无 BTF 环境仍可用），但文档标注"功能降级"。
