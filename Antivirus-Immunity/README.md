# Antivirus-Immunity

> **"An antivirus inspired by the immune system, augmented with local AI — now with eBPF kernel-level vision."**

[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-blue.svg)](https://ebpf.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 项目愿景

Antivirus-Immunity 是基于 **人工免疫系统 (AIS)** 理论的安全防护引擎，结合本地 AI 大模型进行深度研判。与传统依赖特征库的杀毒软件不同，本项目侧重于：

- **自我/非我识别** — 建立系统"正常态"基线，识别偏离行为
- **自适应模糊哈希免疫记忆** — CTPH (Ssdeep) + Imphash 多维度变种识别，告别 SHA256 精确匹配的脆弱性
- **异步推迟阻断** — Linux 端 SIGSTOP 挂起可疑进程，AI 500ms 内出 Verdict 后决定放行或击杀；避免"先运行、后研判"
- **危险信号理论** — 监测系统压力信号（CPU 飙升、进程洪水等），动态调整免疫灵敏度
- **AI 深度分析 (Cortex)** — 对模糊案例调用本地 LLM 进行自然语言推理
- **自适应性** — 对未知攻击手段做出反应，而非依赖已知签名

### 目标场景

- ☁️ 云 ECS / VPS（阿里云、AWS、腾讯云）
- 🐳 Docker / Kubernetes 容器
- 🤖 AI Agent 运行沙盒（LangChain, AutoGPT 等自动化 Agent 的边界护栏）
- 💡 轻量实例适配（1C1G / 2C2G 自动切换 Lite 模式）

---

## 实现状态 (Implementation Status)

> ⚠️ 本项目是**研究 / 教育性质**的原型，**不能替代生产级杀毒或 EDR**。下表如实标注各能力的真实状态，避免对"已实现"产生误解。

| 能力 | 状态 | 说明 |
|------|------|------|
| Windows 进程监控 (ToolHelp32) | ✅ 可用 | 轮询新进程；**注意**：仅评估新出现的 PID，基线已存在的进程与生命周期短于轮询间隔的进程会被漏检 |
| YARA / 路径验证 / 模糊哈希 / 危险信号 | ✅ 可用 | Windows 核心管线，已加固（见下方"安全加固"） |
| AI Cortex (Ollama) | ✅ 可用 | 可选；不可用时自动降级为规则引擎 |
| Linux 进程事件源 (Netlink Connector) | ✅ 可用 | `NETLINK_CONNECTOR` 内核推送，订阅 FORK/EXEC/EXIT |
| Linux `/proc` 轮询兜底 | ✅ 可用 | 无 Netlink 时的最终降级路径 |
| 异步推迟阻断 (SIGSTOP→AI→SIGKILL/SIGCONT) | ✅ 可用 | 已加固 PID 复用竞态防护 |
| **eBPF CO-RE 探针加载 / Ring Buffer 消费** | 🚧 规划中 (v0.5) | `bpf/probes.bpf.c` 已编写但**尚未通过 libbpf-rs 加载/挂载**；当前运行时实际使用 Netlink/`proc` |
| XDP/TC 网络阻断 · LSM 文件护栏内核实现 | 🚧 规划中 (v0.6) | 探针 C 源码存在，内核侧强制尚未接入 |

---

## 架构设计

```
                    ┌─────────────────────────────────────┐
                    │         Workspace (Cargo)           │
                    ├─────────────────────────────────────┤
                    │                                     │
  ┌─────────────────┴─────────┐   ┌──────────────────────┴──────────┐
  │  antivirus-immunity-core  │   │  antivirus-immunity-ebpf        │
  │  (Windows · Legacy v0.3)  │   │  (Linux · v0.4 · Netlink 在用) │
  │                           │   │                                 │
  │  ToolHelp32 进程扫描      │   │  eBPF 探针 (CO-RE · 规划中)     │
  │  YARA 规则引擎            │   │  Netlink Connector (零轮询)     │
  │  Windows API              │   │  Async Deferred Blocking        │
  │  Fuzzy Hash (Ssdeep+Imph) │   │  Docker/K8s 容器感知            │
  │  Quarantine (Rename隔离)  │   │  策略引擎 + AI Agent 沙盒       │
  └─────────┬─────────────────┘   └──────────────┬──────────────────┘
            │                                    │
            └────────────┬───────────────────────┘
                         │
            ┌────────────▼────────────────────┐
            │  antivirus-immunity-common      │
            │  (跨平台共享层)                   │
            │                                 │
            │  SecurityEvent 统一事件格式      │
            │  AI Cortex (Ollama LLM)         │
            │  Logger (JSONL 结构化日志)       │
            │  HashCache (LRU SHA256)         │
            └─────────────────────────────────┘
```

### 多层评估管线

```
新进程 ──→ YARA扫描(黑名单) ──→ 路径验证(MHC) ──→ SHA256 精确匹配 ──→ 模糊哈希匹配(CTPH+Imphash)
              │                      │                      │                      │
        匹配=CRITICAL          伪装=CRITICAL          精确=SAFE         Ssdeep≥80%=SAFE
              │                      │                      │                Imphash=SAFE
              └──────────────────────┼──────────────────────┘
                                     ↓
                          危险信号关联(Danger Theory)
                                     │
                              ┌──────┴──────┐
                              │  AI Cortex  │ ← 仅对模糊案例启用
                              │  深度分析    │
                              └──────┬──────┘
                                     ↓
                            分级响应 (Log/Kill/Quarantine)
```

### 事件源降级策略 (Linux)

```
poll_events() 优先级:
  1. eBPF Ring Buffer      (生产 — 内核探针)  ← 🚧 规划中, 尚未接入
  2. Netlink Connector      (内核推送, 毫秒级延迟, 零 CPU 轮询)  ← ✅ 当前实际使用
  3. /proc 轮询             (最终兜底 — 极老内核兼容)  ← ✅ 降级路径
```

### 异步推迟阻断 (Async Deferred Blocking)

```
Netlink 检测 EXEC → SIGSTOP 进程 → AI Cortex (500ms timeout)
    ├─ TERMINATE/MALICIOUS → SIGKILL (先校验 /proc starttime, 防 PID 复用误杀)
    ├─ SAFE/ALLOW          → SIGCONT (恢复)
    └─ 超时                → SIGCONT + 日志 (默认放行)
```

---

## 项目结构

```
Antivirus-Immunity/
├── Cargo.toml                          # Workspace 定义
├── README.md
├── USER_MANUAL.md
│
├── antivirus-immunity-common/          # 跨平台共享层
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── event.rs                    # SecurityEvent / ProcessInfo / 枚举
│       ├── logger.rs                   # JSONL 结构化日志 (50MB 自动轮转)
│       ├── ai_cortex.rs               # Ollama LLM 接口
│       └── hash_cache.rs             # LRU SHA256 缓存
│
├── antivirus-immunity-ebpf/            # Linux eBPF 引擎 (v0.4.0)
│   ├── Cargo.toml
│   ├── build.sh                        # eBPF 编译脚本
│   ├── bpf/
│   │   └── probes.bpf.c               # CO-RE 内核探针 (C)
│   └── src/
│       ├── main.rs                     # CLI + 事件循环 + 异步推迟阻断
│       ├── probe.rs                    # 探针管理 (eBPF / Netlink / /proc)
│       ├── netlink_connector.rs       # NETLINK_CONNECTOR 零轮询进程监听
│       ├── container.rs               # Docker/K8s 容器上下文
│       ├── policy.rs                  # 安全策略引擎
│       ├── process_tree.rs            # 进程族谱追踪
│       ├── resource_aware.rs          # 硬件感知 + Lite 模式
│       ├── network.rs                 # 网络连接监控
│       └── filesystem.rs             # 文件系统护栏
│
└── antivirus-immunity-core/            # Windows 引擎 (v0.3.0 · Legacy)
    ├── Cargo.toml
    ├── antigens.yar                    # 12+ YARA 规则
    ├── immunity_db.json               # V2 模糊哈希免疫记忆数据库
    └── src/
        ├── main.rs
        ├── receptor/                   # TollLikeReceptor + HashCache
        │   ├── toll_like_receptor.rs
        │   └── hash_cache.rs
        ├── immune/                     # 决策中枢
        │   ├── memory_b_cell.rs       # 免疫记忆 (SHA256 + Ssdeep + Imphash)
        │   ├── fuzzy_hash.rs          # CTPH + Imphash 模糊哈希引擎
        │   ├── danger_theory.rs       # 危险信号理论
        │   ├── path_validator.rs      # 路径验证 (MHC)
        │   └── ai_cortex.rs           # AI Cortex
        └── effector/                   # 响应层
            ├── cytotoxic_t_cell.rs    # 进程终止 (细胞凋亡)
            └── quarantine.rs          # 隔离区管理 (rename-based)
```

---

## 内核探针挂载点 (Linux)

> 🚧 下表探针已在 `bpf/probes.bpf.c` 中以 CO-RE 形式编写，但**当前尚未通过 libbpf-rs 加载挂载**（计划于 v0.5）。在此之前，进程事件由 Netlink Connector 提供，网络 / 文件 / 提权事件尚未接入策略引擎。

| 探针 | 挂载点 | 功能 | Lite模式 |
|------|--------|------|----------|
| 进程执行 | `tracepoint/syscalls/sys_enter_execve` | 捕获所有新进程 | ✅ |
| TCP 外联 | `kprobe/tcp_connect` | 检测出站连接 (挖矿池/C2/反弹shell) | ✅ |
| 提权检测 | `kprobe/commit_creds` | UID 变更至 root | ✅ |
| 文件访问 | `LSM/security_file_open` | 保护敏感文件 (/etc/shadow 等) | ❌ |
| 文件创建 | `LSM/security_inode_create` | 检测可疑文件写入 | ❌ |
| 网络阻断 | `XDP / TC` | 内核级包过滤 | ❌ |

---

## 安全策略配置 (Profiles)

| Profile | 场景 | 网络监控 | 文件护栏 | AI分析 | 提权检测 |
|---------|------|----------|----------|--------|----------|
| **server** | 标准云服务器 | ✅ | ✅ | ✅ | ✅ |
| **container** | Docker/K8s | ✅ | ✅ (docker.sock重点) | ✅ | ✅ |
| **ai-agent** | AI Agent 沙盒 | ✅ (严格边界) | ✅ | ✅ | ✅ |
| **lite** | 1C1G 轻量实例 | ✅ (核心) | ❌ | ❌ | ✅ |

---

## 快速开始

### 前置要求

```bash
# Linux (Ubuntu/Debian)
sudo apt install clang llvm libbpf-dev bpftool
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Ollama (可选, 用于 AI Cortex)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:3b
```

### 编译与运行

```bash
# 编译整个 workspace
cargo build --release

# 运行 eBPF 引擎 (需要 root 权限)
sudo ./target/release/immunity-ebpf --profile server

# AI Agent 沙盒模式
sudo ./target/release/immunity-ebpf --profile ai-agent --ai --ai-model qwen2.5:3b

# Lite 模式 (自动检测, 也可手动)
sudo ./target/release/immunity-ebpf --profile server --max-memory-mb 30
```

### 命令行参数 (eBPF 引擎)

```
USAGE: immunity-ebpf [OPTIONS]

OPTIONS:
  -m, --mode <MODE>           运行模式: monitor, enforce, learn [default: monitor]
  -p, --profile <PROFILE>     策略配置: server, container, ai-agent [default: server]
      --ai                    启用 AI Cortex
      --ai-model <MODEL>      AI 模型 [default: qwen2.5:3b]
      --ai-endpoint <URL>     Ollama 地址 [default: http://localhost:11434]
      --protected-paths <P>   受保护路径 (逗号分隔)
      --max-memory-mb <MB>    内存上限 [default: 100]
      --output <FORMAT>       输出格式: text, json [default: text]
```

### Windows 引擎

```bash
cargo run -p antivirus-immunity-core -- --mode learn    # 学习系统正常态
cargo run -p antivirus-immunity-core -- --mode monitor  # 被动监控
cargo run -p antivirus-immunity-core -- --mode active --policy quarantine --ai true  # 主动防御
cargo run -p antivirus-immunity-core -- --mode quarantine-list  # 查看隔离区
```

---

## 生物学类比

| 生物免疫 | 本项目组件 | 功能 |
|----------|-----------|------|
| Toll 样受体 (TLR) | `probe.rs` / eBPF 探针 | 检测入侵的第一道传感器 |
| 抗原呈递 | `process_tree.rs` | 追踪进程来源，还原攻击链 |
| T 细胞分化 | `policy.rs` | 根据上下文选择杀伤/容忍/观察 |
| 记忆 B 细胞 | `memory_b_cell.rs` / `fuzzy_hash.rs` | 多维度模糊哈希免疫记忆，识别病毒变种 |
| 上皮屏障 | `filesystem.rs` | 保护关键文件 |
| 补体系统 | `network.rs` | 网络巡逻标记外来物 |
| 大脑皮层 | `ai_cortex.rs` | 对疑难案例的深度智能分析 |
| 免疫记忆 | `logger.rs` | JSONL 审计日志，事后回溯 |
| 细胞凋亡 | `cytotoxic_t_cell.rs` | 终止恶意进程 |
| 淋巴结隔离 | `quarantine.rs` | 移星换斗式文件隔离 (rename-based) |
| 新陈代谢调节 | `resource_aware.rs` | 资源不足时进入节能模式 |
| 组织定位 | `container.rs` | 感知进程所在的容器环境 |

---

## 路线图

- [x] **v0.3.0** — Windows 引擎 (ToolHelp32 + YARA + AI Cortex + Fuzzy Hash + Quarantine)
- [x] **v0.4.0** — Linux eBPF 架构骨架 + 策略引擎 + Netlink Connector + Async Deferred Blocking
- [x] **v0.4.1** — 安全加固（见下方"安全加固"章节）
- [ ] **v0.5.0** — 真实 eBPF CO-RE 探针加载 (libbpf-rs) + Ring Buffer 消费
- [ ] **v0.6.0** — XDP/TC 网络阻断 + LSM 文件护栏内核实现
- [ ] **v0.7.0** — K8s Sidecar 部署 + Prometheus metrics + 威胁情报黑名单模糊哈希库
- [ ] **v1.0.0** — 生产就绪

---

## 核心优化亮点

### Windows Quarantine: 移星换斗 (Rename-based Isolation)

利用 Windows 允许对运行中文件在同卷内 `MoveFileExW` 的机制，先 `fs::rename` 移走磁盘文件再 `TerminateProcess` 杀进程。恶意软件无法自恢复。隔离文件以 UUID + `.quarantine` 后缀存放，防止误双击执行；manifest 的 hex 编码仅为**避免明文与防误读，并非加密或防篡改**。

### Linux: Netlink Connector 零轮询事件源

替代 `/proc` 轮询，通过 `NETLINK_CONNECTOR` + `CN_IDX_PROC` 订阅内核 FORK/EXEC/EXIT 事件。内核主动推送，毫秒级延迟，完全消除 TOCTOU 竞态和 CPU 空转。

### Linux: Async Deferred Blocking

对可疑进程立即 `SIGSTOP` 挂起，调用本地 LLM 在 500ms 内给出 Verdict：恶意则 `SIGKILL`，安全或超时则 `SIGCONT` 恢复。避免"先运行、后研判"的安全滞后。

### Fuzzy Hash 免疫记忆 (CTPH + Imphash)

- **CTPH (Ssdeep)**: 纯 Rust 实现，分片模糊哈希。插入/删除/修改局部段落仅影响局部哈希，相似度 ≥80% 即识别为同源变种
- **Imphash**: PE (pelite) / ELF (goblin) 导入表结构哈希。无论核心代码如何混淆，导入的系统 API 签名高度稳定，专门用于恶意家族聚类
- **数据库 V2**: `immunity_db.json` 升级为多哈希签名格式，自动迁移 V1 数据
- **块大小感知比对**: Ssdeep 相似度仅在相同 / 相邻块大小档位间比较，避免跨档位 edit distance 产生的假"同源"匹配

---

## 安全加固 (v0.4.1)

针对一次代码审计的发现，修复了若干会导致**崩溃**或**误判**的问题：

### 崩溃 / 稳定性
- **日志降级不再 panic**：原 `Logger::new()` 失败后会再次 `unwrap()` 重试，必然二次 panic。改为 `Logger::disabled()` 空操作降级，引擎继续运行（core + common + ebpf）。
- **UTF-8 截断 panic**：多处 `&s[..s.len().min(N)]` 在多字节字符（如 AI 返回的中文 reasoning、含中文的路径）中间切片会 panic。统一改用按字符边界截断的 `truncate_chars`。

### 检测有效性
- **路径信任收窄**：`C:\Windows` 整棵树曾被信任，导致用户可写的 `C:\Windows\Temp`、`Tasks`、`tracing` 等常见落地目录被判为可信；且 `starts_with` 会把 `C:\WindowsApps`、`C:\Windows-x` 误判为 Windows 内部。新增可写子目录黑名单 + 路径边界感知的 `is_within`，并补充单元测试。
- **AI 提示注入防护**：进程名 / 路径 / YARA 命中等**攻击者可控字段**此前被原样拼入 LLM 提示，可被构造来操纵裁决。现对每个不可信字段做单行化清洗并以 `«»` 包裹，并显式告知模型其中内容为数据、不可作为指令。
- **AI 自主击杀收口**：模型给出 `TERMINATE/QUARANTINE` 时不再无条件执行。新增门槛——置信度 ≥ 0.8 且目标不在 `Verified/TrustedLocation` 系统位置，否则仅记录待人工复核，限制小模型误报的"爆炸半径"。

### Linux 端
- **PID 复用竞态防护**：异步推迟阻断在 500ms AI 窗口后才发 `SIGKILL`，期间原进程可能已退出并被复用 PID。现以 `/proc/<pid>/stat` 的 starttime 作指纹，击杀前重新校验，避免误杀无辜进程。
- **运行时输出诚实化**：启动横幅不再谎称 "Probes initialized: tracepoint/kprobe/LSM..."（实际未加载 eBPF），改为标注"规划中、当前使用 Netlink/proc"。

### 工程
- 补齐缺失的 [LICENSE](LICENSE)（MIT，徽章原先指向不存在的文件）。

> 已知局限（尚未处理）：Windows 端基于轮询，会漏检基线既有进程及生命周期极短的进程；`FuzzyHasher::compute_all` 对同一文件存在多次读取的性能开销；部分 YARA 规则较宽泛，主动模式下可能误隔离正常软件。详见审计报告。

---

## 许可证

MIT License

## 作者

**KingDragon-yc** — [GitHub](https://github.com/KingDragon-yc)
