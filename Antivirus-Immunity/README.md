# Antivirus-Immunity# Antivirus-Immunity# Antivirus-Immunity# Antivirus-Immuni



> **"A kind of Antivirus inspired by immune system, augmented with local AI — now with eBPF kernel-level vision."**



[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)> **"A kind of Antivirus inspired by immune system, augmented with local AI — now with eBPF kernel-level vision."**本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件，并集成**本地 AI 模型**作为免疫决策中枢。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：

[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-blue.svg)](https://ebpf.io/)

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)



---[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)> **"A kind of Antivirus inspired by immune system, augmented with local AI."**



## 📖 项目愿景[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-blue.svg)](https://ebpf.io/)



Antivirus-Immunity 是基于**人工免疫系统 (AIS)** 理论的安全防护引擎，结合本地 AI 大模型进行深度研判。与传统依赖特征库的杀毒软件不同，本项目侧重于：[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统"正常态"的基线，识别入侵者。



- **自我/非我识别** — 建立系统"正常态"基线，识别偏离行为

- **危险信号理论** — 监测系统压力信号（CPU 飙升、进程洪水等），动态调整免疫灵敏度

- **AI 深度分析 (Cortex)** — 对模糊案例调用本地 LLM 进行自然语言推理---## 📖 项目愿景 (Vision)

- **自适应性** — 对未知攻击手段做出反应，而非依赖已知签名



### v0.4.0: All-in Linux + eBPF

## 📖 项目愿景> **"A kind of Antivirus inspired by immune system, augmented with local AI."**- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。

本版本的战略方向：**放弃 Windows 主战场，全面转向 Linux 云服务器 + eBPF 内核级监控。**



目标场景：

- ☁️ 云 ECS / VPS（阿里云、AWS、腾讯云）Antivirus-Immunity 是基于**人工免疫系统 (AIS)** 理论的安全防护引擎，结合本地 AI 大模型进行深度研判。与传统依赖特征库的杀毒软件不同，本项目侧重于：本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件，并集成**本地 AI 模型**作为免疫决策中枢。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：

- 🐳 Docker / Kubernetes 容器

- 🤖 AI Agent 运行沙盒（LangChain, AutoGPT 等自动化 Agent 的边界护栏）

- 💡 轻量实例适配（1C1G / 2C2G 自动切换 Lite 模式）

- **自我/非我识别** — 建立系统"正常态"基线，识别偏离行为- **危险信号理论 (Danger Theory)**: 通过监测系统压力信号（CPU 飙升、进程洪水等）动态调整免疫灵敏度。

---

- **危险信号理论** — 监测系统压力信号（CPU 飙升、进程洪水等），动态调整免疫灵敏度

## 🏗 架构设计

- **AI 深度分析 (Cortex)** — 对模糊案例调用本地 LLM 进行自然语言推理- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统"正常态"的基线，识别入侵者。

```

                    ┌─────────────────────────────────────┐- **自适应性** — 对未知攻击手段做出反应，而非依赖已知签名

                    │         Workspace (Cargo)           │

                    ├─────────────────────────────────────┤- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。## 📖 项目愿景 (Vision)- **AI 深度分析 (AI Cortex)**: 对模糊案例使用本地 LLM 进行自然语言推理，弥补规则引擎的刚性不足。

                    │                                     │

  ┌─────────────────┴─────────┐   ┌──────────────────────┴──────────┐### v0.4.0: All-in Linux + eBPF

  │  antivirus-immunity-core  │   │  antivirus-immunity-ebpf        │

  │  (Windows · Legacy v0.3)  │   │  (Linux · eBPF v0.4 · Active)  │- **危险信号理论 (Danger Theory)**: 通过监测系统压力信号（CPU 飙升、进程洪水等）动态调整免疫灵敏度。

  │                           │   │                                 │

  │  ToolHelp32 进程扫描      │   │  eBPF 内核探针 (CO-RE)          │本版本的战略方向：**放弃 Windows 主战场，全面转向 Linux 云服务器 + eBPF 内核级监控。**

  │  YARA 规则引擎            │   │  进程/网络/文件/提权 监控       │

  │  Windows API              │   │  Docker/K8s 容器感知            │- **AI 深度分析 (AI Cortex)**: 对模糊案例使用本地 LLM 进行自然语言推理，弥补规则引擎的刚性不足。- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。s-Immunity

  └─────────┬─────────────────┘   │  策略引擎 + AI Agent 沙盒       │

            │                     └──────────────┬──────────────────┘目标场景：

            │                                    │

            └────────────┬───────────────────────┘- ☁️ 云 ECS / VPS（阿里云、AWS、腾讯云）- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。

                         │

            ┌────────────▼────────────────────┐- 🐳 Docker / Kubernetes 容器

            │  antivirus-immunity-common      │

            │  (跨平台共享层)                   │- 🤖 AI Agent 运行沙盒（LangChain, AutoGPT 等自动化 Agent 的边界护栏）本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件，并集成**本地 AI 模型**作为免疫决策中枢。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：

            │                                 │

            │  SecurityEvent 统一事件格式      │- 💡 轻量实例适配（1C1G / 2C2G 自动切换 Lite 模式）

            │  AI Cortex (Ollama LLM)         │

            │  Logger (JSONL 结构化日志)       │## 🏗 架构设计 (Architecture)

            │  HashCache (LRU SHA256)         │

            └─────────────────────────────────┘---

```

> **"A kind of Antivirus inspired by immune system, augmented with local AI."**

### eBPF 引擎架构

## 🏗 架构设计

```

┌──────────────────────────────────────────────────┐系统由四个核心层组成，模拟生物免疫回路：

│  Kernel Space (eBPF probes, C/CO-RE)             │

│  ┌───────────┐ ┌────────────┐ ┌───────────────┐ │```

│  │ execve    │ │ tcp_connect│ │ LSM file_open │ │

│  │ tracepoint│ │ kprobe     │ │ bpf hook      │ │                    ┌─────────────────────────────────────┐- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统"正常态"的基线，识别入侵者。

│  └─────┬─────┘ └──────┬─────┘ └───────┬───────┘ │

│        └───────────────┼───────────────┘         │                    │         Workspace (Cargo)           │

│               BPF Ring Buffer                    │

├────────────────────────┼─────────────────────────┤                    ├─────────────────────────────────────┤```

│  User Space (Rust)     │                         │

│               ┌────────▼─────────┐               │                    │                                     │

│               │  Event Consumer  │               │

│               └────────┬─────────┘               │  ┌─────────────────┴─────────┐   ┌──────────────────────┴──────────┐┌─────────────────────────────────────────────────────────────┐- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。## 📖 项目愿景 (Vision)

│     ┌──────────────────┼──────────────────┐      │

│     │                  │                  │      │  │  antivirus-immunity-core  │   │  antivirus-immunity-ebpf        │

│  ┌──▼───────┐  ┌───────▼──────┐  ┌───────▼───┐  │

│  │ Policy   │  │  AI Cortex   │  │ Effector  │  │  │  (Windows · Legacy v0.3)  │   │  (Linux · eBPF v0.4 · Active)  ││                    AI Cortex (大脑皮层)                       │

│  │ Engine   │  │  (Ollama)    │  │ (kill/    │  │

│  │ (rules+  │  │              │  │  block/   │  │  │                           │   │                                 │

│  │  profile)│  │              │  │  log)     │  │

│  └──────────┘  └──────────────┘  └───────────┘  │  │  ToolHelp32 进程扫描      │   │  eBPF 内核探针 (CO-RE)          ││         Local LLM for deep analysis of ambiguous cases       │- **危险信号理论 (Danger Theory)**: 通过监测系统压力信号（CPU 飙升、进程洪水等）动态调整免疫灵敏度。

│                       │                          │

│               ┌───────▼───────┐                  │  │  YARA 规则引擎            │   │  进程/网络/文件/提权 监控       │

│               │    Logger     │                  │

│               │   (JSONL)     │                  │  │  Windows API              │   │  Docker/K8s 容器感知            ││                   (Ollama + qwen2.5:3b)                      │

│               └───────────────┘                  │

└──────────────────────────────────────────────────┘  └─────────┬─────────────────┘   │  策略引擎 + AI Agent 沙盒       │

```

            │                     └──────────────┬──────────────────┘├─────────────────────────────────────────────────────────────┤- **AI 深度分析 (AI Cortex)**: 对模糊案例使用本地 LLM 进行自然语言推理，弥补规则引擎的刚性不足。本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：

### 内核探针挂载点

            │                                    │

| 探针 | 挂载点 | 功能 | Lite模式 |

|------|--------|------|----------|            └────────────┬───────────────────────┘│                                                              │

| 进程执行 | `tracepoint/syscalls/sys_enter_execve` | 捕获所有新进程 | ✅ |

| TCP 外联 | `kprobe/tcp_connect` | 检测出站连接 (挖矿池/C2/反弹shell) | ✅ |                         │

| 提权检测 | `kprobe/commit_creds` | UID 变更至 root | ✅ |

| 文件访问 | `LSM/security_file_open` | 保护敏感文件 (/etc/shadow 等) | ❌ |            ┌────────────▼────────────────────┐│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统“正常态”的基线，识别入侵者。

| 文件创建 | `LSM/security_inode_create` | 检测可疑文件写入 | ❌ |

| 网络阻断 | `XDP / TC` | 内核级包过滤 | ❌ |            │  antivirus-immunity-common      │



---            │  (跨平台共享层)                   ││  │   Receptor    │  │   Immune     │  │    Effector       │  │



## 📦 项目结构            │                                 │



```            │  SecurityEvent 统一事件格式      ││  │   感知层      │  │   决策层      │  │    响应层          │  │- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。

Antivirus-Immunity/

├── Cargo.toml                          # Workspace 定义            │  AI Cortex (Ollama LLM)         │

├── README.md

├── USER_MANUAL.md            │  Logger (JSONL 结构化日志)       ││  │              │  │              │  │                   │  │

│

├── antivirus-immunity-common/          # 跨平台共享层            │  HashCache (LRU SHA256)         │

│   ├── Cargo.toml

│   └── src/            └─────────────────────────────────┘│  │ TLR (进程监控)│→│ Memory B Cell│→│ Cytotoxic T Cell  │  │## 🏗 架构设计 (Architecture)- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。

│       ├── lib.rs

│       ├── event.rs                    # SecurityEvent / ProcessInfo / 枚举```

│       ├── logger.rs                   # JSONL 结构化日志 (50MB 自动轮转)

│       ├── ai_cortex.rs               # Ollama LLM 接口│  │ Hash Cache   │  │ Path Valid.  │  │ Quarantine        │  │

│       └── hash_cache.rs             # LRU SHA256 缓存

│### eBPF 引擎架构

├── antivirus-immunity-ebpf/            # Linux eBPF 引擎 (v0.4.0)

│   ├── Cargo.toml│  │              │  │ Danger Theory│  │                   │  │

│   ├── build.sh                        # eBPF 编译脚本

│   ├── bpf/```

│   │   └── probes.bpf.c               # CO-RE 内核探针 (C)

│   └── src/┌──────────────────────────────────────────────────┐│  │              │  │ YARA Engine  │  │                   │  │

│       ├── main.rs                     # CLI + 事件循环 + 资源感知

│       ├── probe.rs                    # eBPF 探针管理 (/proc fallback)│  Kernel Space (eBPF probes, C/CO-RE)             │

│       ├── container.rs               # Docker/K8s 容器上下文

│       ├── policy.rs                  # 安全策略引擎 (Server/Container/AI-Agent/Lite)│  ┌───────────┐ ┌────────────┐ ┌───────────────┐ ││  └──────────────┘  └──────────────┘  └───────────────────┘  │系统由四个核心层组成，模拟生物免疫回路：## 🏗 架构设计 (Architecture)

│       ├── process_tree.rs            # 进程族谱追踪 (攻击链还原)

│       ├── resource_aware.rs          # 硬件感知 + Lite 模式自动切换│  │ execve    │ │ tcp_connect│ │ LSM file_open │ │

│       ├── network.rs                 # 网络连接监控 (反弹shell/C2检测)

│       └── filesystem.rs             # 文件系统护栏 (敏感路径保护)│  │ tracepoint│ │ kprobe     │ │ bpf hook      │ ││                                                              │

│

└── antivirus-immunity-core/            # Windows 引擎 (v0.3.0 · Legacy)│  └─────┬─────┘ └──────┬─────┘ └───────┬───────┘ │

    ├── Cargo.toml

    ├── antigens.yar                    # 12+ YARA 规则│        └───────────────┼───────────────┘         │├─────────────────────────────────────────────────────────────┤

    └── src/

        ├── main.rs│               BPF Ring Buffer                    │

        ├── receptor/                   # TollLikeReceptor + HashCache

        ├── immune/                     # MemoryBCell + DangerTheory + PathValidator + AiCortex├────────────────────────┼─────────────────────────┤│                    Logger (免疫记忆日志)                       │

        └── effector/                   # CytotoxicTCell + Quarantine

```│  User Space (Rust)     │                         │



---│               ┌────────▼─────────┐               ││              Structured JSONL event logging                   │```系统由三个核心部分组成，模拟生物免疫回路：



## 🔧 安全策略配置 (Profiles)│               │  Event Consumer  │               │



| Profile | 场景 | 网络监控 | 文件护栏 | AI分析 | 提权检测 |│               └────────┬─────────┘               │└─────────────────────────────────────────────────────────────┘

|---------|------|----------|----------|--------|----------|

| **server** | 标准云服务器 | ✅ | ✅ | ✅ | ✅ |│     ┌──────────────────┼──────────────────┐      │

| **container** | Docker/K8s | ✅ | ✅ (docker.sock重点) | ✅ | ✅ |

| **ai-agent** | AI Agent 沙盒 | ✅ (严格边界) | ✅ | ✅ | ✅ |│     │                  │                  │      │```┌─────────────────────────────────────────────────────────────┐

| **lite** | 1C1G 轻量实例 | ✅ (核心) | ❌ | ❌ | ✅ |

│  ┌──▼───────┐  ┌───────▼──────┐  ┌───────▼───┐  │

### AI Agent 沙盒护栏

│  │ Policy   │  │  AI Cortex   │  │ Effector  │  │

AI Agent (如 LangChain/AutoGPT) 需要执行代码，但边界必须受控：

│  │ Engine   │  │  (Ollama)    │  │ (kill/    │  │

- ✅ 允许：`python3`, `node`, `npm`, `pip`, `cargo`, `gcc`, `git`

- ⛔ 禁止：访问 `/etc/shadow`, `/root/.ssh/`, `/var/run/docker.sock`│  │ (rules+  │  │              │  │  block/   │  │### 1. 感知层 (Sensors / Innate Immunity)│                    AI Cortex (大脑皮层)                       │### 1. 感知层 (Sensors / Innate Immunity)

- ⛔ 禁止：连接到端口 4444/5555/8888/9999（常见 C2/挖矿端口）

- ⚠️ 监控：Shell 被脚本运行时（python/perl/ruby）直接调起 → 反弹 shell 疑似│  │  profile)│  │              │  │  log)     │  │



---│  └──────────┘  └──────────────┘  └───────────┘  │*对应生物学：皮肤、Toll 样受体*



## 🚀 快速开始│                       │                          │



### 前置要求│               ┌───────▼───────┐                  │- **TollLikeReceptor**: 进程快照 + 差分扫描，检测新进程│         Local LLM for deep analysis of ambiguous cases       │*对应生物学：皮肤、巨噬细胞*



```bash│               │    Logger     │                  │

# Linux (Ubuntu/Debian)

sudo apt install clang llvm libbpf-dev bpftool│               │   (JSONL)     │                  │- **HashCache**: LRU 哈希缓存，避免重复计算 SHA256（补体调理素标记）

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

│               └───────────────┘                  │

# Ollama (可选, 用于 AI Cortex)

curl -fsSL https://ollama.com/install.sh | sh└──────────────────────────────────────────────────┘- **SafeHandle**: RAII 包装器，确保 Windows 句柄安全释放│                   (Ollama + qwen2.5:3b)                      │- **功能**: 负责实时监控系统状态。

ollama pull qwen2.5:3b

``````



### 编译与运行



```bash### 内核探针挂载点

# 编译整个 workspace

cargo build --release### 2. 决策层 (Core / Adaptive Immunity)├─────────────────────────────────────────────────────────────┤- **技术**: 



# 运行 eBPF 引擎 (需要 root 权限)| 探针 | 挂载点 | 功能 | Lite模式 |

sudo ./target/release/immunity-ebpf --profile server

|------|--------|------|----------|*对应生物学：T细胞、B细胞、淋巴结*

# AI Agent 沙盒模式

sudo ./target/release/immunity-ebpf --profile ai-agent --ai --ai-model qwen2.5:3b| 进程执行 | `tracepoint/syscalls/sys_enter_execve` | 捕获所有新进程 | ✅ |



# Lite 模式 (自动检测, 也可手动)| TCP 外联 | `kprobe/tcp_connect` | 检测出站连接 (挖矿池/C2/反弹shell) | ✅ |- **Memory B Cell**: SHA256 哈希白名单持久化（免疫记忆）│                                                              │    - Windows ETW (Event Tracing for Windows)

sudo ./target/release/immunity-ebpf --profile server --max-memory-mb 30

| 提权检测 | `kprobe/commit_creds` | UID 变更至 root | ✅ |

# 仅编译 eBPF 内核探针

cd antivirus-immunity-ebpf && bash build.sh probes| 文件访问 | `LSM/security_file_open` | 保护敏感文件 (/etc/shadow 等) | ❌ |- **PathValidator (MHC)**: 路径验证，检测进程名伪装（如 svchost.exe 出现在非 System32 目录）

```

| 文件创建 | `LSM/security_inode_create` | 检测可疑文件写入 | ❌ |

### 命令行参数

| 网络阻断 | `XDP / TC` | 内核级包过滤 | ❌ |- **DangerTheoryEngine**: 系统压力信号监测（CPU/内存/进程洪水），动态调整免疫灵敏度│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │    - File System Minifilter (文件变动监控)

```

USAGE: immunity-ebpf [OPTIONS]



OPTIONS:---- **YARA Engine**: 已知恶意软件特征匹配（抗原数据库，12+ 条规则）

  -m, --mode <MODE>           运行模式: monitor, enforce, learn [default: monitor]

  -p, --profile <PROFILE>     策略配置: server, container, ai-agent [default: server]

      --ai                    启用 AI Cortex

      --ai-model <MODEL>      AI 模型 [default: qwen2.5:3b]## 📦 项目结构│  │   Receptor    │  │   Immune     │  │    Effector       │  │    - Process Callbacks (进程创建/销毁监控)

      --ai-endpoint <URL>     Ollama 地址 [default: http://localhost:11434]

      --protected-paths <P>   受保护路径 (逗号分隔)

      --max-memory-mb <MB>    内存上限 [default: 100]

      --output <FORMAT>       输出格式: text, json [default: text]```### 3. AI 决策中枢 (AI Cortex / Cerebral Cortex)

```

Antivirus-Immunity/

---

├── Cargo.toml                          # Workspace 定义*对应生物学：大脑皮层*│  │   感知层      │  │   决策层      │  │    响应层          │  │

## 🧬 生物学类比

├── README.md

| 生物免疫 | 本项目组件 | 功能 |

|----------|-----------|------|├── USER_MANUAL.md- **AiCortex**: 通过 Ollama 调用本地 LLM，对模糊案例进行深度分析

| Toll 样受体 (TLR) | `probe.rs` / eBPF 探针 | 检测入侵的第一道传感器 |

| 抗原呈递 | `process_tree.rs` | 追踪进程来源，还原攻击链 |│

| T 细胞分化 | `policy.rs` | 根据上下文选择杀伤/容忍/观察 |

| 上皮屏障 | `filesystem.rs` | 保护关键文件（皮肤不可穿透） |├── antivirus-immunity-common/          # 跨平台共享层- **设计原则**: 本地优先、优雅降级、非阻塞、可审计│  │              │  │              │  │                   │  │### 2. 决策层 (Core / Adaptive Immunity)

| 补体系统 | `network.rs` | 在血液（网络）中巡逻标记外来物 |

| 大脑皮层 | `ai_cortex.rs` | 对疑难案例的深度智能分析 |│   ├── Cargo.toml

| 免疫记忆 | `logger.rs` | JSONL 审计日志，事后回溯 |

| 新陈代谢调节 | `resource_aware.rs` | 资源不足时进入节能模式 |│   └── src/

| 组织定位 | `container.rs` | 感知进程所在的容器环境 |

│       ├── lib.rs

---

│       ├── event.rs                    # SecurityEvent / ProcessInfo / 枚举### 4. 响应层 (Effectors)│  │ TLR (进程监控)│→│ Memory B Cell│→│ Cytotoxic T Cell  │  │*对应生物学：T细胞、B细胞、淋巴结*

## 🗺 路线图

│       ├── logger.rs                   # JSONL 结构化日志 (50MB 自动轮转)

- [x] **v0.3.0** — Windows 引擎 (ToolHelp32 + YARA + AI Cortex)

- [x] **v0.4.0** — Linux eBPF 架构骨架 + 策略引擎 + 容器感知│       ├── ai_cortex.rs               # Ollama LLM 接口*对应生物学：抗体中和、细胞吞噬、淋巴结隔离*

- [ ] **v0.5.0** — 真实 eBPF CO-RE 探针加载 (libbpf-rs) + Ring Buffer 消费

- [ ] **v0.6.0** — XDP/TC 网络阻断 + LSM 文件护栏内核实现│       └── hash_cache.rs             # LRU SHA256 缓存

- [ ] **v0.7.0** — K8s Sidecar 部署 + Prometheus metrics

- [ ] **v1.0.0** — 生产就绪：DaemonSet 部署、SIEM 对接、威胁情报订阅│- **CytotoxicTCell**: 终止恶意进程（细胞凋亡），RAII 安全句柄管理│  │ Hash Cache   │  │ Path Valid.  │  │ Quarantine        │  │- **功能**: 分析感知层传来的数据，判断是否为威胁。



---├── antivirus-immunity-ebpf/            # Linux eBPF 引擎 (v0.4.0)



## 📝 许可│   ├── Cargo.toml- **Quarantine**: 文件隔离管理（淋巴结隔离），支持释放/删除



MIT License│   ├── build.sh                        # eBPF 编译脚本



## 👤 作者│   ├── bpf/- **分级响应**: Log → Monitor → Quarantine → Terminate│  │              │  │ Danger Theory│  │                   │  │- **模块**:



**KingDragon-yc** — [GitHub](https://github.com/KingDragon-yc)│   │   └── probes.bpf.c               # CO-RE 内核探针 (C)


│   └── src/

│       ├── main.rs                     # CLI + 事件循环 + 资源感知

│       ├── probe.rs                    # eBPF 探针管理 (/proc fallback)### 5. 日志系统 (Logger / Immunological Memory)│  │              │  │ YARA Engine  │  │                   │  │    - **Negative Selection (负向选择)**: 过滤掉已知的“自身”进程（白名单）。

│       ├── container.rs               # Docker/K8s 容器上下文

│       ├── policy.rs                  # 安全策略引擎 (Server/Container/AI-Agent/Lite)- JSONL 结构化日志，便于 SIEM 集成

│       ├── process_tree.rs            # 进程族谱追踪 (攻击链还原)

│       ├── resource_aware.rs          # 硬件感知 + Lite 模式自动切换- 自动轮转（50MB/文件）│  └──────────────┘  └──────────────┘  └───────────────────┘  │    - **Danger Theory (危险理论)**: 监测系统压力的信号（如CPU突然飙升、大量文件被重命名）。

│       ├── network.rs                 # 网络连接监控 (反弹shell/C2检测)

│       └── filesystem.rs             # 文件系统护栏 (敏感路径保护)- 记录所有安全事件和 AI 分析结果

│

└── antivirus-immunity-core/            # Windows 引擎 (v0.3.0 · Legacy)│                                                              │    - **Memory Cell (记忆细胞)**: 缓存已分析过的进程特征。

    ├── Cargo.toml

    ├── antigens.yar                    # 12+ YARA 规则## 🛠 技术栈 (Tech Stack)

    └── src/

        ├── main.rs├─────────────────────────────────────────────────────────────┤

        ├── receptor/                   # TollLikeReceptor + HashCache

        ├── immune/                     # MemoryBCell + DangerTheory + PathValidator + AiCortex- **开发语言**: Rust

        └── effector/                   # CytotoxicTCell + Quarantine

```- **操作系统**: Windows│                    Logger (免疫记忆日志)                       │### 3. 响应层 (Effectors)



---- **AI 推理**: Ollama (本地 LLM)



## 🔧 安全策略配置 (Profiles)- **关键库**:│              Structured JSONL event logging                   │*对应生物学：抗体中和、细胞吞噬*



| Profile | 场景 | 网络监控 | 文件护栏 | AI分析 | 提权检测 |    - `windows-rs` (WinAPI)

|---------|------|----------|----------|--------|----------|

| **server** | 标准云服务器 | ✅ | ✅ | ✅ | ✅ |    - `yara-x` (特征匹配)└─────────────────────────────────────────────────────────────┘- **功能**: 对确认为威胁的目标采取行动。

| **container** | Docker/K8s | ✅ | ✅ (docker.sock重点) | ✅ | ✅ |

| **ai-agent** | AI Agent 沙盒 | ✅ (严格边界) | ✅ | ✅ | ✅ |    - `sysinfo` (系统监控)

| **lite** | 1C1G 轻量实例 | ✅ (核心) | ❌ | ❌ | ✅ |

    - `reqwest` (AI API 通信)```- **动作**:

### AI Agent 沙盒护栏

    - `lru` (哈希缓存)

AI Agent (如 LangChain/AutoGPT) 需要执行代码，但边界必须受控：

    - `chrono` / `uuid` / `serde_json` (日志与数据)    - **Quarantine (隔离)**: 移动文件到隔离区。

- ✅ 允许：`python3`, `node`, `npm`, `pip`, `cargo`, `gcc`, `git`

- ⛔ 禁止：访问 `/etc/shadow`, `/root/.ssh/`, `/var/run/docker.sock`

- ⛔ 禁止：连接到端口 4444/5555/8888/9999（常见 C2/挖矿端口）

- ⚠️ 监控：Shell 被脚本运行时（python/perl/ruby）直接调起 → 反弹 shell 疑似## 🚀 快速开始 (Quick Start)### 1. 感知层 (Sensors / Innate Immunity)    - **Terminate (杀伤)**: 结束恶意进程。



---



## 🚀 快速开始```bash*对应生物学：皮肤、Toll 样受体*    - **Alert (炎症反应)**: 通知用户。



### 前置要求# 1. 安装 Ollama (可选，用于 AI 深度分析)



```bash# 下载: https://ollama.ai- **TollLikeReceptor**: 进程快照 + 差分扫描，检测新进程

# Linux (Ubuntu/Debian)

sudo apt install clang llvm libbpf-dev bpftoolollama pull qwen2.5:3b

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

- **HashCache**: LRU 哈希缓存，避免重复计算 SHA256（补体调理素标记）## 🛠 技术栈 (Tech Stack)

# Ollama (可选, 用于 AI Cortex)

curl -fsSL https://ollama.com/install.sh | sh# 2. 构建项目

ollama pull qwen2.5:3b

```cd antivirus-immunity-core- **SafeHandle**: RAII 包装器，确保 Windows 句柄安全释放



### 编译 & 运行cargo build --release



```bash- **开发语言**: Rust (主要), Python (辅助分析)

# 编译整个 workspace

cargo build --release# 3. 学习当前系统的"正常态"



# 运行 eBPF 引擎 (需要 root 权限)cargo run -- --mode learn### 2. 决策层 (Core / Adaptive Immunity)- **操作系统**: Windows (首选目标平台)

sudo ./target/release/immunity-ebpf --profile server



# AI Agent 沙盒模式

sudo ./target/release/immunity-ebpf --profile ai-agent --ai --ai-model qwen2.5:3b# 4. 启动被动监控*对应生物学：T细胞、B细胞、淋巴结*- **关键库**: 



# Lite 模式 (自动检测, 也可手动)cargo run -- --mode monitor

sudo ./target/release/immunity-ebpf --profile server --max-memory-mb 30

- **Memory B Cell**: SHA256 哈希白名单持久化（免疫记忆）    - `windows-rs` (WinAPI 交互)

# 仅编译 eBPF 内核探针

cd antivirus-immunity-ebpf && bash build.sh probes# 5. 启动主动防御 (带 AI + 隔离)

```

cargo run -- --mode active --policy quarantine --ai true- **PathValidator (MHC)**: 路径验证，检测进程名伪装（如 svchost.exe 出现在非 System32 目录）    - `ferris-gram` (ETW 封装，待定)

### 命令行参数



```

USAGE: immunity-ebpf [OPTIONS]# 6. 查看隔离区- **DangerTheoryEngine**: 系统压力信号监测（CPU/内存/进程洪水），动态调整免疫灵敏度



OPTIONS:cargo run -- --mode quarantine-list

  -m, --mode <MODE>           运行模式: monitor, enforce, learn [default: monitor]

  -p, --profile <PROFILE>     策略配置: server, container, ai-agent [default: server]```- **YARA Engine**: 已知恶意软件特征匹配（抗原数据库，12+ 条规则）## 🚀 路线图 (Roadmap)

      --ai                    启用 AI Cortex

      --ai-model <MODEL>      AI 模型 [default: qwen2.5:3b]

      --ai-endpoint <URL>     Ollama 地址 [default: http://localhost:11434]

      --protected-paths <P>   受保护路径 (逗号分隔)> 📘 **详细使用指南请参阅 [USER_MANUAL.md](USER_MANUAL.md)**

      --max-memory-mb <MB>    内存上限 [default: 100]

      --output <FORMAT>       输出格式: text, json [default: text]

```

## 📋 CLI 参数### 3. AI 决策中枢 (AI Cortex / Cerebral Cortex)### Phase 1: 骨架构建 (Skeleton)

---



## 🧬 生物学类比

| 参数 | 默认值 | 说明 |*对应生物学：大脑皮层*- [ ] 搭建 Rust 项目结构

| 生物免疫 | 本项目组件 | 功能 |

|----------|-----------|------||------|--------|------|

| Toll 样受体 (TLR) | `probe.rs` / eBPF 探针 | 检测入侵的第一道传感器 |

| 抗原呈递 | `process_tree.rs` | 追踪进程来源，还原攻击链 || `--mode` | `monitor` | 运行模式: `learn`, `monitor`, `active`, `quarantine-list` |- **AiCortex**: 通过 Ollama 调用本地 LLM，对模糊案例进行深度分析- [ ] 实现基础的进程监控 (Process Monitor)

| T 细胞分化 | `policy.rs` | 根据上下文选择杀伤/容忍/观察 |

| 上皮屏障 | `filesystem.rs` | 保护关键文件（皮肤不可穿透） || `--policy` | - | 响应策略: `log`, `kill`, `quarantine` |

| 补体系统 | `network.rs` | 在血液（网络）中巡逻标记外来物 |

| 大脑皮层 | `ai_cortex.rs` | 对疑难案例的深度智能分析 || `--ai` | `true` | 是否启用 AI Cortex |- **设计原则**: 本地优先、优雅降级、非阻塞、可审计- [ ] 实现简单的“白名单”机制

| 免疫记忆 | `logger.rs` | JSONL 审计日志，事后回溯 |

| 新陈代谢调节 | `resource_aware.rs` | 资源不足时进入节能模式 || `--ai-model` | `qwen2.5:3b` | Ollama 模型名称 |

| 组织定位 | `container.rs` | 感知进程所在的容器环境 |

| `--ai-endpoint` | `http://localhost:11434` | Ollama API 地址 |

---

| `--interval` | `500` | 轮询间隔 (毫秒) |

## 🗺 路线图

### 4. 响应层 (Effectors)### Phase 2: 免疫机制 (Immunity)

- [x] **v0.3.0** — Windows 引擎 (ToolHelp32 + YARA + AI Cortex)

- [x] **v0.4.0** — Linux eBPF 架构骨架 + 策略引擎 + 容器感知## 🔬 多层评估管线 (Multi-Layer Evaluation Pipeline)

- [ ] **v0.5.0** — 真实 eBPF CO-RE 探针加载 (libbpf-rs) + Ring Buffer 消费

- [ ] **v0.6.0** — XDP/TC 网络阻断 + LSM 文件护栏内核实现*对应生物学：抗体中和、细胞吞噬、淋巴结隔离*- [ ] 引入 ETW 监控文件操作

- [ ] **v0.7.0** — K8s Sidecar 部署 + Prometheus metrics

- [ ] **v1.0.0** — 生产就绪：DaemonSet 部署、SIEM 对接、威胁情报订阅```



---新进程 ──→ YARA扫描(黑名单) ──→ 路径验证(MHC) ──→ 哈希白名单(B细胞记忆)- **CytotoxicTCell**: 终止恶意进程（细胞凋亡），RAII 安全句柄管理- [ ] 实现基础的行为分析 (例如：检测勒索软件诱饵文件的修改)



## 📝 许可              │                      │                      │



MIT License        匹配=CRITICAL          伪装=CRITICAL          可信=SAFE- **Quarantine**: 文件隔离管理（淋巴结隔离），支持释放/删除



## 👤 作者              │                      │                      │



**KingDragon-yc** — [GitHub](https://github.com/KingDragon-yc)              └──────────────────────┼──────────────────────┘- **分级响应**: Log → Monitor → Quarantine → Terminate### Phase 3: 进化 (Evolution)


                                     ↓

                          危险信号关联(Danger Theory)- [ ] 引入简单的机器学习模型进行异常检测

                                     │

                              ┌──────┴──────┐### 5. 日志系统 (Logger / Immunological Memory)- [ ] 构建 Web 控制台

                              │  AI Cortex  │ ← 仅对模糊案例启用

                              │  深度分析    │- JSONL 结构化日志，便于 SIEM 集成

                              └──────┬──────┘- 自动轮转（50MB/文件）

                                     ↓- 记录所有安全事件和 AI 分析结果

                            分级响应 (Log/Kill/Quarantine)

```## 🛠 技术栈 (Tech Stack)



## 🗺 路线图 (Roadmap)- **开发语言**: Rust

- **操作系统**: Windows

### ✅ Phase 1: 骨架构建 (Skeleton) — 完成- **AI 推理**: Ollama (本地 LLM)

- [x] 搭建 Rust 项目结构- **关键库**:

- [x] 实现基础的进程监控 (TollLikeReceptor)    - `windows-rs` (WinAPI)

- [x] 实现 SHA256 哈希白名单 (Memory B Cell)    - `yara-x` (特征匹配)

    - `sysinfo` (系统监控)

### ✅ Phase 2: 免疫强化 (Immunity) — 完成    - `reqwest` (AI API 通信)

- [x] 路径验证替代进程名白名单 (MHC/PathValidator)    - `lru` (哈希缓存)

- [x] 危险信号理论引擎 (Danger Theory)    - `chrono` / `uuid` / `serde_json` (日志与数据)

- [x] YARA 规则扩充 (12+ 条规则覆盖主要威胁类别)

- [x] LRU 哈希缓存性能优化## 🚀 快速开始 (Quick Start)

- [x] RAII 句柄安全管理

- [x] 文件隔离区系统 (Quarantine)```bash

- [x] 结构化日志系统 (JSONL Logger)# 1. 安装 Ollama (可选，用于 AI 深度分析)

# 下载: https://ollama.ai

### ✅ Phase 3: AI 集成 (AI Cortex) — 完成ollama pull qwen2.5:3b

- [x] 集成 Ollama 本地 LLM 接口

- [x] AI 深度分析模糊案例# 2. 构建项目

- [x] 优雅降级（AI 不可用时回退规则引擎）cd antivirus-immunity-core

- [x] AI 判断结果可审计cargo build --release



### 🔲 Phase 4: 进化 (Evolution) — 规划中# 3. 学习当前系统的"正常态"

- [ ] ETW 事件驱动监控替代轮询cargo run -- --mode learn

- [ ] 文件系统行为监控（勒索软件诱饵文件检测）

- [ ] 网络流量分析# 4. 启动被动监控

- [ ] 群体免疫网络（联邦学习式的威胁情报共享）cargo run -- --mode monitor

- [ ] Web 控制台

- [ ] Hyper-V 沙箱隔离分析# 5. 启动主动防御 (带 AI + 隔离)

cargo run -- --mode active --policy quarantine --ai true

## 📜 License

# 6. 查看隔离区

MITcargo run -- --mode quarantine-list

```

## 📋 CLI 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--mode` | `monitor` | 运行模式: `learn`, `monitor`, `active`, `quarantine-list` |
| `--policy` | - | 响应策略: `log`, `kill`, `quarantine` |
| `--ai` | `true` | 是否启用 AI Cortex |
| `--ai-model` | `qwen2.5:3b` | Ollama 模型名称 |
| `--ai-endpoint` | `http://localhost:11434` | Ollama API 地址 |
| `--interval` | `500` | 轮询间隔 (毫秒) |

## 🔬 多层评估管线 (Multi-Layer Evaluation Pipeline)

```
新进程 ──→ YARA扫描(黑名单) ──→ 路径验证(MHC) ──→ 哈希白名单(B细胞记忆)
              │                      │                      │
        匹配=CRITICAL          伪装=CRITICAL          可信=SAFE
              │                      │                      │
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

## 🗺 路线图 (Roadmap)

### ✅ Phase 1: 骨架构建 (Skeleton) — 完成
- [x] 搭建 Rust 项目结构
- [x] 实现基础的进程监控 (TollLikeReceptor)
- [x] 实现 SHA256 哈希白名单 (Memory B Cell)

### ✅ Phase 2: 免疫强化 (Immunity) — 完成
- [x] 路径验证替代进程名白名单 (MHC/PathValidator)
- [x] 危险信号理论引擎 (Danger Theory)
- [x] YARA 规则扩充 (12+ 条规则覆盖主要威胁类别)
- [x] LRU 哈希缓存性能优化
- [x] RAII 句柄安全管理
- [x] 文件隔离区系统 (Quarantine)
- [x] 结构化日志系统 (JSONL Logger)

### ✅ Phase 3: AI 集成 (AI Cortex) — 完成
- [x] 集成 Ollama 本地 LLM 接口
- [x] AI 深度分析模糊案例
- [x] 优雅降级（AI 不可用时回退规则引擎）
- [x] AI 判断结果可审计

### 🔲 Phase 4: 进化 (Evolution) — 规划中
- [ ] ETW 事件驱动监控替代轮询
- [ ] 文件系统行为监控（勒索软件诱饵文件检测）
- [ ] 网络流量分析
- [ ] 群体免疫网络（联邦学习式的威胁情报共享）
- [ ] Web 控制台
- [ ] Hyper-V 沙箱隔离分析

## 📜 License

MIT
