# Antivirus-Immunity# Anti本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件，并集成**本地 AI 模型**作为免疫决策中枢。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：

- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统"正常态"的基线，识别入侵者。

> **"A kind of Antivirus inspired by immune system, augmented with local AI."**- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。

- **危险信号理论 (Danger Theory)**: 通过监测系统压力信号（CPU 飙升、进程洪水等）动态调整免疫灵敏度。

## 📖 项目愿景 (Vision)- **AI 深度分析 (AI Cortex)**: 对模糊案例使用本地 LLM 进行自然语言推理，弥补规则引擎的刚性不足。

- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。s-Immunity

本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件，并集成**本地 AI 模型**作为免疫决策中枢。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：

> **"A kind of Antivirus inspired by immune system, augmented with local AI."**

- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统"正常态"的基线，识别入侵者。

- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。## 📖 项目愿景 (Vision)

- **危险信号理论 (Danger Theory)**: 通过监测系统压力信号（CPU 飙升、进程洪水等）动态调整免疫灵敏度。

- **AI 深度分析 (AI Cortex)**: 对模糊案例使用本地 LLM 进行自然语言推理，弥补规则引擎的刚性不足。本项目旨在构建一个基于**人工免疫系统 (AIS)** 理论的端点安全防护软件。与依赖特征库的传统杀毒软件不同，Antivirus-Immunity 侧重于：

- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。- **自我识别 (Self/Non-Self Discrimination)**: 通过建立系统“正常态”的基线，识别入侵者。

- **行为免疫 (Behavioral Immunity)**: 基于行为模式而非静态特征来检测威胁。

## 🏗 架构设计 (Architecture)- **自适应性 (Adaptability)**: 能够对未知的攻击手段做出反应。



系统由四个核心层组成，模拟生物免疫回路：## 🏗 架构设计 (Architecture)



```系统由三个核心部分组成，模拟生物免疫回路：

┌─────────────────────────────────────────────────────────────┐

│                    AI Cortex (大脑皮层)                       │### 1. 感知层 (Sensors / Innate Immunity)

│         Local LLM for deep analysis of ambiguous cases       │*对应生物学：皮肤、巨噬细胞*

│                   (Ollama + qwen2.5:3b)                      │- **功能**: 负责实时监控系统状态。

├─────────────────────────────────────────────────────────────┤- **技术**: 

│                                                              │    - Windows ETW (Event Tracing for Windows)

│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │    - File System Minifilter (文件变动监控)

│  │   Receptor    │  │   Immune     │  │    Effector       │  │    - Process Callbacks (进程创建/销毁监控)

│  │   感知层      │  │   决策层      │  │    响应层          │  │

│  │              │  │              │  │                   │  │### 2. 决策层 (Core / Adaptive Immunity)

│  │ TLR (进程监控)│→│ Memory B Cell│→│ Cytotoxic T Cell  │  │*对应生物学：T细胞、B细胞、淋巴结*

│  │ Hash Cache   │  │ Path Valid.  │  │ Quarantine        │  │- **功能**: 分析感知层传来的数据，判断是否为威胁。

│  │              │  │ Danger Theory│  │                   │  │- **模块**:

│  │              │  │ YARA Engine  │  │                   │  │    - **Negative Selection (负向选择)**: 过滤掉已知的“自身”进程（白名单）。

│  └──────────────┘  └──────────────┘  └───────────────────┘  │    - **Danger Theory (危险理论)**: 监测系统压力的信号（如CPU突然飙升、大量文件被重命名）。

│                                                              │    - **Memory Cell (记忆细胞)**: 缓存已分析过的进程特征。

├─────────────────────────────────────────────────────────────┤

│                    Logger (免疫记忆日志)                       │### 3. 响应层 (Effectors)

│              Structured JSONL event logging                   │*对应生物学：抗体中和、细胞吞噬*

└─────────────────────────────────────────────────────────────┘- **功能**: 对确认为威胁的目标采取行动。

```- **动作**:

    - **Quarantine (隔离)**: 移动文件到隔离区。

### 1. 感知层 (Sensors / Innate Immunity)    - **Terminate (杀伤)**: 结束恶意进程。

*对应生物学：皮肤、Toll 样受体*    - **Alert (炎症反应)**: 通知用户。

- **TollLikeReceptor**: 进程快照 + 差分扫描，检测新进程

- **HashCache**: LRU 哈希缓存，避免重复计算 SHA256（补体调理素标记）## 🛠 技术栈 (Tech Stack)

- **SafeHandle**: RAII 包装器，确保 Windows 句柄安全释放

- **开发语言**: Rust (主要), Python (辅助分析)

### 2. 决策层 (Core / Adaptive Immunity)- **操作系统**: Windows (首选目标平台)

*对应生物学：T细胞、B细胞、淋巴结*- **关键库**: 

- **Memory B Cell**: SHA256 哈希白名单持久化（免疫记忆）    - `windows-rs` (WinAPI 交互)

- **PathValidator (MHC)**: 路径验证，检测进程名伪装（如 svchost.exe 出现在非 System32 目录）    - `ferris-gram` (ETW 封装，待定)

- **DangerTheoryEngine**: 系统压力信号监测（CPU/内存/进程洪水），动态调整免疫灵敏度

- **YARA Engine**: 已知恶意软件特征匹配（抗原数据库，12+ 条规则）## 🚀 路线图 (Roadmap)



### 3. AI 决策中枢 (AI Cortex / Cerebral Cortex)### Phase 1: 骨架构建 (Skeleton)

*对应生物学：大脑皮层*- [ ] 搭建 Rust 项目结构

- **AiCortex**: 通过 Ollama 调用本地 LLM，对模糊案例进行深度分析- [ ] 实现基础的进程监控 (Process Monitor)

- **设计原则**: 本地优先、优雅降级、非阻塞、可审计- [ ] 实现简单的“白名单”机制



### 4. 响应层 (Effectors)### Phase 2: 免疫机制 (Immunity)

*对应生物学：抗体中和、细胞吞噬、淋巴结隔离*- [ ] 引入 ETW 监控文件操作

- **CytotoxicTCell**: 终止恶意进程（细胞凋亡），RAII 安全句柄管理- [ ] 实现基础的行为分析 (例如：检测勒索软件诱饵文件的修改)

- **Quarantine**: 文件隔离管理（淋巴结隔离），支持释放/删除

- **分级响应**: Log → Monitor → Quarantine → Terminate### Phase 3: 进化 (Evolution)

- [ ] 引入简单的机器学习模型进行异常检测

### 5. 日志系统 (Logger / Immunological Memory)- [ ] 构建 Web 控制台

- JSONL 结构化日志，便于 SIEM 集成
- 自动轮转（50MB/文件）
- 记录所有安全事件和 AI 分析结果

## 🛠 技术栈 (Tech Stack)

- **开发语言**: Rust
- **操作系统**: Windows
- **AI 推理**: Ollama (本地 LLM)
- **关键库**:
    - `windows-rs` (WinAPI)
    - `yara-x` (特征匹配)
    - `sysinfo` (系统监控)
    - `reqwest` (AI API 通信)
    - `lru` (哈希缓存)
    - `chrono` / `uuid` / `serde_json` (日志与数据)

## 🚀 快速开始 (Quick Start)

```bash
# 1. 安装 Ollama (可选，用于 AI 深度分析)
# 下载: https://ollama.ai
ollama pull qwen2.5:3b

# 2. 构建项目
cd antivirus-immunity-core
cargo build --release

# 3. 学习当前系统的"正常态"
cargo run -- --mode learn

# 4. 启动被动监控
cargo run -- --mode monitor

# 5. 启动主动防御 (带 AI + 隔离)
cargo run -- --mode active --policy quarantine --ai true

# 6. 查看隔离区
cargo run -- --mode quarantine-list
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
