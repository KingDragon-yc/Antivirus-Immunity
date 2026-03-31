# 📘 Antivirus-Immunity 使用手册

> **版本**: v0.3.0 | **最后更新**: 2026-03-31  
> **适用平台**: Windows 10/11 (x86_64)

---

## 📑 目录

1. [系统要求](#-系统要求)
2. [安装与构建](#-安装与构建)
3. [首次使用：快速上手](#-首次使用快速上手)
4. [运行模式详解](#-运行模式详解)
5. [AI Cortex 配置指南](#-ai-cortex-配置指南)
6. [CLI 完整参数参考](#-cli-完整参数参考)
7. [实战演练：测试病毒查杀](#-实战演练测试病毒查杀)
8. [日志与审计](#-日志与审计)
9. [隔离区管理](#-隔离区管理)
10. [YARA 规则自定义](#-yara-规则自定义)
11. [常见问题 FAQ](#-常见问题-faq)
12. [安全提示与免责声明](#-安全提示与免责声明)

---

## 💻 系统要求

| 组件 | 最低要求 | 推荐配置 |
|------|---------|---------|
| **操作系统** | Windows 10 x64 | Windows 11 x64 |
| **CPU** | 双核 | 四核以上（AI 分析需要更多算力） |
| **内存** | 4GB | 8GB+（Ollama 模型加载需要额外内存） |
| **磁盘** | 500MB（构建工具链 + 项目） | 5GB+（含 AI 模型文件） |
| **Rust 工具链** | 1.70+ | latest stable |
| **Ollama**（可选） | v0.1+ | latest |

### 必须安装的软件

1. **Rust 工具链**：https://rustup.rs
2. **Visual Studio Build Tools** (或 Visual Studio)：Rust 在 Windows 上编译需要 MSVC 工具链
   - 安装时勾选 "C++ build tools" 和 "Windows SDK"

### 可选软件

3. **Ollama**（用于 AI 深度分析）：https://ollama.ai
4. **Git**（如果你需要克隆仓库）

---

## 🔧 安装与构建

### 方法一：从 GitHub 克隆（推荐）

```powershell
# 1. 克隆仓库
git clone https://github.com/KingDragon-yc/Antivirus-Immunity.git
cd Antivirus-Immunity

# 2. 进入核心引擎目录
cd antivirus-immunity-core

# 3. 构建 Release 版本（性能优化）
cargo build --release
```

> ⏳ 首次构建可能需要 3~10 分钟（需下载和编译所有依赖项）。

构建完成后，可执行文件位于：
```
antivirus-immunity-core/target/release/antivirus-immunity-core.exe
```

### 方法二：直接运行（开发模式）

```powershell
cd antivirus-immunity-core
cargo run -- --help
```

### 验证安装

```powershell
# 查看版本和帮助信息
cargo run -- --help
```

你应该看到类似输出：
```
An antivirus engine inspired by the biological immune system, with local AI cortex

Usage: antivirus-immunity-core.exe [OPTIONS]

Options:
  -m, --mode <MODE>              Mode of operation [default: monitor]
  -p, --policy <POLICY>          Response policy: 'log', 'kill', or 'quarantine'
      --ai <AI>                  Enable AI Cortex [default: true]
      --ai-model <AI_MODEL>      AI model name [default: qwen2.5:3b]
      --ai-endpoint <ENDPOINT>   Ollama endpoint URL [default: http://localhost:11434]
      --interval <INTERVAL>      Monitoring poll interval in ms [default: 500]
  -h, --help                     Print help
  -V, --version                  Print version
```

---

## 🚀 首次使用：快速上手

按以下 3 步完成首次体验。**请以管理员身份运行 PowerShell**（右键 → "以管理员身份运行"），因为进程监控和终止需要管理员权限。

### 第 1 步：学习"正常态"

```powershell
cd antivirus-immunity-core
cargo run -- --mode learn
```

**这一步做了什么？**  
免疫系统需要先了解什么是"自己人"。学习模式会：
- 扫描当前所有正在运行的进程
- 记录它们的 SHA256 哈希值到 `immunity_db.json`
- 建立"免疫记忆"，下次遇到这些进程时直接放行

> ⚠️ **重要**：请确保学习时你的电脑是"干净的"——没有运行任何恶意软件。否则恶意程序也会被记为"自己人"！

你应该看到类似输出：
```
╔══════════════════════════════════════════════════════════════╗
║          Antivirus-Immunity Core v0.3.0                     ║
║          Biological Architecture + AI Cortex                ║
╚══════════════════════════════════════════════════════════════╝

[*] STARTING LEARNING MODE...
[*] Toll-Like Receptor: Taking snapshot of all running processes...
[!] WARNING: Ensure your system is currently clean before proceeding!
[+] Found 142 processes.
[+] Learning complete. Memory B Cells updated.
```

### 第 2 步：启动监控

```powershell
cargo run -- --mode monitor
```

**这一步做了什么？**  
进入被动监控模式：
- 每 500ms 扫描一次进程列表
- 对比之前学习的"正常态"
- 发现新进程时，通过多层免疫管线进行评估
- **仅记录，不采取行动**（适合先观察一下系统行为）

你会看到实时的进程检测输出：
```
PID    NAME                      STATUS          INFO
------ ------------------------- --------------- --------------------------------------------------
14320  notepad.exe               SAFE            a1b2c3d4e5...（hash）
8472   unknown_app.exe           SUSPICIOUS      Unknown process, not in immune memory
```

> 💡 **提示**：按 `Ctrl+C` 停止监控。

### 第 3 步：启动主动防御（可选，进阶）

```powershell
cargo run -- --mode active --policy quarantine --ai true
```

**这一步做了什么？**  
进入主动防御模式：
- 检测到 **CRITICAL** 威胁 → 自动**隔离文件 + 终止进程**
- 模糊案例 → 交给 **AI Cortex** 分析后决策
- 所有行为都被记录在日志中

> ⚠️ **警告**：主动防御模式会真正终止进程和隔离文件！建议先在监控模式下熟悉系统行为。

---

## 📖 运行模式详解

### 模式一览表

| 模式 | 命令 | 说明 | 风险等级 |
|------|------|------|---------|
| **学习模式** | `--mode learn` | 建立系统正常态基线 | 🟢 无风险 |
| **被动监控** | `--mode monitor` | 只检测和记录，不采取行动 | 🟢 无风险 |
| **主动防御** | `--mode active` | 检测 + 自动响应（杀进程/隔离） | 🔴 会影响运行中的程序 |
| **隔离列表** | `--mode quarantine-list` | 查看当前隔离区中的文件 | 🟢 无风险 |

### 模式 1：学习模式 (learn)

```powershell
cargo run -- --mode learn
```

- 只需运行**一次**即可（除非你安装了新软件想要重新学习）
- 会覆盖之前的 `immunity_db.json`
- 建议在刚装好系统 / 确认安全的状态下运行

### 模式 2：被动监控 (monitor) — 默认模式

```powershell
# 基础监控（无 AI）
cargo run -- --mode monitor --ai false

# 基础监控（带 AI 分析）
cargo run -- --mode monitor --ai true

# 调整扫描频率为每秒一次
cargo run -- --mode monitor --interval 1000
```

被动监控模式下的输出含义：

| 状态标签 | 含义 | 触发条件 |
|---------|------|---------|
| `SAFE` | 安全 | 哈希在免疫记忆中 + 路径验证通过 |
| `UNKNOWN` | 未知 | 不在免疫记忆中，但无恶意特征 |
| `SUSPICIOUS` | 可疑 | 路径可疑 或 行为异常 |
| `CRITICAL` | 严重威胁 | YARA 规则命中 或 进程伪装被识破 |
| `AI_REVIEW` | 待 AI 分析 | 规则引擎无法确定，交由 AI 判断 |

### 模式 3：主动防御 (active)

```powershell
# 仅终止恶意进程（不隔离文件）
cargo run -- --mode active --policy kill

# 隔离文件 + 终止进程（推荐）
cargo run -- --mode active --policy quarantine

# 仅记录（主动模式下选择不执行操作）
cargo run -- --mode active --policy log
```

**分级响应策略：**

| 威胁等级 | `--policy log` | `--policy kill` | `--policy quarantine` |
|---------|----------------|-----------------|----------------------|
| CRITICAL | 仅记录 | 终止进程 | 隔离文件 + 终止进程 |
| SUSPICIOUS | 仅记录 | 仅记录 | 仅记录 |
| AI_REVIEW | AI 分析后记录 | AI 分析后可能终止 | AI 分析后可能隔离+终止 |

### 模式 4：隔离列表 (quarantine-list)

```powershell
cargo run -- --mode quarantine-list
```

输出示例：
```
[*] Listing quarantined files...

ID                                     ORIGINAL PATH                  PROCESS              DATE
-------------------------------------- ------------------------------ -------------------- --------------------
a1b2c3d4-e5f6-7890-abcd-ef1234567890   C:\Users\test\malware.exe      malware.exe          2026-03-31 15:30:00
```

---

## 🧠 AI Cortex 配置指南

AI Cortex 是系统的"大脑皮层"，负责对模糊案例进行深度分析。它通过本地运行的 **Ollama** 调用 LLM 模型。

### 安装 Ollama

1. 访问 https://ollama.ai 下载安装包
2. 安装后，Ollama 会作为系统服务自动启动
3. 拉取推荐模型：

```powershell
# 推荐模型（3B 参数，平衡速度和准确度）
ollama pull qwen2.5:3b

# 轻量级替代（1B 参数，速度更快，适合低配机器）
ollama pull llama3.2:1b

# 中等模型（更准确，但需要更多内存）
ollama pull qwen2.5:7b
```

### 验证 Ollama 运行状态

```powershell
# 检查 Ollama 是否在运行
curl http://localhost:11434/api/tags
```

如果返回 JSON 数据（包含已安装的模型列表），说明 Ollama 正常运行。

### 使用不同的 AI 模型

```powershell
# 使用默认模型 (qwen2.5:3b)
cargo run -- --mode monitor --ai true

# 使用更小的模型（速度快，适合低配）
cargo run -- --mode monitor --ai true --ai-model llama3.2:1b

# 使用更大的模型（更准确）
cargo run -- --mode monitor --ai true --ai-model qwen2.5:7b

# 自定义 Ollama 端点（如果不在本机运行）
cargo run -- --mode monitor --ai true --ai-endpoint http://192.168.1.100:11434
```

### 不使用 AI（纯规则引擎模式）

```powershell
cargo run -- --mode monitor --ai false
```

系统会自动回退到纯规则引擎模式，不影响基本功能。

### AI 优雅降级

即使启用了 AI（`--ai true`），如果 Ollama 没有运行或不可达，系统会：
1. 启动时提示 "AI Cortex: Ollama not reachable"
2. 自动回退到规则引擎判断
3. 不会崩溃或阻塞

---

## 📋 CLI 完整参数参考

```
antivirus-immunity-core.exe [OPTIONS]
```

| 参数 | 短写 | 类型 | 默认值 | 说明 |
|------|------|------|--------|------|
| `--mode` | `-m` | string | `monitor` | 运行模式：`learn` / `monitor` / `active` / `quarantine-list` |
| `--policy` | `-p` | string | *(无)* | 响应策略：`log` / `kill` / `quarantine` |
| `--ai` | | bool | `true` | 是否启用 AI Cortex |
| `--ai-model` | | string | `qwen2.5:3b` | Ollama 模型名称 |
| `--ai-endpoint` | | string | `http://localhost:11434` | Ollama API 端点地址 |
| `--interval` | | u64 | `500` | 监控轮询间隔（毫秒） |
| `--help` | `-h` | | | 显示帮助信息 |
| `--version` | `-V` | | | 显示版本号 |

### 常用命令组合速查

```powershell
# 📚 学习系统正常态
cargo run -- --mode learn

# 👁️ 安静观察（无 AI，仅监控）
cargo run -- --mode monitor --ai false

# 🧠 智能监控（带 AI 分析）
cargo run -- --mode monitor --ai true

# ⚔️ 全力防御（AI + 隔离 + 杀进程）
cargo run -- --mode active --policy quarantine --ai true

# 🐌 降低 CPU 占用（增大轮询间隔）
cargo run -- --mode monitor --interval 2000

# 📦 查看隔离文件
cargo run -- --mode quarantine-list

# 🔧 使用编译好的 Release 版本运行（性能更好）
.\target\release\antivirus-immunity-core.exe --mode monitor --ai true
```

---

## 🧪 实战演练：测试病毒查杀

项目自带了一个**模拟病毒程序**（`mock_antigen`），可以安全地测试整个检测→分析→响应流程。

### 步骤 1：构建模拟病毒

```powershell
cd antivirus-immunity-core

# 构建模拟病毒
cargo build --example mock_antigen
```

> 💡 `mock_antigen` 是一个包含 EICAR 测试签名和 `malware_test_string` 的无害测试程序，不会对系统造成任何损害。

### 步骤 2：启动监控引擎

打开**第一个终端**（管理员权限）：

```powershell
cd antivirus-immunity-core
cargo run -- --mode active --policy quarantine --ai true
```

### 步骤 3：运行模拟病毒

打开**第二个终端**：

```powershell
cd antivirus-immunity-core
.\target\debug\examples\mock_antigen.exe
```

### 步骤 4：观察结果

切换回第一个终端，你应该看到类似输出：

```
8472   mock_antigen.exe          CRITICAL        YARA match: Test_Malware_Signature
    [!!!] QUARANTINING & ELIMINATING... QUARANTINED (a1b2c3d4). TARGET ELIMINATED.
```

🎉 **恭喜！** 你刚刚完整体验了一次免疫响应：
1. **感知层（TLR）** 发现了新进程
2. **决策层（Memory B Cell + YARA）** 识别出恶意特征
3. **响应层（Cytotoxic T Cell）** 隔离文件并终止了进程

### 使用辅助工具分析可疑文件

项目还自带了一个**抗原提取器**工具，可以分析任意可执行文件中的可疑字符串：

```powershell
# 构建工具
cargo build --bin antigen_extractor

# 分析某个可疑文件（替换为实际路径）
.\target\debug\antigen_extractor.exe "C:\path\to\suspicious_file.exe"

# 设置最小字符串长度（默认为 4）
.\target\debug\antigen_extractor.exe "C:\path\to\suspicious_file.exe" 6
```

输出会用 🔍 标记出可疑字符串（如注册表路径、网络 URL、敏感 API 调用等）。

---

## 📊 日志与审计

所有安全事件都以 **JSONL**（每行一个 JSON 对象）格式记录在 `logs/` 目录中。

### 日志文件位置

```
antivirus-immunity-core/
  logs/
    security_events.jsonl        ← 当前活跃日志
    security_events_20260331.jsonl  ← 自动轮转的历史日志
```

### 日志条目示例

```json
{
  "timestamp": "2026-03-31T15:30:00.000Z",
  "event_type": "ThreatDetected",
  "pid": 8472,
  "process_name": "mock_antigen.exe",
  "process_path": "C:\\...\\mock_antigen.exe",
  "assessment": "CRITICAL",
  "detail": "YARA match: Test_Malware_Signature",
  "action_taken": "QUARANTINE",
  "ai_verdict": null,
  "danger_level": "Normal"
}
```

### 日志事件类型

| 事件类型 | 说明 |
|---------|------|
| `SystemStart` | 系统启动 |
| `LearningComplete` | 学习模式完成 |
| `ProcessDetected` | 新进程被检测到 |
| `ThreatDetected` | 威胁被识别 |
| `ThreatEliminated` | 威胁被消除 |
| `FileQuarantined` | 文件被隔离 |
| `DangerSignal` | 系统压力信号（CPU 飙升等） |
| `AiAnalysis` | AI Cortex 分析结果 |

### 查看日志的便捷方法

```powershell
# 查看最新 20 条日志
Get-Content logs\security_events.jsonl -Tail 20

# 搜索所有 CRITICAL 事件
Select-String "CRITICAL" logs\security_events.jsonl

# 搜索 AI 分析记录
Select-String "AiAnalysis" logs\security_events.jsonl

# 使用 Python 美化输出（如果你有 Python）
python -c "import json,sys;[print(json.dumps(json.loads(l),indent=2,ensure_ascii=False)) for l in open('logs/security_events.jsonl')]"
```

### 自动轮转

日志文件大小超过 **50MB** 时自动轮转，旧日志会被重命名为带日期的文件名。

---

## 📦 隔离区管理

被隔离的文件存放在 `quarantine/` 目录中，并以 UUID 重命名以防止误执行。

### 查看隔离区

```powershell
cargo run -- --mode quarantine-list
```

### 隔离区目录结构

```
antivirus-immunity-core/
  quarantine/
    manifest.json                ← 隔离清单（元数据）
    a1b2c3d4-e5f6-...           ← 被隔离的文件（UUID 重命名）
    b2c3d4e5-f6a7-...           ← 被隔离的文件
```

### 清单文件 (manifest.json)

清单记录了每个被隔离文件的完整信息：
- 原始路径
- SHA256 哈希
- 隔离原因
- 关联的进程名和 PID
- 隔离时间
- 当前状态（Active / Released / Deleted）

> ⚠️ **注意**：隔离区中的文件已被重命名且无扩展名，不会被意外执行。但请不要手动修改 `quarantine/` 目录内容。

---

## 📝 YARA 规则自定义

YARA 规则文件位于 `antigens.yar`，你可以添加自定义规则来扩展检测能力。

### 当前内置规则

| 规则名 | 类别 | 严重度 | 说明 |
|--------|------|--------|------|
| `Test_Malware_Signature` | test | CRITICAL | EICAR 测试文件 |
| `Ransomware_Note_Indicators` | ransomware | CRITICAL | 勒索信特征 |
| `Ransomware_Extension_Changer` | ransomware | HIGH | 批量文件加密行为 |
| `Credential_Harvester` | credential_theft | CRITICAL | 凭证窃取工具 (mimikatz等) |
| `LSASS_Memory_Dump` | credential_theft | CRITICAL | LSASS 内存转储 |
| `Registry_Persistence` | persistence | HIGH | 注册表持久化 |
| `Scheduled_Task_Persistence` | persistence | MEDIUM | 计划任务持久化 |
| `Suspicious_Script_Exec` | execution | HIGH | 可疑脚本执行 |
| `PowerShell_Obfuscation` | evasion | HIGH | PowerShell 混淆 |
| `Process_Injection` | injection | CRITICAL | 进程注入 |
| `Reverse_Shell_Indicators` | c2 | CRITICAL | 反向Shell |
| `Cryptominer_Indicators` | cryptominer | HIGH | 加密货币挖矿 |

### 添加自定义规则

编辑 `antivirus-immunity-core/antigens.yar`，按以下模板添加：

```yara
rule My_Custom_Rule {
    meta:
        description = "Description of what this rule detects"
        severity = "HIGH"           // CRITICAL, HIGH, MEDIUM, LOW
        category = "custom"
    strings:
        $s1 = "suspicious_string_1" nocase
        $s2 = "suspicious_string_2"
    condition:
        any of them
}
```

保存后重启引擎即可生效，无需重新编译。

---

## ❓ 常见问题 FAQ

### Q1: "以管理员身份运行"是必须的吗？

**A**: 强烈推荐。没有管理员权限时：
- ✅ 可以：监控进程、YARA 扫描、AI 分析
- ❌ 不能：终止其他用户的进程、读取受保护进程的路径

### Q2: 我没有安装 Ollama，能用吗？

**A**: 完全可以！AI Cortex 是**可选功能**。不安装 Ollama 时：
- 使用 `--ai false` 禁用 AI
- 或保持默认——系统检测到 Ollama 不可达时会自动回退到纯规则引擎模式
- 基础的 YARA 扫描 + 路径验证 + 哈希白名单仍然可以工作

### Q3: 学习模式需要运行多久？

**A**: 几秒钟即可完成。它是一次性快照，不是持续学习。如果你安装了新软件后想让系统认识它，重新运行一次学习模式即可。

### Q4: 被隔离的文件能恢复吗？

**A**: 可以。隔离清单（`quarantine/manifest.json`）记录了每个文件的原始路径。当前版本需要手动恢复：
1. 查看 `manifest.json` 找到 UUID 和原始路径
2. 将 `quarantine/<UUID>` 文件重命名并移回原始路径

> 未来版本会添加 `--mode quarantine-release <ID>` 命令。

### Q5: CPU 占用高怎么办？

**A**: 调大轮询间隔：
```powershell
cargo run -- --mode monitor --interval 2000   # 每 2 秒扫描一次
cargo run -- --mode monitor --interval 5000   # 每 5 秒扫描一次
```

### Q6: 会不会误杀正常软件？

**A**: 有以下保护机制：
1. **学习模式**建立白名单，已知程序不会被误杀
2. **路径验证**防止仅凭进程名判断
3. **多层评估**需要多个信号同时触发才会判定为 CRITICAL
4. **AI 复审**对模糊案例进行二次判断
5. **被动监控模式**不执行任何动作，可以先观察

> 💡 建议：先用 `--mode monitor` 观察 1~2 天，确认没有误报后再切换到 `--mode active`。

### Q7: 支持 Linux / macOS 吗？

**A**: 当前版本**仅支持 Windows**。核心的进程监控和终止功能使用了 Windows API（ToolHelp32、OpenProcess 等）。跨平台支持在未来的路线图中。

### Q8: 危险信号 (Danger Signal) 是什么意思？

**A**: 系统会监控以下系统压力指标：

| 信号 | 触发条件 | 含义 |
|------|---------|------|
| CPU 飙升 | CPU > 90% | 可能有挖矿或恶意计算 |
| 内存压力 | 内存 > 95% | 可能有内存泄漏攻击 |
| 进程洪水 | 短时间创建大量进程 | 可能是 Fork Bomb 或恶意脚本 |

危险信号会动态提高免疫灵敏度——平时被判为 UNKNOWN 的进程，在高压环境下会被升级为 SUSPICIOUS。

---

## ⚠️ 安全提示与免责声明

### 安全提示

1. 🔒 **始终以管理员权限运行**以获得完整的进程管理能力
2. 📚 **首次使用务必先运行学习模式**，否则所有进程都会被标记为未知
3. 👁️ **先用被动监控模式观察**，确认系统行为符合预期后再启用主动防御
4. 💾 **定期备份 `immunity_db.json`**，这是系统的免疫记忆
5. 📋 **定期检查日志**，关注 CRITICAL 和 AI 分析记录
6. 🧬 **不要修改隔离区文件**，可能导致清单不一致

### 免责声明

> ⚠️ **Antivirus-Immunity 是一个实验性/教育性项目**，旨在探索人工免疫系统 (AIS) 理论在端点安全中的应用。  
>  
> - 本软件**不能替代**成熟的商业杀毒软件（如 Windows Defender、卡巴斯基等）  
> - 在生产环境中使用前请充分测试  
> - 主动防御模式可能终止正常进程，请谨慎使用  
> - 开发者不对因使用本软件造成的任何损失负责

---

## 🎓 进阶阅读

想深入了解项目的设计理念？

- **README.md** — 项目总览、架构设计、技术栈
- **src/immune/ai_cortex.rs** — AI Cortex 模块的设计原则和实现
- **src/immune/danger_theory.rs** — 危险信号理论的实现
- **src/immune/path_validator.rs** — MHC 路径验证机制
- **antigens.yar** — YARA 规则库，了解支持检测的威胁类型

---

<div align="center">

**Made with 🧬 by KingDragon-yc**  
*Inspired by the elegance of the biological immune system.*

</div>
