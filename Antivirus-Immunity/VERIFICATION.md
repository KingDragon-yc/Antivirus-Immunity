# ✅ Antivirus-Immunity 验收清单

> 给评审者：按本清单逐项操作，每步都给出**可复现命令**和**预期结果**。
> 全部通过 = 项目交付合格。任何一项不符请在对应行的 ❑ 里记下实际现象。
>
> 验收环境：Windows 10/11 x64（core 引擎）+ 可选 WSL2/Ubuntu（ebpf 引擎、CI 复现）。

---

## 0. 预备：拉取正确版本

```powershell
git clone https://github.com/KingDragon-yc/Antivirus-Immunity.git
cd Antivirus-Immunity
git checkout v0.4.1        # 或 main 分支最新提交
```

- ❑ 仓库根有 `Cargo.toml`（workspace）、`README.md`、`USER_MANUAL.md`、`VERIFICATION.md`（本文件）
- ❑ 三个子 crate：`antivirus-immunity-common` / `-core` / `-ebpf`
- ❑ `Cargo.toml` 里 `resolver = "3"`，三个 crate 的 `edition = "2024"`

---

## 1. 构建验收

### 1.1 Windows 构建（core + common）

前置：Rust 1.85+（`rustup default stable`）、VS Build Tools（C++ + Windows SDK）。

```powershell
cargo build --release -p antivirus-immunity-common -p antivirus-immunity-core
```

- ❑ 退出码 0，无 error
- ❑ 产物：`antivirus-immunity-core/target/release/antivirus-immunity-core.exe`
- ❑ **不再需要系统 OpenSSL**（v0.4 起 reqwest 切到 rustls，依赖链无系统 OpenSSL 需求）

### 1.2 版本号自检

```powershell
.\antivirus-immunity-core\target\release\antivirus-immunity-core.exe --version
```

- ❑ 输出 `antivirus-immunity-core 0.4.1`

### 1.3 Linux 构建（ebpf + common，可选，需 WSL2/Linux）

```bash
cargo build --release -p antivirus-immunity-common -p antivirus-immunity-ebpf
```

- ❑ 退出码 0（注意：ebpf 的 netlink/probe/process_tree 代码是 `#[cfg(target_os="linux")]`，必须在 Linux 编译）

---

## 2. 自动化测试

### 2.1 Windows 单元测试（core）

```powershell
cargo test -p antivirus-immunity-core
```

- ❑ 至少 **25 个测试通过**（7 path_validator + 13 fuzzy_hash + 5 其它）
- ❑ 0 失败

### 2.2 跨平台单测（common + ebpf，任意 OS）

```bash
cargo test -p antivirus-immunity-common   # 期望 4 passed
cargo test -p antivirus-immunity-ebpf     # 期望 5 passed（含 procfs ppid 回归）
```

- ❑ common 4 passed（safety 模块的 truncate/sanitize/置信度门控/可信路径）
- ❑ ebpf 5 passed（procfs 的 `parse_ppid` 含空格/括号/畸形输入回归测试）

### 2.3 代码质量门槛

```bash
cargo fmt --all -- --check                 # 格式
cargo clippy -p antivirus-immunity-common -- -D warnings
cargo clippy -p antivirus-immunity-ebpf -- -A dead_code -D warnings
cargo clippy -p antivirus-immunity-core -- -D warnings
```

- ❑ fmt 无 diff
- ❑ 三个 crate clippy 全部 `-D warnings` 通过（零 warning）

---

## 3. 功能演示（Windows，需管理员 PowerShell）

### 3.1 学习模式（建立免疫记忆）

```powershell
cd antivirus-immunity-core
cargo run --release -- --mode learn
```

- ❑ banner 显示 `v0.4.1`
- ❑ 输出 `Found N processes` + `Learning complete`
- ❑ 生成 `immunity_db.json`，内容含 `"version": 2` 和 `signatures` 数组（每条含 sha256 + 可选 ssdeep/imphash）

### 3.2 端到端查杀（mock_antigen）

终端 1（管理员）：
```powershell
cargo run --release -- --mode active --policy quarantine
```

终端 2：
```powershell
cargo build --example mock_antigen
.\target\debug\examples\mock_antigen.exe
```

- ❑ 终端 1 检测到 `mock_antigen.exe`，状态 `CRITICAL`，详情 `Antigen Detected: Test_Malware_Signature`
- ❑ 执行 `QUARANTINING & ELIMINATING` → 文件被移入 `quarantine/`，进程被终止
- ❑ `quarantine/` 下出现 `<uuid>.exe.quarantine` 文件 + `.qdb` 清单

### 3.3 隔离列表

```powershell
cargo run --release -- --mode quarantine-list
```

- ❑ 列出上一步隔离的条目（UUID / 原路径 / 进程名 / 日期）

---

## 4. 安全特性验证（v0.4.x 重点）

### 4.1 AI 安全门控（需 Ollama，可选）

这条验证"AI 即使建议杀进程，也不会杀可信路径下的进程"。

```powershell
# 启动带 AI 的主动防御
cargo run --release -- --mode active --policy kill --ai true --ai-model qwen2.5:3b
```

构造一个位于 `C:\Windows\System32\` 的"可疑"进程（或观察 AI 对系统进程的判断）：
- ❑ AI 对可信路径（System32 / Program Files）下的进程即使返回 `TERMINATE`，日志里也是 `AI_ACTION_SUPPRESSED`，**进程不被杀**
- ❑ 日志 `logs/security_events.jsonl` 中能搜到 `"action_taken":"AI_ACTION_SUPPRESSED"`

### 4.2 模糊哈希变体识别

验证"软件更新后仍能识别为可信"（v0.4 核心能力）：

1. 学习一个程序（如 `notepad.exe`）→ 记入 `immunity_db.json`
2. 对其做微小修改（如追加几个字节）改变 SHA256 但保持高 ssdeep 相似度
3. 监控模式扫描修改后的文件

- ❑ 评估结果为 `SAFE` 或 `AI_REVIEW`（Ssdeep 相似度 ≥80% 命中），而非纯 `UNKNOWN`
- ❑ 日志 detail 含 `Ssdeep NN% similarity`

### 4.3 路径伪装检测（Imposter）

把一个可执行文件改名为 `svchost.exe` 放到非 System32 目录，监控模式扫描：
- ❑ 状态 `CRITICAL`，详情 `PATH IMPOSTER: 'svchost.exe' expected in [C:\Windows\System32] but found in '...'`

---

## 5. CI 验收（GitHub Actions）

打开仓库的 Actions 页面，确认最新一次 `main` 或 PR 的 CI 运行：

- ❑ **Linux (common + ebpf)** job：success
- ❑ **Windows (common + core)** job：success（含 core 的 25+ 测试）
- ❑ **Security Audit** job：success

---

## 6. 文档与诚实度

- ❑ README 顶部实现状态表如实标注 eBPF 探针为"🚧 规划中"，未夸大为已实现
- ❑ README 徽章 `Rust-2024`，与 Cargo.toml 的 `edition = "2024"` 一致
- ❑ USER_MANUAL 版本号 `v0.4.1`，描述了模糊哈希 / AI 安全门控 / 隔离区机制
- ❑ 免责声明明确"实验性/教育性项目，不能替代商业杀毒"

---

## 附：已知限制（不算缺陷，验收时知悉即可）

| 项 | 现状 | 说明 |
|----|------|------|
| eBPF 探针 | 未接入 | `bpf/probes.bpf.c` 已编写但未通过 libbpf-rs 加载；ebpf 运行时用 Netlink Connector |
| core 跨平台 | 仅 Windows | core 用 Win32 API（ToolHelp32/TerminateProcess），Linux 上不编译（设计如此） |
| 隔离区 CLI | 无 release/purge 子命令 | API 有 `release`/`purge` 方法，CLI 暂未暴露，需手动恢复 |
| 进程监控盲区 | 轮询型 | core 每 N ms 轮询一次，短命进程（<轮询间隔）可能漏检；ebpf 的 Netlink 是事件驱动无此问题 |
