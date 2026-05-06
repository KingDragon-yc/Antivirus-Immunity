# Antivirus-Immunity

> An experimental antivirus/security engine inspired by biological immune systems, augmented with local AI analysis.

[![CI](https://github.com/KingDragon-yc/Antivirus-Immunity/actions/workflows/ci.yml/badge.svg)](https://github.com/KingDragon-yc/Antivirus-Immunity/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Antivirus-Immunity is a Rust workspace exploring how Artificial Immune System (AIS) ideas can be applied to endpoint and cloud security. Instead of relying only on static signatures, the project combines process observation, path validation, hash-based immune memory, YARA rules, danger-signal correlation, and optional local LLM review through Ollama.

This is a research and education project. It is not a replacement for production antivirus or EDR software.

## Project Status

The repository currently contains two engine directions:

| Component | Platform | Status | Notes |
| --- | --- | --- | --- |
| `antivirus-immunity-core` | Windows | Active prototype, v0.3 | Process polling through Windows ToolHelp APIs, YARA scanning, hash memory, path validation, quarantine, termination, JSONL logs, optional Ollama review. |
| `antivirus-immunity-ebpf` | Linux | Experimental architecture, v0.4 | Policy engine, container-aware design, eBPF probe C source, and `/proc` fallback are present. Real libbpf-rs CO-RE loading and ring-buffer consumption are planned. |
| `antivirus-immunity-common` | Cross-platform | Shared library | Common event types, logger, hash cache, and AI Cortex client used by the Linux direction. |

## Immune-System Model

The codebase uses biological immune-system concepts as design metaphors:

| Biology concept | Project module | Security role |
| --- | --- | --- |
| Toll-like receptors | Process/eBPF probes | Detect new process and system events. |
| Memory B cells | Hash memory | Remember trusted binaries learned during a clean baseline scan. |
| MHC/path validation | `PathValidator` | Detect system-process impersonation, such as `svchost.exe` outside `System32`. |
| Danger theory | `DangerTheoryEngine` | Increase suspicion during CPU spikes, memory pressure, or process floods. |
| Cytotoxic T cells | `CytotoxicTCell` | Terminate confirmed malicious processes. |
| Quarantine | `Quarantine` | Copy suspicious files into an isolated directory and record metadata. |
| Cerebral cortex | `AiCortex` | Ask a local Ollama model to review ambiguous cases. |

## Workspace Layout

```text
Antivirus-Immunity/
├── Cargo.toml
├── README.md
├── USER_MANUAL.md
├── antivirus-immunity-common/
│   └── src/
│       ├── ai_cortex.rs
│       ├── event.rs
│       ├── hash_cache.rs
│       ├── lib.rs
│       └── logger.rs
├── antivirus-immunity-core/
│   ├── antigens.yar
│   ├── src/
│   │   ├── main.rs
│   │   ├── receptor/
│   │   ├── immune/
│   │   └── effector/
│   ├── tests/
│   │   └── mock_antigen.rs
│   └── tools/
│       └── antigen_extractor.rs
└── antivirus-immunity-ebpf/
    ├── build.sh
    ├── bpf/
    │   └── probes.bpf.c
    └── src/
        ├── main.rs
        ├── probe.rs
        ├── policy.rs
        ├── container.rs
        ├── process_tree.rs
        ├── resource_aware.rs
        ├── network.rs
        └── filesystem.rs
```

## Windows Core Engine

The Windows prototype is the most complete implementation today.

### Detection Pipeline

```text
new process
  -> YARA antigen scan
  -> path validation
  -> trusted hash memory
  -> danger-signal correlation
  -> optional AI Cortex review
  -> log / quarantine / terminate
```

### Main Features

- Process polling with Windows ToolHelp APIs.
- SHA256 hash cache to avoid repeated hashing of unchanged files.
- `immunity_db.json` trusted-hash memory created by learning mode.
- YARA rule database in `antigens.yar`.
- Path checks for common Windows process impersonation.
- CPU, memory, and process-flood danger signals.
- Optional local Ollama analysis for ambiguous cases.
- JSONL audit logging under `logs/`.
- Quarantine manifest under `quarantine/`.

### Quick Start

Run these commands from the Windows engine directory:

```powershell
cd antivirus-immunity-core
cargo build --release
```

Learn the current clean system baseline:

```powershell
cargo run -- --mode learn
```

Start passive monitoring:

```powershell
cargo run -- --mode monitor --ai false
```

Start monitoring with local AI review:

```powershell
cargo run -- --mode monitor --ai true --ai-model qwen2.5:3b
```

Start active defense with quarantine:

```powershell
cargo run -- --mode active --policy quarantine --ai true
```

View active quarantine entries:

```powershell
cargo run -- --mode quarantine-list
```

> Active defense can terminate processes and move files. Use passive monitoring first until you understand the alerts on your machine.

## Ollama / AI Cortex

AI Cortex is optional. If Ollama is unavailable, the engine falls back to rule-based evaluation.

Install and pull a small local model:

```powershell
ollama pull qwen2.5:3b
```

Then run:

```powershell
cargo run -- --mode monitor --ai true --ai-model qwen2.5:3b
```

The AI request is local-first: process context is sent to the configured Ollama endpoint, which defaults to `http://localhost:11434`.

## Linux eBPF Engine

The Linux engine is the v0.4 direction for cloud servers, containers, Kubernetes nodes, and AI agent sandboxes.

Implemented so far:

- Command-line engine shell in Rust.
- Hardware-aware Lite mode.
- Policy profiles for `server`, `container`, and `ai-agent`.
- Container context and process ancestry scaffolding.
- eBPF C probe source for process exec, TCP connect, credential change, and LSM file hooks.
- Development fallback that polls `/proc` for new processes.

Planned next:

- Compile and load CO-RE eBPF objects through `libbpf-rs`.
- Consume BPF ring-buffer events in Rust.
- Wire file/network/credential events into the policy engine.
- Add real LSM access blocking and XDP/TC network enforcement.
- Add Kubernetes deployment artifacts and Prometheus metrics.

Build the Rust userspace component:

```bash
cd antivirus-immunity-ebpf
cargo build --release
```

Build eBPF probes on a Linux host with `clang`, `bpftool`, and kernel BTF support:

```bash
cd antivirus-immunity-ebpf
./build.sh probes
```

## Useful Commands

Format the workspace:

```bash
cargo fmt --all
```

Check the shared crate:

```bash
cargo check -p antivirus-immunity-common
```

Check the Windows core crate on Windows:

```powershell
cargo check -p antivirus-immunity-core
```

Check the Linux engine Rust crate:

```bash
cargo check -p antivirus-immunity-ebpf
```

Run tests:

```bash
cargo test --workspace
```

Platform-specific crates may require matching operating systems and toolchains. The CI workflow builds the Windows core on Windows and the Linux/eBPF userspace crate on Ubuntu.

## YARA Rules

The Windows engine loads rules from:

```text
antivirus-immunity-core/antigens.yar
```

The included rules cover test signatures and common malware indicators such as ransomware notes, credential dumping, persistence, suspicious script execution, PowerShell obfuscation, process injection, reverse shells, and cryptomining.

Add custom rules by editing `antigens.yar` and restarting the engine.

## Roadmap

- Stabilize the Windows core prototype and CLI.
- Split documentation clearly between Windows v0.3 and Linux v0.4.
- Convert the Linux eBPF implementation from architecture scaffold to real libbpf-rs runtime.
- Add more unit tests around path validation, YARA decisions, quarantine behavior, and policy profiles.
- Add signed release artifacts and clearer installation instructions.
- Add SIEM-friendly event output and deployment examples.

## Safety Notice

This project can terminate processes and move files when active defense is enabled. Run it in a test environment first, keep backups, and prefer passive monitoring until the local baseline is understood.

Do not use this project as your only security control in production.

## License

MIT

## Author

KingDragon-yc
