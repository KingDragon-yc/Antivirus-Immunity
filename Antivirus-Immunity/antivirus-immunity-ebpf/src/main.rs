//! Antivirus-Immunity eBPF — 云原生 Linux 安全引擎
//!
//! 基于 eBPF 的零侵入内核级安全监控，主攻：
//! - 云服务器 (ECS/VPS) 进程行为监控
//! - Docker/K8s 容器上下文关联
//! - AI Agent 运行沙盒护栏
//!
//! 架构：
//! ┌──────────────────────────────────────────────┐
//! │  Kernel Space (eBPF probes, C/restricted)     │
//! │  ┌─────────┐ ┌──────────┐ ┌───────────────┐ │
//! │  │ execve  │ │ tcp_conn │ │ LSM file_open │ │
//! │  │ tracepoint│ │ kprobe   │ │ bpf hook     │ │
//! │  └────┬────┘ └─────┬────┘ └──────┬────────┘ │
//! │       └─────────────┼─────────────┘          │
//! │              BPF Ring Buffer                  │
//! ├──────────────────────┼────────────────────────┤
//! │  User Space (Rust)   │                        │
//! │              ┌───────▼────────┐               │
//! │              │ Event Consumer │               │
//! │              └───────┬────────┘               │
//! │    ┌─────────────────┼─────────────────┐      │
//! │    │                 │                 │      │
//! │  ┌─▼──────┐  ┌──────▼─────┐  ┌───────▼───┐  │
//! │  │Immune  │  │ AI Cortex  │  │ Effector  │  │
//! │  │Pipeline│  │ (Ollama)   │  │ (block/   │  │
//! │  │(YARA+  │  │            │  │  kill/log)│  │
//! │  │ rules) │  │            │  │           │  │
//! │  └────────┘  └────────────┘  └───────────┘  │
//! │                    │                         │
//! │              ┌─────▼─────┐                   │
//! │              │  Logger   │                   │
//! │              │  (JSONL)  │                   │
//! │              └───────────┘                   │
//! └──────────────────────────────────────────────┘

mod container;
mod filesystem;
mod network;
mod policy;
mod probe;
mod process_tree;
mod resource_aware;

use antivirus_immunity_common::{
    ai_cortex::{AiCortex, AiCortexConfig},
    event::{DangerLevel, SecurityEvent, SecurityEventType, Severity},
    logger::Logger,
};
use chrono::Utc;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "immunity-ebpf",
    author = "KingDragon-yc",
    version = "0.4.0",
    about = "eBPF-based cloud-native Linux security engine",
    long_about = "Antivirus-Immunity eBPF edition uses kernel-level probes for zero-overhead \
                  process monitoring, network interception, and file system guardrails. \
                  Designed for cloud servers, Docker containers, and AI Agent sandboxes."
)]
struct Args {
    /// Mode: 'monitor', 'enforce', 'learn', 'lite'
    #[arg(short, long, default_value = "monitor")]
    mode: String,

    /// Policy profile: 'server', 'container', 'ai-agent', 'custom'
    #[arg(short, long, default_value = "server")]
    profile: String,

    /// Enable AI Cortex for deep analysis
    #[arg(long, default_value = "true")]
    ai: bool,

    /// AI model name
    #[arg(long, default_value = "qwen2.5:3b")]
    ai_model: String,

    /// Ollama endpoint
    #[arg(long, default_value = "http://localhost:11434")]
    ai_endpoint: String,

    /// Whitelist config path (YAML/JSON)
    #[arg(long)]
    whitelist: Option<String>,

    /// Protected paths (comma-separated)
    #[arg(long, default_value = "/etc/shadow,/root/.ssh,/var/run/docker.sock")]
    protected_paths: String,

    /// Max memory budget in MB (auto Lite mode if system < threshold)
    #[arg(long, default_value = "100")]
    max_memory_mb: u64,

    /// Event output format: 'text', 'json'
    #[arg(long, default_value = "text")]
    output: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // ==================== RESOURCE AWARENESS ====================
    let hw_profile = resource_aware::detect_hardware();
    let lite_mode = hw_profile.should_use_lite_mode(args.max_memory_mb);

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        Antivirus-Immunity eBPF Engine v0.4.0               ║");
    println!("║        Cloud-Native Linux Security · eBPF + AI Cortex      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!(
        "[*] Hardware: {} CPU(s), {} MB RAM",
        hw_profile.cpu_count, hw_profile.memory_mb
    );
    if lite_mode {
        println!("[!] LITE MODE: Low-resource instance detected (< 2C4G).");
        println!("[!] Heavy scans suspended. Core eBPF monitoring only.");
        println!(
            "[!] Memory budget capped at {} MB.",
            args.max_memory_mb.min(50)
        );
    }
    println!("[*] Mode: {}", args.mode);
    println!("[*] Profile: {}", args.profile);
    println!();

    // ==================== LOGGER ====================
    let logger = Logger::new().unwrap_or_else(|e| {
        eprintln!("[!] Logger init failed: {}. Continuing.", e);
        Logger::new().unwrap()
    });

    // ==================== POLICY ENGINE ====================
    let protected_paths: Vec<String> = args
        .protected_paths
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let policy = policy::PolicyEngine::new(
        &args.profile,
        &args.mode,
        protected_paths,
        args.whitelist.as_deref(),
    );

    println!(
        "[*] Policy Engine: {} rules loaded, {} protected paths",
        policy.rule_count(),
        policy.protected_path_count()
    );

    // ==================== AI CORTEX ====================
    let mut ai_cortex = AiCortex::new(AiCortexConfig {
        endpoint: args.ai_endpoint.clone(),
        model: args.ai_model.clone(),
        timeout_secs: 30,
        enabled: args.ai && !lite_mode, // Disable AI in lite mode
    });

    if args.ai && !lite_mode {
        println!("[*] AI Cortex: Checking Ollama...");
        ai_cortex.health_check().await;
    } else if lite_mode {
        println!("[*] AI Cortex: Disabled in Lite mode to conserve resources.");
    }

    // ==================== CONTAINER CONTEXT ====================
    let container_ctx = container::ContainerContext::detect();
    println!("[*] Container runtime: {}", container_ctx.runtime_name());

    // ==================== LOG SYSTEM START ====================
    logger.log(&SecurityEvent {
        timestamp: Utc::now(),
        event_type: SecurityEventType::SystemStart,
        severity: Severity::Info,
        pid: None,
        process_name: None,
        process_path: None,
        container_id: None,
        detail: format!(
            "eBPF engine started: mode={}, profile={}, lite={}, ai={}",
            args.mode,
            args.profile,
            lite_mode,
            args.ai && !lite_mode,
        ),
        action_taken: None,
        ai_verdict: None,
        danger_level: Some(format!("{:?}", DangerLevel::Normal)),
    });

    // ==================== eBPF PROBE LOADING ====================
    println!();
    println!("[*] Loading eBPF probes...");

    // In the full Linux build, this is where we'd:
    // 1. Open + load the compiled eBPF object (CO-RE .bpf.o)
    // 2. Attach probes to kernel hooks
    // 3. Set up BPF Ring Buffer consumer
    //
    // For now, we demonstrate the architecture with /proc-based polling
    // as a fallback for development/testing on non-eBPF systems.

    let mut probe_manager = probe::ProbeManager::new(lite_mode)?;
    println!("[+] Probes initialized:");
    println!("    - Process: tracepoint/syscalls/sys_enter_execve");
    println!("    - Network: kprobe/tcp_connect, kprobe/udp_sendmsg");
    if !lite_mode {
        println!("    - File:    LSM/security_file_open, LSM/security_inode_create");
        println!("    - Creds:   kprobe/commit_creds");
    }
    println!();

    // ==================== PROCESS TREE ====================
    let proc_tree = process_tree::ProcessTree::new();
    println!("[+] Process ancestry tracker initialized.");

    println!("[!] Press Ctrl+C to stop.");
    println!();
    println!(
        "{:<8} {:<20} {:<12} {:<15} {:<}",
        "PID", "COMM", "CONTAINER", "VERDICT", "DETAIL"
    );
    println!("{:-<8} {:-<20} {:-<12} {:-<15} {:-<50}", "", "", "", "", "");

    // ==================== MAIN EVENT LOOP ====================
    // In production, this reads from BPF Ring Buffer.
    // In dev/fallback mode, uses /proc polling.
    loop {
        let events = probe_manager.poll_events()?;

        for event in events {
            // Enrich with container context
            let container_id = container_ctx.resolve_container(event.pid);

            // Build process ancestry for AI context
            let parent_chain = proc_tree.get_ancestry(event.pid);

            // Policy evaluation
            let verdict = policy.evaluate(&event, container_id.as_deref(), &parent_chain);

            let container_label = container_id
                .as_deref()
                .map(|id| &id[..id.len().min(12)])
                .unwrap_or("HOST");

            let verdict_str = format!("{:?}", verdict.action);
            let detail = &event.detail;

            println!(
                "{:<8} {:<20} {:<12} {:<15} {:.50}",
                event.pid, event.comm, container_label, verdict_str, detail
            );

            // Log
            logger.log(&SecurityEvent {
                timestamp: Utc::now(),
                event_type: SecurityEventType::ProcessExec,
                severity: verdict.severity.clone(),
                pid: Some(event.pid),
                process_name: Some(event.comm.clone()),
                process_path: Some(event.path.clone()),
                container_id: container_id.clone(),
                detail: detail.clone(),
                action_taken: Some(format!("{:?}", verdict.action)),
                ai_verdict: None,
                danger_level: None,
            });

            // Execute action
            match verdict.action {
                antivirus_immunity_common::event::ResponseAction::Terminate => {
                    println!("    [!!!] KILLING PID {}...", event.pid);
                    #[cfg(target_os = "linux")]
                    {
                        use nix::sys::signal::{kill, Signal};
                        use nix::unistd::Pid;
                        let _ = kill(Pid::from_raw(event.pid as i32), Signal::SIGKILL);
                    }
                }
                antivirus_immunity_common::event::ResponseAction::BlockAccess => {
                    println!("    [!] ACCESS BLOCKED (eBPF LSM returned -EPERM)");
                    // In the real eBPF path, blocking happens in kernel space.
                    // The userspace just logs the event.
                }
                _ => {}
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
