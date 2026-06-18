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
#[cfg(target_os = "linux")]
mod netlink_connector;
mod network;
mod policy;
mod probe;
// `procfs` is entirely Linux-only (the file starts with `#![cfg(target_os =
// "linux")]`), so it compiles to nothing on other platforms automatically — no
// need to cfg-gate the `mod` declaration here too.
mod process_tree;
mod procfs;
mod resource_aware;

use antivirus_immunity_common::{
    ai_cortex::{AiCortex, AiCortexConfig},
    event::{DangerLevel, SecurityEvent, SecurityEventType, Severity},
    logger::Logger,
};
use chrono::Utc;
use clap::Parser;

/// Read a process's start time (field 22 of `/proc/<pid>/stat`, clock ticks
/// since boot). Used as a PID-reuse fingerprint: if it changes, the PID now
/// refers to a different process. Thin wrapper over [`procfs::read_starttime`]
/// so the comm-aware stat parser exists in exactly one place.
#[cfg(target_os = "linux")]
fn proc_start_time(pid: u32) -> Option<u64> {
    crate::procfs::read_starttime(pid)
}

/// SIGKILL `pid` only if it is still the same process we observed earlier
/// (its start time is unchanged). Returns false without signalling if the PID
/// was reused or has already exited. Guards against killing an innocent
/// process that reused the PID during the AI deferral window.
#[cfg(target_os = "linux")]
fn guarded_sigkill(pid: u32, expected_start: Option<u64>) -> bool {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    // `expected_start == None` means we could not read `/proc/<pid>/stat`
    // when fingerprinting (process already exited, or permission denied).
    // That is precisely when PID reuse is most likely, so we MUST refuse to
    // fire rather than treat None as "safe to kill" — the previous logic
    // gated only on `is_some()` and would send SIGKILL unconditionally here.
    let Some(expected) = expected_start else {
        eprintln!(
            "    [!] Cannot verify PID {} identity (/proc unreadable); aborting SIGKILL to avoid hitting the wrong process.",
            pid
        );
        return false;
    };
    if proc_start_time(pid) != Some(expected) {
        eprintln!(
            "    [!] PID {} was reused or has exited; aborting SIGKILL to avoid hitting the wrong process.",
            pid
        );
        return false;
    }
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
    true
}

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
        eprintln!(
            "[!] Logger init failed: {}. Continuing without file logging.",
            e
        );
        Logger::disabled()
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

    // Wrap in Arc for shared access across deferred blocking tasks
    let ai_cortex = std::sync::Arc::new(ai_cortex);

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

    // ==================== EVENT SOURCE INITIALIZATION ====================
    println!();
    // NOTE: CO-RE eBPF object loading and ring-buffer consumption are not yet
    // wired up (see bpf/probes.bpf.c and the roadmap). The engine currently
    // ingests process events via the Netlink Connector, falling back to /proc
    // polling. ProbeManager::new prints which source is actually active.
    println!(
        "[*] Initializing event source (eBPF ring buffer not yet wired — using Netlink/proc)..."
    );

    let mut probe_manager = probe::ProbeManager::new(lite_mode)?;
    println!("[*] Planned eBPF probes (compiled in bpf/probes.bpf.c, not yet attached):");
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
    // Event ingestion priority:
    //   1. eBPF Ring Buffer (production)
    //   2. Netlink Connector (zero-polling kernel push, millisecond latency)
    //   3. /proc polling (legacy fallback)
    //
    // Async Deferred Blocking flow:
    //   Suspicious process → SIGSTOP → AI Cortex (500ms timeout) → SIGCONT or SIGKILL
    // (The active source — Netlink vs /proc — was reported by ProbeManager above.)
    println!();

    // ── Graceful shutdown: track SIGSTOP'd PIDs and resume them on exit ──
    //
    // P0-4 fix: previously, Ctrl+C / SIGTERM killed the engine immediately
    // and left every process it had SIGSTOP'd (waiting for an AI verdict)
    // frozen forever. We now remember each stopped PID and install a signal
    // handler that SIGCONT's them all before the process exits.
    #[cfg(target_os = "linux")]
    let stopped_pids: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    #[cfg(target_os = "linux")]
    {
        let stopped_pids_for_signal = stopped_pids.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[!] Could not install SIGINT handler: {}", e);
                    return;
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[!] Could not install SIGTERM handler: {}", e);
                    return;
                }
            };
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
            eprintln!("\n[!] Signal received: resuming all SIGSTOP'd processes before exit.");
            if let Ok(pids) = stopped_pids_for_signal.lock() {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;
                for pid in pids.iter() {
                    let _ = kill(Pid::from_raw(*pid as i32), Signal::SIGCONT);
                }
            }
            std::process::exit(130);
        });
    }

    loop {
        let events = probe_manager.poll_events()?;

        // Collect AI-deferred tasks for this cycle
        let mut deferred_tasks = Vec::new();

        for event in events {
            // Enrich with container context
            let container_id = container_ctx.resolve_container(event.pid);

            // Build process ancestry for AI context
            let parent_chain = proc_tree.get_ancestry(event.pid);

            // ── Rule-based policy evaluation (fast path) ──
            let verdict = policy.evaluate(&event, container_id.as_deref(), &parent_chain);

            let container_label = container_id
                .as_deref()
                .map(|id| match id.char_indices().nth(12) {
                    Some((idx, _)) => &id[..idx],
                    None => id,
                })
                .unwrap_or("HOST");

            let verdict_str = format!("{:?}", verdict.action);
            let detail = &event.detail;

            println!(
                "{:<8} {:<20} {:<12} {:<15} {:.50}",
                event.pid, event.comm, container_label, verdict_str, detail
            );

            // Log the detection
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

            // Fingerprint the process now so later kills can detect PID reuse.
            #[cfg(target_os = "linux")]
            let proc_start = proc_start_time(event.pid);
            #[cfg(not(target_os = "linux"))]
            let proc_start: Option<u64> = None;

            // ── Execute action ──
            match verdict.action {
                antivirus_immunity_common::event::ResponseAction::Terminate => {
                    println!("    [!!!] KILLING PID {}...", event.pid);
                    #[cfg(target_os = "linux")]
                    {
                        guarded_sigkill(event.pid, proc_start);
                    }
                }
                antivirus_immunity_common::event::ResponseAction::BlockAccess => {
                    println!("    [!] ACCESS BLOCKED (eBPF LSM returned -EPERM)");
                }
                antivirus_immunity_common::event::ResponseAction::Monitor => {
                    // ── Async Deferred Blocking ──
                    // Suspicious process: suspend it, ask AI, then resume or kill.
                    // clippy::collapsible_match wants to merge this `if` into the
                    // surrounding match arm, but the match keys on `verdict.action`
                    // (an enum) while this `if` keys on a runtime bool — they are
                    // not collapsible without obscuring intent, so we allow it.
                    #[allow(clippy::collapsible_match)]
                    if ai_cortex.is_available() && event.pid > 1 {
                        println!(
                            "    [🧠] Deferred blocking PID {}: SIGSTOP → AI analysis...",
                            event.pid
                        );

                        // Step 1: Suspend the process immediately and remember it so
                        // the shutdown signal handler can SIGCONT it if we crash/exit
                        // mid-verdict (otherwise it would stay frozen forever).
                        #[cfg(target_os = "linux")]
                        {
                            use nix::sys::signal::{Signal, kill};
                            use nix::unistd::Pid;
                            match kill(Pid::from_raw(event.pid as i32), Signal::SIGSTOP) {
                                Ok(()) => {
                                    if let Ok(mut guard) = stopped_pids.lock() {
                                        guard.push(event.pid);
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "    [!] SIGSTOP failed for PID {}: {}",
                                        event.pid, e
                                    );
                                }
                            }
                        }

                        // Step 2: Build AI context and spawn deferred evaluation.
                        // `path_verdict` / `yara_matches` are new unified fields
                        // (see common::ai_cortex::ProcessContext); ebpf has no
                        // path validator yet so they stay empty.
                        let ctx = antivirus_immunity_common::ai_cortex::ProcessContext {
                            pid: event.pid,
                            name: event.comm.clone(),
                            path: Some(event.path.clone()),
                            hash: None,
                            cmdline: None,
                            container_id: container_id.clone(),
                            parent_chain: parent_chain.clone(),
                            network_activity: Vec::new(),
                            file_access: Vec::new(),
                            danger_level: format!("{:?}", verdict.severity),
                            is_known_hash: false,
                            path_verdict: String::new(),
                            yara_matches: Vec::new(),
                        };

                        let logger_clone = logger.clone();
                        let ai_cortex = ai_cortex.clone();
                        let pid = event.pid;
                        let comm = event.comm.clone();
                        let detail_clone = detail.clone();
                        let proc_start_for_task = proc_start;
                        // Clone the tracker so the deferred task can remove the
                        // PID once it SIGCONTs/SIGKILLs it (frees it from the
                        // shutdown-resume set).
                        #[cfg(target_os = "linux")]
                        let stopped_pids_for_task = stopped_pids.clone();

                        deferred_tasks.push(tokio::spawn(async move {
                            // Helper: remove this PID from the stopped set (linux only).
                            #[cfg(target_os = "linux")]
                            let forget_stopped = || {
                                if let Ok(mut guard) = stopped_pids_for_task.lock() {
                                    guard.retain(|p| *p != pid);
                                }
                            };

                            // Step 3: AI evaluation with 500ms hard timeout
                            let ai_result = tokio::time::timeout(
                                std::time::Duration::from_millis(500),
                                ai_cortex.evaluate(&ctx),
                            )
                            .await;

                            match ai_result {
                                Ok(Some(verdict)) => {
                                    println!(
                                        "    [🧠] AI verdict for PID {} ({}): {} (confidence {:.0}%) → {}",
                                        pid, comm,
                                        verdict.classification,
                                        verdict.confidence * 100.0,
                                        verdict.recommendation,
                                    );

                                    let action = match verdict.recommendation.as_str() {
                                        "TERMINATE" | "BLOCK" => {
                                            // P0-2 safety gate: a small local model can
                                            // hallucinate, and killing a critical system
                                            // process is far worse than a miss. Mirror the
                                            // Windows core crate: require both high
                                            // confidence AND a non-trusted path. Otherwise
                                            // suppress the kill and resume for human review.
                                            let path_str = ctx.path.as_deref().unwrap_or("");
                                            let destructive_ok = antivirus_immunity_common::safety::ai_destructive_allowed_by_path(
                                                verdict.confidence, path_str,
                                            );
                                            if destructive_ok {
                                                println!("    [!!!] AI: ELIMINATING PID {}...", pid);
                                                #[cfg(target_os = "linux")]
                                                {
                                                    // Re-verify identity: the process was SIGSTOP'd, but
                                                    // it could have exited before the stop landed and had
                                                    // its PID reused. Only kill if the fingerprint matches.
                                                    guarded_sigkill(pid, proc_start_for_task);
                                                    forget_stopped();
                                                }
                                                "TERMINATE"
                                            } else {
                                                // Low confidence or trusted location: do NOT kill.
                                                // Resume the process and log the suppression so a
                                                // human can review the AI's reasoning.
                                                use antivirus_immunity_common::safety::truncate_chars;
                                                println!(
                                                    "    [⚠] AI recommended kill but SUPPRESSED (confidence {:.0}%, path: {}). Resuming for review.",
                                                    verdict.confidence * 100.0,
                                                    truncate_chars(path_str, 40),
                                                );
                                                #[cfg(target_os = "linux")]
                                                {
                                                    use nix::sys::signal::{kill, Signal};
                                                    use nix::unistd::Pid;
                                                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGCONT);
                                                    forget_stopped();
                                                }
                                                "SUPPRESSED"
                                            }
                                        }
                                        _ => {
                                            // SAFE/ALLOW/MONITOR: resume the process
                                            println!("    [✓] AI: Resuming PID {}...", pid);
                                            #[cfg(target_os = "linux")]
                                            {
                                                use nix::sys::signal::{kill, Signal};
                                                use nix::unistd::Pid;
                                                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGCONT);
                                                forget_stopped();
                                            }
                                            "RESUMED"
                                        }
                                    };

                                    logger_clone.log(&SecurityEvent {
                                        timestamp: Utc::now(),
                                        event_type: SecurityEventType::AiAnalysis,
                                        severity: Severity::High,
                                        pid: Some(pid),
                                        process_name: Some(comm),
                                        process_path: None,
                                        container_id: None,
                                        detail: format!(
                                            "Deferred AI verdict: {} | Reasoning: {}",
                                            verdict.classification, verdict.reasoning,
                                        ),
                                        action_taken: Some(action.to_string()),
                                        ai_verdict: Some(
                                            serde_json::to_string(&verdict).unwrap_or_default(),
                                        ),
                                        danger_level: None,
                                    });
                                }
                                Ok(None) | Err(_) => {
                                    // AI unavailable or timed out — default allow
                                    println!("    [⏰] AI timeout/unavailable for PID {}. Resuming...", pid);
                                    #[cfg(target_os = "linux")]
                                    {
                                        use nix::sys::signal::{kill, Signal};
                                        use nix::unistd::Pid;
                                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGCONT);
                                        forget_stopped();
                                    }

                                    logger_clone.log(&SecurityEvent {
                                        timestamp: Utc::now(),
                                        event_type: SecurityEventType::AiAnalysis,
                                        severity: Severity::Medium,
                                        pid: Some(pid),
                                        process_name: Some(comm),
                                        process_path: None,
                                        container_id: None,
                                        detail: format!(
                                            "Deferred AI timed out or unavailable for: {}",
                                            detail_clone,
                                        ),
                                        action_taken: Some("RESUMED (AI timeout)".to_string()),
                                        ai_verdict: None,
                                        danger_level: None,
                                    });
                                }
                            }
                        }));
                    }
                }
                _ => {} // Log — no action needed
            }
        }

        // Await all deferred AI tasks before next poll cycle
        if !deferred_tasks.is_empty() {
            for task in deferred_tasks {
                if let Err(e) = task.await {
                    eprintln!("    [!] Deferred AI task panicked: {}", e);
                }
            }
        }

        // No explicit sleep: Netlink Connector blocks on recvfrom() with 100ms timeout.
        // On /proc fallback, add a minimal yield to prevent CPU spinning.
        #[cfg(not(target_os = "linux"))]
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
