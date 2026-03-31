mod effector;
mod immune;
mod logger;
mod receptor;

use chrono::Utc;
use clap::Parser;
use effector::cytotoxic_t_cell::{CytotoxicTCell, ResponseAction};
use effector::quarantine::Quarantine;
use immune::ai_cortex::{AiCortex, AiCortexConfig, ProcessContext};
use immune::{Assessment, DangerTheoryEngine, ImmuneSystem};
use logger::{EventType, Logger, SecurityEvent};
use receptor::toll_like_receptor::TollLikeReceptor;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Parser, Debug)]
#[command(
    name = "antivirus-immunity-core",
    author = "KingDragon-yc",
    version = "0.3.0",
    about = "An antivirus engine inspired by the biological immune system, with local AI cortex",
    long_about = "Antivirus-Immunity combines AIS (Artificial Immune System) theory with \
                  local AI inference to provide behavior-based endpoint security."
)]
struct Args {
    /// Mode of operation: 'monitor', 'active', 'learn', or 'quarantine-list'
    #[arg(short, long, default_value = "monitor")]
    mode: String,

    /// Response policy: 'log', 'kill', or 'quarantine' (Only relevant for monitor/active)
    #[arg(short, long)]
    policy: Option<String>,

    /// Enable AI Cortex for deep analysis of ambiguous processes
    #[arg(long, default_value = "true")]
    ai: bool,

    /// AI model name (Ollama model, e.g., "qwen2.5:3b", "llama3.2:1b")
    #[arg(long, default_value = "qwen2.5:3b")]
    ai_model: String,

    /// Ollama endpoint URL
    #[arg(long, default_value = "http://localhost:11434")]
    ai_endpoint: String,

    /// Monitoring poll interval in milliseconds
    #[arg(long, default_value = "500")]
    interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize Logger
    let logger = Logger::new().unwrap_or_else(|e| {
        eprintln!(
            "[!] Failed to initialize logger: {}. Continuing without file logging.",
            e
        );
        Logger::new().unwrap() // retry
    });

    // Determine Policy
    let active_defense = args.mode == "active"
        || args.policy.as_deref() == Some("kill")
        || args.policy.as_deref() == Some("quarantine");
    let quarantine_mode = args.policy.as_deref() == Some("quarantine");
    let learning_mode = args.mode == "learn";
    let quarantine_list_mode = args.mode == "quarantine-list";

    // Initialize Immune System Components
    let mut immune_system = ImmuneSystem::new();
    let mut receptor = TollLikeReceptor::new();
    let mut danger_engine = DangerTheoryEngine::new();
    let mut quarantine = Quarantine::new().ok();

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          Antivirus-Immunity Core v0.3.0                     ║");
    println!("║          Biological Architecture + AI Cortex                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ==================== QUARANTINE LIST MODE ====================
    if quarantine_list_mode {
        println!("[*] Listing quarantined files...\n");
        if let Some(ref q) = quarantine {
            let active = q.list_active();
            if active.is_empty() {
                println!("    (No files currently in quarantine)");
            } else {
                println!(
                    "{:<38} {:<30} {:<20} {}",
                    "ID", "ORIGINAL PATH", "PROCESS", "DATE"
                );
                println!("{:-<38} {:-<30} {:-<20} {:-<20}", "", "", "", "");
                for entry in active {
                    println!(
                        "{:<38} {:<30} {:<20} {}",
                        entry.id,
                        &entry.original_path[..entry.original_path.len().min(28)],
                        entry.process_name,
                        entry.quarantined_at.format("%Y-%m-%d %H:%M:%S"),
                    );
                }
            }
        } else {
            println!("    [!] Quarantine system not initialized.");
        }
        return Ok(());
    }

    // ==================== AI CORTEX INITIALIZATION ====================
    let mut ai_cortex = AiCortex::new(AiCortexConfig {
        endpoint: args.ai_endpoint.clone(),
        model: args.ai_model.clone(),
        timeout_secs: 30,
        enabled: args.ai,
    });

    if args.ai {
        println!("[*] AI Cortex: Checking Ollama connectivity...");
        ai_cortex.health_check().await;
    } else {
        println!("[*] AI Cortex: Disabled by user. Using rule-based evaluation only.");
    }

    println!("Mode: {}", args.mode);

    // ==================== LEARNING MODE ====================
    if learning_mode {
        println!("[*] STARTING LEARNING MODE...");
        println!("[*] Toll-Like Receptor: Taking snapshot of all running processes...");
        println!("[!] WARNING: Ensure your system is currently clean before proceeding!");

        match receptor.snapshot() {
            Ok(processes) => {
                println!("[+] Found {} processes.", processes.len());
                immune_system.learn_self(&processes);
                println!("[+] Learning complete. Memory B Cells updated.");
                logger.log(&SecurityEvent {
                    timestamp: Utc::now(),
                    event_type: EventType::LearningComplete,
                    pid: None,
                    process_name: None,
                    process_path: None,
                    assessment: None,
                    detail: format!("Learned {} processes", processes.len()),
                    action_taken: None,
                    ai_verdict: None,
                    danger_level: None,
                });
            }
            Err(e) => eprintln!("[-] Error during learning snapshot: {}", e),
        }
        return Ok(());
    }

    // ==================== MONITORING MODE ====================
    let policy_str = if quarantine_mode {
        "ACTIVE IMMUNITY + QUARANTINE (File isolation + Cytotoxic T Cells)"
    } else if active_defense {
        "ACTIVE IMMUNITY (Cytotoxic T Cells ENGAGED)"
    } else {
        "PASSIVE IMMUNITY (Monitoring Only)"
    };
    println!("Policy: {}", policy_str);
    println!("Poll Interval: {}ms", args.interval);
    println!();
    println!("[*] Initializing baseline scan...");

    // Initial Scan
    if let Err(e) = receptor.snapshot() {
        eprintln!("[-] Failed to take initial snapshot: {}", e);
        return Ok(());
    }

    println!("[+] Baseline established. Entering Real-time Monitoring Mode...");
    println!("[+] {}", receptor.cache_stats());
    println!("[!] Press Ctrl+C to stop.");
    println!();

    // Log system start
    logger.log(&SecurityEvent {
        timestamp: Utc::now(),
        event_type: EventType::SystemStart,
        pid: None,
        process_name: None,
        process_path: None,
        assessment: None,
        detail: format!(
            "System started in '{}' mode with '{}' policy",
            args.mode, policy_str
        ),
        action_taken: None,
        ai_verdict: None,
        danger_level: None,
    });

    println!("{:<6} {:<25} {:<15} {:<}", "PID", "NAME", "STATUS", "INFO");
    println!("{:-<6} {:-<25} {:-<15} {:-<50}", "", "", "", "");

    // ==================== MAIN EVENT LOOP ====================
    let mut loop_count: u64 = 0;

    loop {
        // Periodically assess danger level
        let danger_signals = danger_engine.assess();
        for signal in &danger_signals {
            let level_str = format!("{:?}", signal.level);
            println!("  ⚠ DANGER SIGNAL: [{}] {}", level_str, signal.description);
            logger.log_danger(&level_str, &signal.description);
        }

        let current_danger = danger_engine.current_level().clone();

        match receptor.scan_diff() {
            Ok((new_procs, _dead_pids)) => {
                for p in new_procs {
                    // Record process creation for flood detection
                    danger_engine.record_process_creation();

                    let assessment = immune_system.evaluate(&p, &current_danger);

                    let (status_str, is_critical, is_suspicious, needs_ai) = match &assessment {
                        Assessment::Safe => ("SAFE", false, false, false),
                        Assessment::Critical(_) => ("CRITICAL", true, false, false),
                        Assessment::Suspicious(_) => ("SUSPICIOUS", false, true, false),
                        Assessment::Unknown => ("UNKNOWN", false, false, false),
                        Assessment::NeedsAiReview(_) => ("AI_REVIEW", false, false, true),
                    };

                    let info = match &assessment {
                        Assessment::Critical(ref reason) => reason.clone(),
                        Assessment::Suspicious(ref reason) => reason.clone(),
                        Assessment::NeedsAiReview(ref reason) => reason.clone(),
                        _ => p.hash.clone().unwrap_or_else(|| "-".to_string()),
                    };

                    println!(
                        "{:<6} {:<25} {:<15} {:.60}",
                        p.pid, p.name, status_str, info
                    );

                    // Log the detection
                    logger.log_process_detected(
                        p.pid,
                        &p.name,
                        p.path.as_deref(),
                        status_str,
                        &info,
                    );

                    // ===== AI CORTEX DEEP ANALYSIS =====
                    if needs_ai && ai_cortex.is_available() {
                        let ctx = ProcessContext {
                            pid: p.pid,
                            name: p.name.clone(),
                            path: p.path.clone(),
                            hash: p.hash.clone(),
                            path_verdict: immune_system
                                .get_path_verdict_string(&p.name, p.path.as_deref()),
                            yara_matches: p
                                .path
                                .as_deref()
                                .map(|path| immune_system.get_yara_matches(path))
                                .unwrap_or_default(),
                            danger_level: format!("{:?}", current_danger),
                            is_known_hash: p
                                .hash
                                .as_deref()
                                .map(|h| immune_system.is_hash_trusted(h))
                                .unwrap_or(false),
                        };

                        print!("    🧠 AI Cortex analyzing... ");
                        match ai_cortex.evaluate(&ctx).await {
                            Some(verdict) => {
                                println!(
                                    "[{}] (confidence: {:.0}%)",
                                    verdict.classification,
                                    verdict.confidence * 100.0
                                );
                                println!(
                                    "       Reasoning: {}",
                                    &verdict.reasoning[..verdict.reasoning.len().min(100)]
                                );
                                println!("       Recommendation: {}", verdict.recommendation);

                                logger.log(&SecurityEvent {
                                    timestamp: Utc::now(),
                                    event_type: EventType::AiAnalysis,
                                    pid: Some(p.pid),
                                    process_name: Some(p.name.clone()),
                                    process_path: p.path.clone(),
                                    assessment: Some(verdict.classification.clone()),
                                    detail: verdict.reasoning.clone(),
                                    action_taken: Some(verdict.recommendation.clone()),
                                    ai_verdict: Some(
                                        serde_json::to_string(&verdict).unwrap_or_default(),
                                    ),
                                    danger_level: Some(format!("{:?}", current_danger)),
                                });

                                // Act on AI recommendation if in active mode
                                if active_defense && verdict.recommendation == "TERMINATE" {
                                    print!("    [!!!] AI RECOMMENDS TERMINATION. ACTIVATING CYTOTOXIC T CELLS... ");
                                    match CytotoxicTCell::induce_apoptosis(p.pid) {
                                        Ok(_) => {
                                            println!("TARGET ELIMINATED.");
                                            logger.log_action(
                                                p.pid,
                                                &p.name,
                                                "TERMINATE",
                                                "AI-directed elimination",
                                            );
                                        }
                                        Err(e) => println!("FAILED: {}", e),
                                    }
                                } else if active_defense && verdict.recommendation == "QUARANTINE" {
                                    if let Some(ref mut q) = quarantine {
                                        if let Some(ref path) = p.path {
                                            print!(
                                                "    [!] AI RECOMMENDS QUARANTINE. ISOLATING... "
                                            );
                                            match q.isolate(
                                                path,
                                                p.hash.clone(),
                                                &verdict.reasoning,
                                                &p.name,
                                                p.pid,
                                            ) {
                                                Ok(entry) => {
                                                    println!("ISOLATED (ID: {})", &entry.id[..8]);
                                                    logger.log_action(
                                                        p.pid,
                                                        &p.name,
                                                        "QUARANTINE",
                                                        &format!("Isolated: {}", entry.id),
                                                    );
                                                }
                                                Err(e) => println!("FAILED: {}", e),
                                            }
                                        }
                                    }
                                }
                            }
                            None => {
                                println!("UNAVAILABLE (falling back to rule-based)");
                            }
                        }
                        continue; // Skip normal response logic for AI-reviewed processes
                    }

                    // ===== STANDARD RESPONSE LOGIC =====
                    let action = CytotoxicTCell::determine_response(
                        is_critical,
                        is_suspicious,
                        active_defense,
                    );

                    match action {
                        ResponseAction::QuarantineAndTerminate => {
                            // Quarantine first, then kill
                            if let (Some(ref mut q), Some(ref path)) = (&mut quarantine, &p.path) {
                                print!("    [!!!] QUARANTINING & ELIMINATING... ");
                                match q.isolate(path, p.hash.clone(), &info, &p.name, p.pid) {
                                    Ok(entry) => {
                                        print!("QUARANTINED ({}). ", &entry.id[..8]);
                                        logger.log_action(p.pid, &p.name, "QUARANTINE", &entry.id);
                                    }
                                    Err(e) => print!("Quarantine failed: {}. ", e),
                                }
                            } else {
                                print!("    [!!!] ELIMINATING TARGET... ");
                            }
                            match CytotoxicTCell::induce_apoptosis(p.pid) {
                                Ok(_) => {
                                    println!("TARGET ELIMINATED.");
                                    logger.log_action(p.pid, &p.name, "TERMINATE", &info);
                                }
                                Err(e) => println!("FAILED TO ELIMINATE: {}", e),
                            }
                        }
                        ResponseAction::Terminate => {
                            print!("    [!] ACTIVATING CYTOTOXIC T CELLS... ");
                            match CytotoxicTCell::induce_apoptosis(p.pid) {
                                Ok(_) => {
                                    println!("TARGET ELIMINATED.");
                                    logger.log_action(p.pid, &p.name, "TERMINATE", &info);
                                }
                                Err(e) => println!("FAILED TO ELIMINATE: {}", e),
                            }
                        }
                        ResponseAction::Log => {
                            if is_critical {
                                println!("    [!!!] CRITICAL ANTIGEN DETECTED. Logging only.");
                            } else if is_suspicious {
                                println!("    [!] NON-SELF DETECTED. Logging only.");
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("[!] Error in monitoring loop: {}", e),
        }

        // Periodic status (every 60 loops)
        loop_count += 1;
        if loop_count % 60 == 0 {
            println!(
                "\n--- Status: {} | {} ---\n",
                danger_engine.status_summary(),
                receptor.cache_stats(),
            );
        }

        sleep(Duration::from_millis(args.interval)).await;
    }
}
