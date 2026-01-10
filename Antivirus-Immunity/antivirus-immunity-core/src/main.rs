mod receptor;
mod immune;
mod effector;

use clap::Parser;
use receptor::toll_like_receptor::TollLikeReceptor;
use immune::{ImmuneSystem, Assessment};
use effector::cytotoxic_t_cell::CytotoxicTCell;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mode of operation: 'monitor', 'active', or 'learn'
    #[arg(short, long, default_value = "monitor")]
    mode: String,

    /// Response policy: 'log' or 'kill' (Only relevant for monitor/active)
    #[arg(short, long)]
    policy: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    // Determine Policy
    let active_defense = args.mode == "active" || args.policy.as_deref() == Some("kill");
    let learning_mode = args.mode == "learn";
    
    // Initialize Immune System Components
    let mut immune_system = ImmuneSystem::new();
    let mut receptor = TollLikeReceptor::new(); // Was ProcessSensor

    println!("Antivirus-Immunity Core v0.2.0 (Biological Refactoring)");
    println!("-------------------------------------------------------");
    println!("Mode: {}", args.mode);
    
    if learning_mode {
        println!("[*] STARTING LEARNING MODE...");
        println!("[*] Toll-Like Receptor: Taking snapshot of all running processes...");
        println!("[!] WARNING: Ensure your system is currently clean before proceeding!");
        
        match receptor.snapshot() {
            Ok(processes) => {
                println!("[+] Found {} processes.", processes.len());
                immune_system.learn_self(&processes);
                println!("[+] Learning complete. Memory B Cells updated.");
            }
            Err(e) => eprintln!("[-] Error during learning snapshot: {}", e),
        }
        return Ok(());
    }

    println!("Policy: {}", if active_defense { "ACTIVE IMMUNITY (Cytotoxic T Cells ENGAGED)" } else { "PASSIVE IMMUNITY (Monitoring Only)" });
    println!("[*] Initializing baseline scan...");
    
    // Initial Scan to populate known_pids
    if let Err(e) = receptor.snapshot() {
            eprintln!("[-] Failed to take initial snapshot: {}", e);
            return Ok(());
    }
    println!("[+] Baseline established. Entering Real-time Monitoring Mode...");
    println!("[!] Press Ctrl+C to stop.");
    println!("\n{:<6} {:<20} {:<15} {:<}", "PID", "NAME", "STATUS", "INFO");
    println!("{:-<6} {:-<20} {:-<15} {:-<}", "", "", "", "");

    // Event Loop
    loop {
        match receptor.scan_diff() {
            Ok((new_procs, dead_pids)) => {
                // Handle Dead (Optional logging)
                for _pid in dead_pids {
                    // println!("[-] Process Terminated: {}", pid);
                }

                // Handle New
                for p in new_procs {
                    let assessment = immune_system.evaluate(&p);
                    
                    let status_str = match assessment {
                        Assessment::Safe => "SAFE",
                        Assessment::Critical(_) => "CRITICAL",
                        Assessment::Suspicious(_) => "SUSPICIOUS",
                        Assessment::Unknown => "UNKNOWN",
                    };

                    let info = match assessment {
                        Assessment::Critical(ref reason) => reason.clone(),
                        Assessment::Suspicious(ref reason) => reason.clone(),
                        _ => p.hash.clone().unwrap_or_else(|| "-".to_string()),
                    };

                    println!("{:<6} {:<20} {:<15} {:.64}", p.pid, p.name, status_str, info);

                    // ACTIVE DEFENSE LOGIC
                    match assessment {
                        Assessment::Critical(_) => {
                            // Critical = Confirmed Antigen (Malware)
                            if active_defense {
                                print!("    [!!!] CRITICAL ANTIGEN DETECTED. ACTIVATING CYTOTOXIC T CELLS... ");
                                match CytotoxicTCell::induce_apoptosis(p.pid) {
                                    Ok(_) => println!("TARGET ELIMINATED."),
                                    Err(e) => println!("FAILED TO ELIMINATE: {}", e),
                                }
                            } else {
                                println!("    [!!!] CRITICAL ANTIGEN DETECTED. Logging only.");
                            }
                        },
                        Assessment::Suspicious(_) => {
                            // Suspicious = Non-Self (Anomaly)
                            if active_defense {
                                print!("    [!] NON-SELF DETECTED. ACTIVATING CYTOTOXIC T CELLS... ");
                                match CytotoxicTCell::induce_apoptosis(p.pid) {
                                    Ok(_) => println!("TARGET ELIMINATED."),
                                    Err(e) => println!("FAILED TO ELIMINATE: {}", e),
                                }
                            } else {
                                println!("    [!] NON-SELF DETECTED. Logging only.");
                            }
                        },
                        _ => {}
                    }
                }
            }
            Err(e) => eprintln!("[!] Error in monitoring loop: {}", e),
        }

        // Sleep to prevent high CPU usage (Polling Interval)
        sleep(Duration::from_millis(1000)).await;
    }
}
