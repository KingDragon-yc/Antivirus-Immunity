use std::env;
use std::fs::File;
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: antigen_extractor <file_path> [min_length]");
        return Ok(());
    }

    let file_path = &args[1];
    let min_len = args
        .get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4); // Lowered default to 4 to catch 'calc'

    println!("🔬 Analyzing Antigen: {}", file_path);
    println!("----------------------------------------");

    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Suspicious keywords to highlight
    let suspicious_keywords = [
        "Software\\",
        "CurrentVersion",
        "Run",
        "RunOnce", // Registry
        ".exe",
        "calc",
        "cmd",
        "powershell", // Execution
        "http",
        "https",
        "ftp", // Network
        "RegOpen",
        "RegSet",
        "CreateProcess",
        "ShellExecute", // APIs
    ];

    println!("[*] Extracting ASCII strings (len >= {})...", min_len);
    println!("[*] 🔍 indicates POTENTIALLY INTERESTING strings related to behavior.\n");

    let mut current_string = String::new();

    for byte in &buffer {
        let c = *byte as char;
        // Check for printable ASCII
        if c.is_ascii_graphic() || c == ' ' {
            current_string.push(c);
        } else {
            if current_string.len() >= min_len {
                print_string(&current_string, &suspicious_keywords);
            }
            current_string.clear();
        }
    }
    // Check last string
    if current_string.len() >= min_len {
        print_string(&current_string, &suspicious_keywords);
    }

    println!("----------------------------------------");
    println!("💡 TIP: Look for the lines marked with 🔍.");

    Ok(())
}

fn print_string(s: &str, keywords: &[&str]) {
    let mut is_suspicious = false;
    for k in keywords {
        if s.contains(k) {
            // Case-sensitive search for simplicity, can be made case-insensitive
            is_suspicious = true;
            break;
        }
    }

    if is_suspicious {
        println!("🔍 Found: \"{}\"", s);
    } else {
        // Optional: Uncomment to see ALL strings, but for analysis we focus on suspicious ones
        // or just print them normally. Let's print normally but indented.
        println!("    Found: \"{}\"", s);
    }
}
