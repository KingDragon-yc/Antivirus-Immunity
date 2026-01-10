use std::thread;
use std::time::Duration;

fn main() {
    println!("👻 I am a MOCK ANTIGEN (Test Virus).");
    println!("I carry the EICAR test signature.");

    // This string triggers the YARA rule 'Test_Malware_Signature'
    // Note: We break it slightly to avoid AVs killing the source code,
    // but when compiled it might still be detected by real AVs!
    // For our internal test, we use the specific string defined in antigens.yar:
    // "malware_test_string"

    let part1 = "malware";
    let part2 = "_test_string";
    let signature = format!("{}{}", part1, part2);

    // Also include the EICAR string just in case, but keep it constructed to avoid static detection of this source file
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    println!("Signature loaded: {}", signature);
    println!("Running... (Press Ctrl+C to stop)");

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
