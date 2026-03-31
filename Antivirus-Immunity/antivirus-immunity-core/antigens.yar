// ============================================================
// Antivirus-Immunity — Antigen Database (YARA Rules)
// Version: 0.3.0
// 
// Organized by threat category. Each rule corresponds to a
// known "antigen" pattern that the immune system can recognize.
// ============================================================

// ==================== TEST SIGNATURES ====================

rule Test_Malware_Signature {
    meta:
        description = "Detects EICAR test file and dummy malware signatures"
        author = "Antivirus-Immunity"
        severity = "CRITICAL"
        category = "test"
    strings:
        $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $s2 = "malware_test_string" nocase
    condition:
        any of them
}

// ==================== RANSOMWARE INDICATORS ====================

rule Ransomware_Note_Indicators {
    meta:
        description = "Detects common ransomware note patterns"
        severity = "CRITICAL"
        category = "ransomware"
    strings:
        $note1 = "Your files have been encrypted" nocase
        $note2 = "pay the ransom" nocase
        $note3 = "bitcoin wallet" nocase
        $note4 = "decrypt your files" nocase
        $note5 = "DECRYPT_INSTRUCTION" nocase
        $note6 = "README_TO_RESTORE" nocase
    condition:
        2 of them
}

rule Ransomware_Extension_Changer {
    meta:
        description = "Detects bulk file extension modification patterns"
        severity = "HIGH"
        category = "ransomware"
    strings:
        $api1 = "MoveFileEx" nocase
        $api2 = "CryptEncrypt" nocase
        $api3 = "CryptGenKey" nocase
        $api4 = "FindFirstFile" nocase
        $api5 = "FindNextFile" nocase
    condition:
        ($api2 or $api3) and ($api4 and $api5)
}

// ==================== CREDENTIAL THEFT ====================

rule Credential_Harvester {
    meta:
        description = "Detects credential harvesting tool patterns"
        severity = "CRITICAL"
        category = "credential_theft"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa" nocase
        $s3 = "lsadump" nocase
        $s4 = "wdigest" nocase
        $s5 = "kerberos::list" nocase
    condition:
        2 of them
}

rule LSASS_Memory_Dump {
    meta:
        description = "Detects LSASS memory dumping tools"
        severity = "CRITICAL"
        category = "credential_theft"
    strings:
        $s1 = "MiniDumpWriteDump"
        $s2 = "lsass.exe" nocase
        $s3 = "procdump" nocase
        $s4 = "comsvcs.dll" nocase
    condition:
        $s1 and ($s2 or $s3 or $s4)
}

// ==================== PERSISTENCE MECHANISMS ====================

rule Registry_Persistence {
    meta:
        description = "Detects registry-based persistence techniques"
        severity = "HIGH"
        category = "persistence"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $api1 = "RegSetValueEx"
        $api2 = "RegCreateKeyEx"
    condition:
        ($run or $runonce or $winlogon) and ($api1 or $api2)
}

rule Scheduled_Task_Persistence {
    meta:
        description = "Detects scheduled task creation for persistence"
        severity = "MEDIUM"
        category = "persistence"
    strings:
        $s1 = "schtasks" nocase
        $s2 = "/create" nocase
        $s3 = "/sc" nocase
        $s4 = "ITaskService" nocase
    condition:
        ($s1 and $s2 and $s3) or $s4
}

// ==================== SUSPICIOUS SCRIPT EXECUTION ====================

rule Suspicious_Script_Exec {
    meta:
        description = "Detects suspicious script execution patterns"
        severity = "HIGH"
        category = "execution"
    strings:
        $cmd1 = "powershell.exe -enc" nocase
        $cmd2 = "powershell.exe -e " nocase
        $cmd3 = "powershell -nop -w hidden" nocase
        $cmd4 = "cmd.exe /c" nocase
        $url = "http://"
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $download3 = "Invoke-WebRequest" nocase
        $download4 = "wget" nocase
        $download5 = "curl" nocase
    condition:
        ($cmd1 or $cmd2 or $cmd3) and ($url or any of ($download*))
}

rule PowerShell_Obfuscation {
    meta:
        description = "Detects obfuscated PowerShell commands"
        severity = "HIGH"
        category = "evasion"
    strings:
        $s1 = "[Convert]::FromBase64String" nocase
        $s2 = "IEX(" nocase
        $s3 = "Invoke-Expression" nocase
        $s4 = "[System.Text.Encoding]" nocase
        $s5 = "-join" nocase
        $s6 = "[char]" nocase
    condition:
        ($s1 or ($s2 or $s3)) and ($s4 or ($s5 and $s6))
}

// ==================== PROCESS INJECTION ====================

rule Process_Injection {
    meta:
        description = "Detects process injection techniques"
        severity = "CRITICAL"
        category = "injection"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtCreateThreadEx"
        $api5 = "QueueUserAPC"
        $api6 = "SetThreadContext"
    condition:
        $api1 and $api2 and ($api3 or $api4 or $api5 or $api6)
}

// ==================== REVERSE SHELL / C2 ====================

rule Reverse_Shell_Indicators {
    meta:
        description = "Detects reverse shell patterns"
        severity = "CRITICAL"
        category = "c2"
    strings:
        $s1 = "WSAStartup"
        $s2 = "cmd.exe" nocase
        $s3 = "CreateProcess"
        $s4 = "/bin/sh" nocase
        $s5 = "socket" nocase
        $s6 = "connect" nocase
        $pipe1 = "CreatePipe"
        $pipe2 = "PeekNamedPipe"
    condition:
        $s1 and ($s2 or $s4) and $s3 and ($s5 or $s6 or $pipe1 or $pipe2)
}

// ==================== CRYPTOMINER ====================

rule Cryptominer_Indicators {
    meta:
        description = "Detects cryptocurrency mining indicators"
        severity = "HIGH"
        category = "cryptominer"
    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = "mining.pool" nocase
        $algo1 = "randomx" nocase
        $algo2 = "cryptonight" nocase
        $algo3 = "ethash" nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ // Bitcoin address pattern
    condition:
        any of ($pool*) or (any of ($algo*) and $wallet)
}

