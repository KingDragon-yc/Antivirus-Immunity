rule Test_Malware_Signature {
    meta:
        description = "Detects a dummy malware signature for testing"
        author = "Antivirus-Immunity"
        severity = "CRITICAL"
    strings:
        $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $s2 = "malware_test_string" nocase
    condition:
        any of them
}

rule Suspicious_Script_Exec {
    meta:
        description = "Detects suspicious script execution patterns"
        severity = "HIGH"
    strings:
        $cmd = "powershell.exe -enc" nocase
        $url = "http://"
    condition:
        $cmd and $url
}
