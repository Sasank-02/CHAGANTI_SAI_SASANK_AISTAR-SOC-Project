import re

RULES = [
    {
        "id": "RULE-SEC-001",
        "name": "SSH & RDP Authentication Brute Force",
        "mitre_id": "T1110",
        "severity": "HIGH",
        "eval": lambda log: log.get("failed_attempts", 0) >= 5 or "failed password" in str(log.get("raw_payload", "")).lower()
    },
    {
        "id": "RULE-SEC-002",
        "name": "SQL Injection Pattern in Web URI/Payload",
        "mitre_id": "T1190",
        "severity": "CRITICAL",
        "eval": lambda log: bool(re.search(r"(union\s+select|1\s*=\s*1|--|information_schema|waitfor\s+delay)", str(log.get("uri_path", "")), re.IGNORECASE))
    },
    {
        "id": "RULE-SEC-003",
        "name": "Cobalt Strike / C2 Beaconing Activity",
        "mitre_id": "T1071",
        "severity": "CRITICAL",
        "eval": lambda log: any(k in str(log.get("raw_payload", "")).lower() for k in ["cobaltstrike", "beacon", "c2-server", "heartbeat.php"])
    },
    {
        "id": "RULE-SEC-004",
        "name": "OS Credential Extraction (LSASS / Mimikatz)",
        "mitre_id": "T1003",
        "severity": "CRITICAL",
        "eval": lambda log: any(k in str(log.get("process_name", "")).lower() for k in ["mimikatz"]) or any(k in str(log.get("command", "")).lower() for k in ["sekurlsa", "privilege::debug", "logonpasswords"])
    },
    {
        "id": "RULE-SEC-005",
        "name": "Abnormal Outbound Data Transfer (Exfiltration)",
        "mitre_id": "T1041",
        "severity": "CRITICAL",
        "eval": lambda log: log.get("bytes_out", 0) > 10000000 or "exfiltration" in str(log.get("raw_payload", "")).lower()
    },
    {
        "id": "RULE-SEC-006",
        "name": "Network Discovery / Port Sweep Reconnaissance",
        "mitre_id": "T1046",
        "severity": "MEDIUM",
        "eval": lambda log: "nmap" in str(log.get("process_name", "")).lower() or "scan" in str(log.get("raw_payload", "")).lower()
    },
    {
        "id": "RULE-SEC-007",
        "name": "Obfuscated / Base64 Encoded PowerShell Execution",
        "mitre_id": "T1059",
        "severity": "HIGH",
        "eval": lambda log: "powershell" in str(log.get("process_name", "")).lower() and ("-enc" in str(log.get("command", "")).lower() or "-encodedcommand" in str(log.get("command", "")).lower())
    }
]

def brute_force(log):
    """Backwards compatibility helper for existing references."""
    return log.get("failed_attempts", 0) > 5

def evaluate_rules(log):
    """
    Evaluates a normalized log against all security correlation rules.
    Returns a list of matched rule descriptors.
    """
    matched = []
    for rule in RULES:
        try:
            if rule["eval"](log):
                matched.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "mitre_id": rule["mitre_id"],
                    "severity": rule["severity"]
                })
        except Exception:
            continue
    return matched
