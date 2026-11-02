MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to attempt credential guessing or password spraying.",
        "mitigation": "Account lockout policies, multi-factor authentication (MFA), and rate-limiting authentication endpoints.",
        "severity": "HIGH"
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software (e.g., SQL injection, SSRF, remote code execution).",
        "mitigation": "Web Application Firewall (WAF), parameterized queries, strict input validation, regular patch management.",
        "severity": "CRITICAL"
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, CMD) to execute commands.",
        "mitigation": "PowerShell Constrained Language Mode, script block logging (EID 4104), AppLocker/WDAC application control.",
        "severity": "HIGH"
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may dump memory from the Local Security Authority Subsystem Service (LSASS) to harvest plaintext passwords or NTLM hashes.",
        "mitigation": "Enable LSA Protection (RunAsPPL), Windows Defender Credential Guard, monitor Handle access to lsass.exe.",
        "severity": "CRITICAL"
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol: Web Protocols (C2)",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS/DNS) to conceal C2 traffic within normal network traffic.",
        "mitigation": "Network traffic analysis, deep packet inspection (DPI), outbound SSL decryption, C2 domain/IP reputation blocking.",
        "severity": "CRITICAL"
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel / Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries may steal data by exfiltrating it over an established C2 channel, FTP, or cloud storage.",
        "mitigation": "Data Loss Prevention (DLP) agents, egress traffic filtering, network flow anomaly detection on outbound byte volume.",
        "severity": "CRITICAL"
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of other systems and services on the network through port scanning.",
        "mitigation": "Internal microsegmentation, Network Intrusion Detection Systems (NIDS) alerting on SYN/connect port sweeps.",
        "severity": "MEDIUM"
    },
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries may exploit software vulnerabilities or misconfigurations to elevate privileges.",
        "mitigation": "Principle of least privilege, kernel patching, EDR behavioral monitoring.",
        "severity": "HIGH"
    }
}

def map_attack(log):
    """
    Intelligently maps an event or alert log to the MITRE ATT&CK framework.
    Returns a dictionary with technique ID, name, tactic, description, and mitigation.
    """
    payload = str(log.get("raw_payload", "")).lower()
    proc = str(log.get("process_name", "")).lower()
    cmd = str(log.get("command", "")).lower()
    uri = str(log.get("uri_path", "")).lower()
    failed = log.get("failed_attempts", 0)
    bytes_out = log.get("bytes_out", 0)

    # 1. LSASS dumping / Mimikatz
    if "mimikatz" in proc or "lsass" in payload or "sekurlsa" in cmd or "privilege::debug" in cmd:
        return MITRE_TECHNIQUES["T1003"]

    # 2. SQL Injection / Web exploitation
    if any(k in uri or k in payload for k in ["union select", "1=1", "sqlmap", "information_schema", "drop table", "select password"]):
        return MITRE_TECHNIQUES["T1190"]

    # 3. Data Exfiltration
    if bytes_out > 10000000 or "exfiltration" in payload or "ftp://" in cmd:
        return MITRE_TECHNIQUES["T1041"]

    # 4. C2 Beaconing
    if any(k in payload for k in ["cobaltstrike", "beacon", "c2-server", "heartbeat"]) or "powershell -enc" in cmd:
        return MITRE_TECHNIQUES["T1071"]

    # 5. Brute Force
    if failed >= 5 or "credential stuffing" in payload or "failed password" in payload:
        return MITRE_TECHNIQUES["T1110"]

    # 6. Port Scan / Discovery
    if "nmap" in proc or "scan" in payload or "port sweep" in payload:
        return MITRE_TECHNIQUES["T1046"]

    # 7. Scripting execution
    if proc in ["powershell.exe", "cmd.exe", "bash"] and cmd != "":
        return MITRE_TECHNIQUES["T1059"]

    # Default fallback
    return {
        "id": "T0000",
        "name": "Benign / Unclassified Activity",
        "tactic": "Operational Normal",
        "tactic_id": "TA0000",
        "description": "Standard administrative or authenticated user activity.",
        "mitigation": "Maintain standard baseline monitoring.",
        "severity": "INFO"
    }

def get_technique_details(technique_id):
    """Retrieves full metadata for a given MITRE technique ID."""
    return MITRE_TECHNIQUES.get(technique_id.upper(), None)

def get_all_matrix():
    """Returns the registered MITRE ATT&CK techniques."""
    return list(MITRE_TECHNIQUES.values())
