import re

KNOWN_IOC_DATABASE = {
    "198.51.100.42": {
        "type": "ip",
        "reputation": "malicious",
        "risk_score": 92,
        "threat_actor": "APT28 (Fancy Bear)",
        "country": "RU",
        "asn": "AS49505",
        "category": "Brute Force / SSH Scanner",
        "tags": ["scanner", "botnet", "credential-stuffer", "tor-exit"],
        "confidence": 0.95,
        "first_seen": "2026-08-12",
        "notes": "Observed in global automated credential stuffing and dictionary attacks against SSH/RDP."
    },
    "185.220.101.5": {
        "type": "ip",
        "reputation": "suspicious",
        "risk_score": 78,
        "threat_actor": "Unknown / Script Kiddie",
        "country": "DE",
        "asn": "AS60729",
        "category": "Web Exploit Probe",
        "tags": ["sqlmap", "web-scanner", "sqli", "tor-exit"],
        "confidence": 0.88,
        "first_seen": "2026-10-01",
        "notes": "Frequent source of automated SQL injection scans and DirBuster fuzzing."
    },
    "194.26.29.112": {
        "type": "ip",
        "reputation": "critical",
        "risk_score": 98,
        "threat_actor": "FIN7 / Carbanak",
        "country": "NL",
        "asn": "AS44592",
        "category": "Command & Control (C2)",
        "tags": ["cobalt-strike", "c2-server", "active-threat", "ransomware-precursor"],
        "confidence": 0.99,
        "first_seen": "2026-09-18",
        "notes": "Verified Cobalt Strike teamserver infrastructure active in financial sector intrusions."
    },
    "45.142.166.11": {
        "type": "ip",
        "reputation": "critical",
        "risk_score": 95,
        "threat_actor": "BlackCat (ALPHV) affiliate",
        "country": "SC",
        "asn": "AS206264",
        "category": "Data Exfiltration Drop",
        "tags": ["bulletproof-host", "ftp-exfil", "darkweb-leak-host"],
        "confidence": 0.96,
        "first_seen": "2026-10-15",
        "notes": "Bulletproof FTP repository used for staging corporate data exfiltration."
    },
    "203.0.113.88": {
        "type": "ip",
        "reputation": "suspicious",
        "risk_score": 74,
        "threat_actor": "Automated Botnet (Mirai variant)",
        "country": "CN",
        "asn": "AS4134",
        "category": "RDP Credential Stuffer",
        "tags": ["rdp-scanner", "worm", "botnet"],
        "confidence": 0.82,
        "first_seen": "2026-09-02",
        "notes": "High frequency scanning on port 3389 looking for default credentials."
    }
}

INTERNAL_SUBNETS = ["10.0.", "192.168.", "172.16.", "127.0.0.1"]

def is_internal_ip(ip):
    """Checks if an IP address belongs to standard RFC 1918 private subnets."""
    if not ip or not isinstance(ip, str):
        return False
    return any(ip.startswith(prefix) for prefix in INTERNAL_SUBNETS)

def enrich(ip):
    """
    Enriches an IP indicator with threat intelligence metadata.
    Returns reputation, risk score, threat actor, tags, country, and action recommendation.
    """
    if not ip:
        return {"ip": "unknown", "reputation": "unknown", "risk_score": 0}

    # Direct match in known threat database
    if ip in KNOWN_IOC_DATABASE:
        data = KNOWN_IOC_DATABASE[ip].copy()
        data["ip"] = ip
        return data

    # Internal IP heuristics
    if is_internal_ip(ip):
        return {
            "ip": ip,
            "type": "ip",
            "reputation": "internal",
            "risk_score": 10,
            "threat_actor": "Corporate LAN Asset",
            "country": "LOCAL",
            "asn": "AS-PRIVATE-ENTERPRISE",
            "category": "Internal Endpoint",
            "tags": ["private-subnet", "corporate-asset"],
            "confidence": 0.90,
            "first_seen": "2026-01-01",
            "notes": "Verified internal private IP address within protected perimeter."
        }

    # External IP default heuristics (unknown external)
    return {
        "ip": ip,
        "type": "ip",
        "reputation": "unverified",
        "risk_score": 35,
        "threat_actor": "Unattributed External Host",
        "country": "GLOBAL",
        "asn": "AS-INTERNET-TRANSIT",
        "category": "External Traffic",
        "tags": ["external", "unindexed-ioc"],
        "confidence": 0.50,
        "first_seen": "Just observed",
        "notes": "Indicator not present in current threat intelligence feeds. Monitor for baseline anomalies."
    }

def query_threat_feed():
    """Returns a list of all active known threat indicators."""
    return [{"indicator": k, **v} for k, v in KNOWN_IOC_DATABASE.items()]
