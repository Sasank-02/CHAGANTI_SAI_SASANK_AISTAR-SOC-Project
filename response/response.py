import datetime
import uuid

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), name="IST")

# In-memory stores for active quarantines and SOAR execution history
QUARANTINE_REGISTRY = {}
PLAYBOOK_AUDIT_LOG = []

def block_ip(ip, reason="Automated Agentic Incident Containment", duration_seconds=86400):
    """Executes firewall containment by registering the IP in the quarantine registry."""
    if not ip or ip == "127.0.0.1":
        return {"status": "skipped", "message": "Loopback or empty IP cannot be quarantined"}

    action_id = f"SOAR-ACT-{uuid.uuid4().hex[:6].upper()}"
    expiry = (datetime.datetime.now(IST) + datetime.timedelta(seconds=duration_seconds)).isoformat()
    record = {
        "action_id": action_id,
        "type": "IP_BLOCK",
        "target": ip,
        "reason": reason,
        "timestamp": datetime.datetime.now(IST).isoformat(),
        "expires_at": expiry,
        "status": "ACTIVE"
    }
    QUARANTINE_REGISTRY[ip] = record
    PLAYBOOK_AUDIT_LOG.insert(0, record)
    print(f"[SOAR FIREWALL] Blocked IP: {ip} | Reason: {reason}")
    return record

def isolate_host(hostname, reason="Malware / Ransomware Containment"):
    """Simulates endpoint network isolation through EDR API."""
    action_id = f"SOAR-ACT-{uuid.uuid4().hex[:6].upper()}"
    record = {
        "action_id": action_id,
        "type": "HOST_ISOLATION",
        "target": hostname,
        "reason": reason,
        "timestamp": datetime.datetime.now(IST).isoformat(),
        "status": "ISOLATED"
    }
    QUARANTINE_REGISTRY[hostname] = record
    PLAYBOOK_AUDIT_LOG.insert(0, record)
    print(f"[SOAR EDR] Isolated Host: {hostname} | Reason: {reason}")
    return record

def revoke_credentials(username, reason="Compromised Account Remediation"):
    """Revokes active Kerberos / OAuth tokens and flags password reset."""
    action_id = f"SOAR-ACT-{uuid.uuid4().hex[:6].upper()}"
    record = {
        "action_id": action_id,
        "type": "CREDENTIAL_REVOCATION",
        "target": username,
        "reason": reason,
        "timestamp": datetime.datetime.now(IST).isoformat(),
        "status": "REVOKED"
    }
    PLAYBOOK_AUDIT_LOG.insert(0, record)
    print(f"[SOAR IAM] Revoked Credentials for: {username} | Reason: {reason}")
    return record

def release_quarantine(target):
    """Releases an IP or host from quarantine."""
    if target in QUARANTINE_REGISTRY:
        record = QUARANTINE_REGISTRY.pop(target)
        record["status"] = "RELEASED"
        record["released_at"] = datetime.datetime.now(IST).isoformat()
        PLAYBOOK_AUDIT_LOG.insert(0, record)
        print(f"[SOAR] Released target from quarantine: {target}")
        return {"status": "success", "target": target}
    return {"status": "not_found", "target": target}

def execute_playbook(playbook_name, target, context="Autonomous Incident Mitigation"):
    """
    Dispatcher for SOAR automated playbooks.
    Supported: 'block_ip', 'isolate_host', 'revoke_credentials'
    """
    playbook_map = {
        "block_ip": block_ip,
        "isolate_host": isolate_host,
        "revoke_credentials": revoke_credentials
    }
    handler = playbook_map.get(playbook_name.lower())
    if not handler:
        return {"status": "error", "message": f"Unknown playbook: {playbook_name}"}
    return handler(target, reason=context)

def respond(ip):
    """Backwards-compatible interface for main.py."""
    return block_ip(ip, reason="Legacy SOC Auto-Response")

def get_quarantined_assets():
    """Returns list of currently active quarantined assets."""
    return list(QUARANTINE_REGISTRY.values())

def get_playbook_logs(limit=50):
    """Returns recent playbook execution logs."""
    return PLAYBOOK_AUDIT_LOG[:limit]
