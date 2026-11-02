import base64
import urllib.parse
from threat_intel.intel import enrich, query_threat_feed
from detection.mitre_mapping import get_technique_details, map_attack
from response.response import block_ip, isolate_host, revoke_credentials

def tool_threat_intel_lookup(indicator):
    """Tool: Look up an IP or indicator in the threat intelligence feeds."""
    return enrich(indicator)

def tool_mitre_attack_lookup(technique_id):
    """Tool: Retrieve MITRE ATT&CK technique details and mitigations."""
    details = get_technique_details(technique_id)
    if details:
        return details
    return {"id": technique_id, "name": "Custom / Unmapped Technique", "mitigation": "Review network controls"}

def tool_decode_payload(payload):
    """Tool: Decodes URL-encoded or Base64-obfuscated strings."""
    if not payload:
        return {"original": "", "decoded": ""}
    decoded = urllib.parse.unquote(str(payload))
    b64_candidate = None
    try:
        # Check for Base64 substring
        if len(decoded) > 16 and (len(decoded) % 4 == 0 or "=" in decoded):
            clean_b64 = decoded.strip()
            raw_bytes = base64.b64decode(clean_b64)
            b64_candidate = raw_bytes.decode('utf-8', errors='ignore')
    except Exception:
        b64_candidate = None

    return {
        "url_decoded": decoded,
        "base64_decoded": b64_candidate
    }

def tool_host_telemetry_check(host):
    """Tool: Returns known asset criticality and risk context for a hostname."""
    critical_servers = {
        "auth-srv-prod-01": {"criticality": "TIER-0", "role": "Domain Controller / Identity Gateway"},
        "web-gateway-01": {"criticality": "TIER-1", "role": "Internet DMZ Reverse Proxy"},
        "database-internal-01": {"criticality": "TIER-0", "role": "PCI-DSS Regulated Core Database"},
        "workstation-fin-04": {"criticality": "TIER-2", "role": "Corporate Finance Department Endpoint"}
    }
    return critical_servers.get(host, {"criticality": "TIER-3", "role": "Standard Corporate Client Host"})

def tool_execute_containment(playbook, target, reason):
    """Tool: Execute a SOAR containment action."""
    if playbook == "block_ip":
        return block_ip(target, reason=reason)
    elif playbook == "isolate_host":
        return isolate_host(target, reason=reason)
    elif playbook == "revoke_credentials":
        return revoke_credentials(target, reason=reason)
    return {"status": "error", "message": f"Unsupported playbook: {playbook}"}
