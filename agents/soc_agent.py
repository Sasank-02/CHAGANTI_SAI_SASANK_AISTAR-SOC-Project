import uuid
import datetime

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), name="IST")

from agents.agent_tools import (
    tool_threat_intel_lookup,
    tool_mitre_attack_lookup,
    tool_decode_payload,
    tool_host_telemetry_check,
    tool_execute_containment
)
from detection.mitre_mapping import map_attack

INCIDENT_STORE = []

class AgenticSOCAnalyst:
    """
    Autonomous Tier-1/Tier-2 AI SOC Analyst.
    Implements a ReAct (Reason + Act) loop to investigate security alerts,
    gather forensic evidence across tools, correlate attack stages, and execute SOAR response.
    """

    def __init__(self, agent_name="AISTAR-Autonomous-Analyst-v2"):
        self.agent_name = agent_name

    def investigate(self, log, anomaly_data=None, rule_matches=None):
        """
        Executes an autonomous multi-step investigation on a security event.
        Returns a comprehensive Incident Dossier with full audit trail.
        """
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        start_time = datetime.datetime.now(IST).isoformat()
        chain_of_thought = []

        src_ip = log.get("source_ip", "127.0.0.1")
        host = log.get("host", "unknown-host")
        user = log.get("user", "unknown-user")
        raw_payload = log.get("raw_payload", "")
        uri_path = log.get("uri_path", "")

        # =========================================================================
        # STEP 1: PERCEPTION & TRIAGE
        # =========================================================================
        step1_thought = f"Alert triggered for host '{host}' involving source IP '{src_ip}'. I need to inspect the event context, check anomaly score, and identify active indicators."
        anomaly_score = anomaly_data.get("anomaly_score", 0.0) if anomaly_data else 0.0
        rule_names = [r["rule_name"] for r in (rule_matches or [])]

        step1_obs = f"Ingested event. ML Anomaly Score: {anomaly_score}%. Matched Correlation Rules: {rule_names if rule_names else 'None'}. Source IP: {src_ip}."
        chain_of_thought.append({
            "step": 1,
            "phase": "Triage & Perception",
            "thought": step1_thought,
            "action": "triage_alert",
            "observation": step1_obs
        })

        # =========================================================================
        # STEP 2: THREAT INTEL QUERY
        # =========================================================================
        step2_thought = f"Checking global threat intelligence repositories for source IP {src_ip} to assess reputation, threat actor affiliation, and past attack history."
        intel_result = tool_threat_intel_lookup(src_ip)
        step2_obs = (
            f"Threat Intel match: Reputation={intel_result.get('reputation')}, "
            f"Threat Actor={intel_result.get('threat_actor', 'None')}, "
            f"Risk Score={intel_result.get('risk_score', 0)}/100, Country={intel_result.get('country')}"
        )
        chain_of_thought.append({
            "step": 2,
            "phase": "Threat Intelligence Enrichment",
            "thought": step2_thought,
            "action": "tool_threat_intel_lookup",
            "action_input": src_ip,
            "observation": step2_obs
        })

        # =========================================================================
        # STEP 3: ASSET & HOST CRITICALITY CHECK
        # =========================================================================
        step3_thought = f"Evaluating asset criticality and role for target host '{host}' to calculate enterprise impact."
        host_info = tool_host_telemetry_check(host)
        step3_obs = f"Target Host '{host}' identified as Tier: {host_info.get('criticality')} | Role: {host_info.get('role')}."
        chain_of_thought.append({
            "step": 3,
            "phase": "Asset Criticality Assessment",
            "thought": step3_thought,
            "action": "tool_host_telemetry_check",
            "action_input": host,
            "observation": step3_obs
        })

        # =========================================================================
        # STEP 4: PAYLOAD & FORENSIC DECODING (IF PRESENT)
        # =========================================================================
        decoded_evidence = None
        if uri_path or log.get("command"):
            target_str = uri_path if uri_path else log.get("command")
            step4_thought = f"Inspecting suspicious URI/command payload for obfuscation, SQLi tokens, or base64 encoded scripts."
            decoded_evidence = tool_decode_payload(target_str)
            step4_obs = f"Decoded string inspection completed. URL Decoded: {decoded_evidence.get('url_decoded')[:80]}..."
            chain_of_thought.append({
                "step": 4,
                "phase": "Forensic Payload Analysis",
                "thought": step4_thought,
                "action": "tool_decode_payload",
                "action_input": target_str[:100],
                "observation": step4_obs
            })

        # =========================================================================
        # STEP 5: MITRE ATT&CK CORRELATION
        # =========================================================================
        step5_thought = "Mapping observed attack techniques, artifacts, and evasion patterns to the MITRE ATT&CK Enterprise Matrix."
        mitre_info = map_attack(log)
        step5_obs = f"Mapped Technique: {mitre_info.get('id')} ({mitre_info.get('name')}) under Tactic '{mitre_info.get('tactic')}'."
        chain_of_thought.append({
            "step": 5,
            "phase": "MITRE ATT&CK Mapping",
            "thought": step5_thought,
            "action": "tool_mitre_attack_lookup",
            "action_input": mitre_info.get("id"),
            "observation": step5_obs
        })

        # =========================================================================
        # STEP 6: RISK SCORING & VERDICT FORMATION
        # =========================================================================
        intel_score = intel_result.get("risk_score", 20)
        host_weight = 1.3 if host_info.get("criticality") == "TIER-0" else (1.1 if host_info.get("criticality") == "TIER-1" else 1.0)
        rule_weight = 40.0 if rule_matches else 0.0

        composite_risk = min(100.0, round(((intel_score * 0.35) + (anomaly_score * 0.35) + (rule_weight * 0.30)) * host_weight, 1))

        if composite_risk >= 75.0 or mitre_info.get("severity") == "CRITICAL":
            verdict = "TRUE_POSITIVE_THREAT"
            severity = "CRITICAL" if composite_risk >= 85 else "HIGH"
            confidence = 0.94
        elif composite_risk >= 45.0 or rule_matches:
            verdict = "SUSPICIOUS_ANOMALY"
            severity = "MEDIUM"
            confidence = 0.82
        else:
            verdict = "BENIGN_FALSE_POSITIVE"
            severity = "LOW"
            confidence = 0.88

        step6_thought = f"Synthesizing evidence: Intel Risk ({intel_score}), ML Anomaly ({anomaly_score}), Rules ({len(rule_matches or [])}). Composite Risk calculated at {composite_risk}%. Determining verdict."
        step6_obs = f"Verdict established: {verdict} | Severity: {severity} | Confidence: {int(confidence*100)}%."
        chain_of_thought.append({
            "step": 6,
            "phase": "Risk Synthesis & Verdict",
            "thought": step6_thought,
            "action": "calculate_risk_verdict",
            "observation": step6_obs
        })

        # =========================================================================
        # STEP 7: AUTONOMOUS SOAR RESPONSE DISPATCH
        # =========================================================================
        containment_actions = []
        if verdict == "TRUE_POSITIVE_THREAT":
            step7_thought = f"Threat verified as {severity} risk. Autonomous containment is authorized under SOC Policy Level-1. Executing perimeter block on source IP {src_ip}."
            
            # Action A: Block IP if external
            if intel_result.get("reputation") != "internal" and src_ip != "127.0.0.1":
                block_res = tool_execute_containment("block_ip", src_ip, reason=f"Autonomous containment for {mitre_info.get('id')} - {mitre_info.get('name')}")
                containment_actions.append(block_res)

            # Action B: Isolate host if credential dumping or C2
            if mitre_info.get("id") in ["T1003", "T1071", "T1041"]:
                iso_res = tool_execute_containment("isolate_host", host, reason=f"Compromised host containment for {mitre_info.get('name')}")
                containment_actions.append(iso_res)

            # Action C: Revoke credentials if brute force succeeded or mimikatz
            if user and user not in ["unknown", "anonymous", "root"] and mitre_info.get("id") in ["T1110", "T1003"]:
                rev_res = tool_execute_containment("revoke_credentials", user, reason=f"Revoking tokens for account under {mitre_info.get('id')} attack")
                containment_actions.append(rev_res)

            step7_obs = f"Successfully dispatched {len(containment_actions)} automated containment actions."
            chain_of_thought.append({
                "step": 7,
                "phase": "Autonomous SOAR Playbook Execution",
                "thought": step7_thought,
                "action": "tool_execute_containment",
                "observation": step7_obs
            })

        # =========================================================================
        # STEP 8: ROOT CAUSE & EXECUTIVE SUMMARY GENERATION
        # =========================================================================
        root_cause = (
            f"Adversary originating from {src_ip} ({intel_result.get('threat_actor', 'Unattributed')}, {intel_result.get('country')}) "
            f"conducted {mitre_info.get('name')} against protected host '{host}' ({host_info.get('role')}). "
            f"Detection triggered via {', '.join(rule_names) if rule_names else 'Behavioral ML Model'} with an anomaly confidence of {anomaly_score}%."
        )

        executive_summary = (
            f"Automated AI SOC Analyst contained a {severity} security incident ({incident_id}) "
            f"classified under MITRE ATT&CK {mitre_info.get('id')}. Perimeter firewall rules and asset safeguards were applied autonomously."
        )

        incident_record = {
            "incident_id": incident_id,
            "timestamp": start_time,
            "status": "CONTAINED" if containment_actions else ("TRIAGED" if verdict == "SUSPICIOUS_ANOMALY" else "RESOLVED"),
            "verdict": verdict,
            "severity": severity,
            "composite_risk_score": composite_risk,
            "confidence_score": confidence,
            "target_host": host,
            "target_user": user,
            "source_indicator": src_ip,
            "mitre_technique": mitre_info,
            "threat_intel": intel_result,
            "rule_matches": rule_matches or [],
            "anomaly_data": anomaly_data or {},
            "chain_of_thought": chain_of_thought,
            "containment_actions": containment_actions,
            "root_cause_analysis": root_cause,
            "executive_summary": executive_summary,
            "remediation_guidance": mitre_info.get("mitigation", "Enforce continuous endpoint isolation and credential rotation.")
        }

        INCIDENT_STORE.insert(0, incident_record)
        if len(INCIDENT_STORE) > 100:
            INCIDENT_STORE.pop()

        return incident_record

def get_incidents(limit=50):
    """Returns stored incidents."""
    return INCIDENT_STORE[:limit]

def get_incident_by_id(incident_id):
    """Finds a specific incident by ID."""
    for inc in INCIDENT_STORE:
        if inc["incident_id"] == incident_id:
            return inc
    return None
