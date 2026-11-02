import os
import sys
import time

# Ensure root workspace is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ingestion.log_collector import collect_logs
from detection.anomaly_model import train, score_log
from detection.rule_engine import evaluate_rules, brute_force
from detection.mitre_mapping import map_attack
from response.alert import create_alert, alert
from response.response import respond, get_quarantined_assets
from agents.soc_agent import AgenticSOCAnalyst
from analytics.soc_analytics import SOCAnalyticsEngine

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"""{CYAN}{BOLD}
    ====================================================================
      ___  _____ ____ _____  _    ____       ____   ___   ____ 
     / _ \\|_   _/ ___|_   _|/ \\  |  _ \\     / ___| / _ \\ / ___|
    / /_\\ \\ | | \\___ \\ | | / _ \\ | |_) |____\\___ \\| | | | |    
    |  _  | | |  ___) || |/ ___ \\|  _ <_____|___) | |_| | |___ 
    |_| |_| |_| |____/ |_/_/   \\_\\_| \\_\\    |____/ \\___/ \\____|
          AUTONOMOUS AGENTIC AI CYBERSECURITY SOC ANALYST
    ===================================================================={RESET}
    [+] Autonomous Multi-Stage Threat Detection, Triage & Containment
    [+] ReAct Agentic Reasoning Loop • MITRE ATT&CK Matrix • SOAR Engine
    """)

def main():
    banner()

    print(f"{BOLD}[PHASE 1] TELEMETRY INGESTION & NORMALIZATION{RESET}")
    logs = collect_logs(os.path.join(BASE_DIR, "data", "sample_logs"))
    print(f"[*] Ingested {len(logs)} multi-vector telemetry events (SSH, Web, Network, Endpoint, Exfiltration).\n")

    print(f"{BOLD}[PHASE 2] UNSUPERVISED ML BASELINE & ANOMALY MODEL TRAINING{RESET}")
    print("[*] Training Isolation Forest model on multi-dimensional telemetry features...")
    model = train(logs)
    print(f"{GREEN}[✓] Isolation Forest model trained and baseline established.{RESET}\n")

    print(f"{BOLD}[PHASE 3] AGENTIC AI SOC ANALYST TRIAGE & REACT REASONING PIPELINE{RESET}")
    agent = AgenticSOCAnalyst()

    incidents_triaged = []

    for i, log in enumerate(logs, 1):
        rule_matches = evaluate_rules(log)
        anomaly_info = score_log(model, log)

        is_threat = bool(rule_matches or anomaly_info["is_anomaly"] or brute_force(log))

        if is_threat:
            print(f"\n{RED}────────────────────────────────────────────────────────────────────{RESET}")
            print(f"{RED}[TRIGGER DETECTED]{RESET} Event: {log['id']} | Host: {log['host']} | Source: {log['source_ip']}")
            
            # Create Alert
            alt = create_alert(
                title=f"Suspicious activity on {log['host']}",
                severity="CRITICAL" if rule_matches else "HIGH",
                mitre_id=rule_matches[0]["mitre_id"] if rule_matches else "T1110",
                indicator=log["source_ip"],
                log_ref=log["id"]
            )

            # Invoke Autonomous SOC Analyst ReAct Loop
            incident = agent.investigate(log, anomaly_data=anomaly_info, rule_matches=rule_matches)
            incidents_triaged.append(incident)

            # Display Agent's ReAct Chain-of-Thought in terminal
            print(f"{YELLOW}{BOLD}[🧠 AGENT CHAIN-OF-THOUGHT INVESTIGATION]{RESET}")
            for step in incident["chain_of_thought"]:
                print(f"  {CYAN}▸ Step {step['step']} [{step['phase']}]:{RESET}")
                print(f"    Thought : {step['thought']}")
                print(f"    Action  : {step['action']}")
                print(f"    Obs     : {step['observation']}")

            print(f"{GREEN}{BOLD}[VERDICT & CONTAINMENT SUMMARY]{RESET}")
            print(f"  Verdict       : {incident['verdict']} (Confidence: {int(incident['confidence_score']*100)}%)")
            print(f"  Risk Severity : {incident['severity']} (Composite Risk: {incident['composite_risk_score']}%)")
            print(f"  MITRE ATT&CK  : {incident['mitre_technique']['id']} - {incident['mitre_technique']['name']}")
            print(f"  SOAR Actions  : {len(incident['containment_actions'])} automated countermeasures deployed")

    print(f"\n{BOLD}[PHASE 4] CYBERSECURITY ANALYTICS & BI POSTURE INTELLIGENCE{RESET}")
    print(f"====================================================================")
    analytics_engine = SOCAnalyticsEngine()
    analytics_data = analytics_engine.compute_analytics(logs, incidents_triaged, get_quarantined_assets())

    summary = analytics_data["summary"]
    print(f"  Total Security Events Ingested : {summary['total_telemetry_events']}")
    print(f"  Incidents Autonomously Triaged : {summary['total_incidents_analyzed']}")
    print(f"  Critical Threat Ratio          : {summary['critical_threat_ratio']}%")
    print(f"  Average Incident Risk Score    : {summary['average_incident_risk_score']}/100")
    print(f"  Active Quarantines (SOAR)      : {summary['active_perimeter_quarantines']}")
    print(f"  Mean Time To Respond (MTTR)    : {summary['mean_time_to_respond_sec']}s (Machine speed)")
    print(f"  Analyst Hours Saved (Est.)     : {analytics_data['soar_efficiency']['analyst_hours_saved_est']} hrs")

    print(f"\n  {YELLOW}▸ Top Attack Vectors Detected:{RESET}")
    for v in analytics_data["threat_vector_distribution"][:3]:
        print(f"    - {v['vector']}: {v['count']} events ({v['percentage']}%)")

    print(f"\n  {RED}▸ Target Asset Exposure Ranking:{RESET}")
    for a in analytics_data["target_asset_risk_matrix"][:3]:
        print(f"    - Host '{a['host']}': {a['incident_count']} incidents | Avg Risk: {a['average_risk']}% | Compromised: {a['compromised']}")

    print(f"====================================================================")
    print(f"\n{GREEN}[✓] Autonomous Pipeline & Analytics computation complete.{RESET}")
    print(f"{CYAN}[i] View Live Visual Analytics on Dashboard: {BOLD}http://127.0.0.1:5000{RESET}")
    print(f"{CYAN}[i] Query Analytics REST API Endpoints   : {BOLD}http://127.0.0.1:5001/api/analytics{RESET}\n")

if __name__ == "__main__":
    main()
