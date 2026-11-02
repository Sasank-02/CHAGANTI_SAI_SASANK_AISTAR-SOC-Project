# AISTAR-SOC: Autonomous Agentic AI Cybersecurity SOC Analyst

> **A Complete, End-to-End Autonomous Cybersecurity Security Operations Center (SOC) Analyst Platform powered by Agentic ReAct Reasoning, ML Anomaly Detection, MITRE ATT&CK Correlation, and Automated SOAR Incident Containment.**

---

## 🌟 Architecture & Agentic Workflow

```
       [ Multi-Source Security Telemetry ]
   (SSH, Web WAF, EDR Processes, Network C2, Exfiltration)
                         │
                         ▼
        [ Phase 1: Ingestion & Normalization ]
         Standardized Common Security Event Format
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
 [ Unsupervised ML Model ]     [ Sigma/YARA Rules ]
  Isolation Forest Anomaly      Multi-threat Patterns
      Scoring (0-100%)         (SQLi, C2, Mimikatz)
          └──────────────┬──────────────┘
                         │ (Threat Trigger)
                         ▼
   ┌───────────────────────────────────────────────┐
   │     🧠 AUTONOMOUS AGENTIC AI SOC ANALYST      │
   │           (ReAct Reasoning Engine)            │
   │                                               │
   │  1. Perception: Alert & Context Ingestion     │
   │  2. Forensic Queries: Threat Intel (OSINT)    │
   │  3. Asset Assessment: Host Criticality Check  │
   │  4. Payload Decoder: URL / Base64 Inspection  │
   │  5. MITRE ATT&CK Mapping: Tactics/Techniques  │
   │  6. Evidence Synthesis: Composite Risk Score  │
   └──────────────────────┬────────────────────────┘
                          │
                          ▼
            [ Automated SOAR Engine ]
      • Firewall IP Perimeter Block (TTL)
      • Compromised Host Network Isolation
      • IAM Credential & Session Revocation
                          │
                          ▼
        [ Executive Incident Dossier & UI ]
       Live Cyber Operations Center Dashboard
```

---

## 🚀 Key Features

1. **Autonomous ReAct Reasoning Loop**:
   - The AI Analyst executes explicit **Perception -> Hypothesis -> Tool Execution -> Forensic Observation -> Synthesis** cycles.
   - Generates fully explainable chains of thought for auditability and compliance.

2. **Multi-Source Security Telemetry**:
   - Ingests diverse threat vectors: SSH/RDP brute force, web attacks (SQLi), Cobalt Strike C2 beaconing, LSASS memory dumping (Mimikatz), and data exfiltration.

3. **Hybrid Detection Engine**:
   - **Machine Learning**: Multi-feature `IsolationForest` detecting volume, port, and behavioral anomalies.
   - **Correlation Rules**: High-fidelity detection rules mapped to threat actor behaviors.

4. **Threat Intelligence & Enrichment**:
   - Built-in OSINT IOC repository scoring IP reputation, threat actor attribution (e.g., APT28, FIN7, ALPHV), ASN, and geolocations.

5. **MITRE ATT&CK Enterprise Matrix**:
   - Maps alerts directly to Tactics (Credential Access, Execution, Persistence, Command & Control, Exfiltration) and Techniques (`T1110`, `T1190`, `T1071`, `T1003`, `T1041`, `T1046`, `T1059`).

6. **Automated SOAR Playbooks**:
   - Automated perimeter IP blocking, host quarantine, credential revocations, and analyst manual override console.

7. **Modern Web Command Center UI**:
   - Cyber dark mode dashboard, live telemetry feed, MITRE ATT&CK heatmap, interactive attack campaign simulator, and one-click incident report exporter.

8. **Cybersecurity Data Analytics & BI Charts Suite**:
   - **Time-Series Area Chart**: Real-time telemetry flow and threat volumetric curves across Indian Standard Time (IST).
   - **Threat Severity Donut Chart**: Proportional breakdown of Critical, High, Medium, and Low risk threats.
   - **Attack Vectors Horizontal Bar Chart**: Technique hit comparisons across brute force, web injections, and C2 beacons.
   - **MITRE ATT&CK Threat Radar**: Multi-axis radar visualizing organizational exposure across tactics.
   - **Target Asset Risk Grouped Bar Chart**: Host-level vulnerability indexing comparing incident count against average risk score.
   - **SOAR Operational Efficiency BI**: Real-time tracking of estimated analyst hours saved and machine containment rates.

---

## 🛠️ Project Structure

```
AISTAR-SOC/
├── agents/                     # Agentic AI Core
│   ├── soc_agent.py            # Autonomous AI SOC Analyst (ReAct Loop)
│   └── agent_tools.py          # Forensic tools for threat intel, decoding & SOAR
├── api/
│   └── server.py               # Production Flask REST API (12+ endpoints)
├── dashboard/
│   ├── app.py                  # Web application server
│   ├── templates/index.html    # Cyber Dark Operations Center UI
│   └── static/
│       ├── css/dashboard.css   # Modern dark-mode cybersecurity theme
│       └── js/dashboard.js     # Live streaming and simulator controls
├── data/
│   └── sample_logs/logs.json   # Multi-vector cybersecurity sample telemetry
├── detection/
│   ├── anomaly_model.py        # Multi-dimensional Isolation Forest model
│   ├── rule_engine.py          # Sigma-style correlation rule engine
│   └── mitre_mapping.py        # MITRE ATT&CK Matrix mapping & mitigations
├── ingestion/
│   └── log_collector.py        # Telemetry ingestion, normalizer & simulator
├── response/
│   ├── alert.py                # Structured alert manager
│   └── response.py             # SOAR automated mitigation engine
├── main.py                     # CLI Agentic Pipeline runner
└── requirements.txt            # Python dependencies
```

---

## 💻 Setup & Execution Instructions

### 1. Activate Environment & Install Dependencies

```powershell
# Open terminal in project root
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

---

### 2. Run the Autonomous Agentic Pipeline (CLI Demonstration)

Runs the full end-to-end autonomous triage, forensic analysis, and SOAR response in the terminal with colored reasoning output:

```powershell
python main.py
```

---

### 3. Launch the SOC Command Center Dashboard

Starts the web dashboard on **http://127.0.0.1:5000**:

```powershell
python dashboard/app.py
```

Open your browser to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

*From the dashboard, you can:*
- Click any **"Inject Cyber Attack Campaign"** button to simulate live attacks (SSH Brute Force, SQL Injection, Cobalt Strike C2, Mimikatz, Data Exfiltration).
- Watch the **AI Agent** investigate in real time.
- Click **"Investigate"** on any incident to see the complete **Chain-of-Thought reasoning steps**.
- Click **"Export Incident Report"** to download an executive Markdown summary.

---

### 4. Run the Standalone REST API (Optional)

Starts the dedicated REST API on **http://127.0.0.1:5001**:

```powershell
python api/server.py
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | System health, active agents, and metric counters |
| `GET` | `/api/metrics` | SOC KPIs (MTTD, MTTR, automated containment rate) |
| `GET` | `/api/telemetry` | Recent multi-vector telemetry stream |
| `POST` | `/api/telemetry/simulate` | Inject simulated attack campaign (`brute_force`, `sqli`, `c2_beacon`, `mimikatz`, `exfiltration`) |
| `GET` | `/api/alerts` | List all triaged alerts |
| `GET` | `/api/incidents` | List analyzed incidents with risk scores |
| `GET` | `/api/incidents/<id>` | Full incident details with Agent ReAct Chain-of-Thought |
| `POST` | `/api/incidents/<id>/respond` | Trigger manual SOAR containment playbook override |
| `POST` | `/api/agent/investigate` | Run autonomous investigation on arbitrary submitted log |
| `GET` | `/api/threat-intel/<ioc>` | Enrich an IP/IOC with reputation, threat actor, and country |
| `GET` | `/api/quarantine` | List active firewall blocks and host isolations |
| `POST` | `/api/quarantine/release` | Unblock an asset from quarantine |
| `GET` | `/api/mitre/matrix` | Full list of supported MITRE ATT&CK techniques |
| `GET` | `/api/analytics/overview` | Full BI threat vector breakdown, asset exposure, and SOAR efficiency |
| `GET` | `/api/analytics/assets` | Target host vulnerability and risk exposure ranking |
| `GET` | `/api/analytics/vectors` | Distribution of attack vectors, MITRE tactics, and severities |
