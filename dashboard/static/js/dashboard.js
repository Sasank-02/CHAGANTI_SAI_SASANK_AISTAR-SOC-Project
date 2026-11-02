// ==========================================================================
// AISTAR-SOC | Autonomous Agentic Cybersecurity Operations Frontend
// ==========================================================================

const API_BASE = window.location.port === "5000" ? "" : "http://127.0.0.1:5001";
let currentModalIncident = null;

// On Page Load
document.addEventListener("DOMContentLoaded", () => {
  initClock();
  fetchAllData();
  // Live polling every 4 seconds
  setInterval(fetchAllData, 4000);
});

function formatIST(isoStr) {
  if (!isoStr) return "--";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    }) + " IST";
  } catch (e) {
    return isoStr.substring(11, 19) + " IST";
  }
}

function initClock() {
  const clockEl = document.getElementById("live-ist-clock");
  if (!clockEl) return;
  const update = () => {
    const now = new Date();
    const timeStr = now.toLocaleTimeString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
    clockEl.textContent = `${timeStr} IST`;
  };
  update();
  setInterval(update, 1000);
}

async function fetchAllData() {
  await Promise.all([
    loadMetrics(),
    loadIncidents(),
    loadTelemetry(),
    loadQuarantines(),
    loadMitreMatrix(),
    loadAnalytics()
  ]);
}

// --------------------------------------------------------------------------
// 1. Metrics & KPIs
// --------------------------------------------------------------------------
async function loadMetrics() {
  try {
    const res = await fetch(`${API_BASE}/api/metrics`);
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById("val-events").textContent = data.total_events_processed;
    document.getElementById("val-incidents").textContent = data.total_incidents_analyzed;
    document.getElementById("val-quarantines").textContent = data.quarantined_threats;
    document.getElementById("val-containment-rate").textContent = `${data.automated_containment_rate}%`;
    document.getElementById("val-mttr").textContent = `${data.avg_mttr_seconds}s`;
  } catch (err) {
    console.warn("API offline or metrics loading error:", err);
  }
}

// --------------------------------------------------------------------------
// 2. Incident Management & Triage
// --------------------------------------------------------------------------
async function loadIncidents() {
  try {
    const res = await fetch(`${API_BASE}/api/incidents?limit=15`);
    if (!res.ok) return;
    const incidents = await res.json();
    const tbody = document.getElementById("incidents-tbody");

    if (!incidents || incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center text-dim">No incidents triaged yet. Inject an attack scenario to begin.</td></tr>`;
      return;
    }

    tbody.innerHTML = incidents.map(inc => {
      const sevClass = `sev-${inc.severity.toLowerCase()}`;
      const statusClass = inc.status === "CONTAINED" ? "status-contained" : (inc.status === "OPEN" ? "status-open" : "status-triaged");
      const mitre = inc.mitre_technique || {};
      const timeStr = formatIST(inc.timestamp);

      return `
        <tr>
          <td><strong style="color:var(--accent-cyan); font-family:var(--font-mono);">${inc.incident_id}</strong></td>
          <td><span style="color:var(--text-dim); font-family:var(--font-mono);">${timeStr}</span></td>
          <td><span class="badge-sev ${sevClass}">${inc.severity}</span></td>
          <td>
            <strong style="color:#fff;">${mitre.id || 'T0000'}</strong> 
            <span style="color:var(--text-dim); font-size:11px;">${(mitre.name || '').substring(0, 20)}...</span>
          </td>
          <td>
            <div style="font-family:var(--font-mono);">${inc.source_indicator}</div>
            <div style="color:var(--text-dim); font-size:10px;">Host: ${inc.target_host}</div>
          </td>
          <td><strong style="color:${inc.composite_risk_score > 70 ? 'var(--accent-red)' : 'var(--accent-amber)'}">${inc.composite_risk_score}%</strong></td>
          <td><span class="badge-status ${statusClass}">${inc.status}</span></td>
          <td>
            <button class="btn-inspect" onclick="openIncidentDetails('${inc.incident_id}')">Investigate</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Error loading incidents:", err);
  }
}

// --------------------------------------------------------------------------
// 3. Raw Telemetry Stream
// --------------------------------------------------------------------------
async function loadTelemetry() {
  try {
    const res = await fetch(`${API_BASE}/api/telemetry?limit=8`);
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.getElementById("telemetry-tbody");
    const countTag = document.getElementById("telemetry-counter");

    if (countTag) countTag.textContent = `Showing ${data.telemetry ? data.telemetry.length : 0} latest of ${data.total} flows`;

    if (!data.telemetry || data.telemetry.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center">No telemetry logs available.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.telemetry.map(t => {
      const payloadSnippet = t.raw_payload || t.command || t.uri_path || "Standard traffic flow";
      return `
        <tr>
          <td style="font-family:var(--font-mono); color:var(--text-dim);">${t.id}</td>
          <td><span style="font-weight:600; text-transform:uppercase; font-size:10px; color:var(--accent-cyan);">${t.event_type}</span></td>
          <td>${t.host}</td>
          <td style="font-family:var(--font-mono);">${t.source_ip}</td>
          <td style="font-family:var(--font-mono);">${t.destination_ip}:${t.destination_port}</td>
          <td style="color:var(--text-muted); font-size:11px; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
            ${payloadSnippet}
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Error loading telemetry:", err);
  }
}

// --------------------------------------------------------------------------
// 4. Quarantines & SOAR Console
// --------------------------------------------------------------------------
async function loadQuarantines() {
  try {
    const res = await fetch(`${API_BASE}/api/quarantine`);
    if (!res.ok) return;
    const data = await res.json();
    const container = document.getElementById("quarantine-items");
    const badge = document.getElementById("quarantine-count-badge");

    const active = data.quarantined_assets || [];
    if (badge) badge.textContent = `${active.length} Active`;

    if (active.length === 0) {
      container.innerHTML = `<div class="empty-placeholder">No active perimeter blocks. All systems nominal.</div>`;
      return;
    }

    container.innerHTML = active.map(item => `
      <div class="quarantine-item">
        <div class="quarantine-meta">
          <span class="quarantine-target">${item.target} (${item.type})</span>
          <span class="quarantine-reason">${item.reason}</span>
        </div>
        <button class="btn-release" onclick="releaseTarget('${item.target}')">Release</button>
      </div>
    `).join("");
  } catch (err) {
    console.error("Error loading quarantines:", err);
  }
}

async function releaseTarget(target) {
  try {
    await fetch(`${API_BASE}/api/quarantine/release`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target })
    });
    loadQuarantines();
    loadMetrics();
  } catch (err) {
    alert("Failed to release target: " + err);
  }
}

// --------------------------------------------------------------------------
// 5. MITRE ATT&CK Matrix
// --------------------------------------------------------------------------
async function loadMitreMatrix() {
  const grid = document.getElementById("mitre-matrix-grid");
  if (grid.dataset.loaded === "true") return;

  try {
    const res = await fetch(`${API_BASE}/api/mitre/matrix`);
    if (!res.ok) return;
    const techniques = await res.json();
    grid.innerHTML = techniques.map(t => `
      <div class="mitre-cell">
        <div class="mitre-tactic">${t.tactic}</div>
        <div class="mitre-id">${t.id}</div>
        <div class="mitre-name" title="${t.name}">${t.name}</div>
      </div>
    `).join("");
    grid.dataset.loaded = "true";
  } catch (err) {
    console.error("Error loading MITRE matrix:", err);
  }
}

// --------------------------------------------------------------------------
// 6. Threat Intel Search
// --------------------------------------------------------------------------
async function searchThreatIntel() {
  const query = document.getElementById("intel-query-input").value.trim();
  const display = document.getElementById("intel-result-display");
  if (!query) return;

  display.innerHTML = `<div style="color:var(--text-dim);">Querying threat intelligence database...</div>`;

  try {
    const res = await fetch(`${API_BASE}/api/threat-intel/${encodeURIComponent(query)}`);
    const data = await res.json();

    const isMal = data.risk_score >= 70;
    display.innerHTML = `
      <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
        <strong style="color:var(--accent-cyan); font-family:var(--font-mono);">${data.ip}</strong>
        <span class="badge-sev ${isMal ? 'sev-critical' : 'sev-low'}">${data.reputation.toUpperCase()} (${data.risk_score}/100)</span>
      </div>
      <div style="font-size:11px; color:var(--text-muted); line-height:1.6;">
        <div><strong>Threat Actor:</strong> ${data.threat_actor || 'None / Unattributed'}</div>
        <div><strong>Country:</strong> ${data.country || 'N/A'} | <strong>ASN:</strong> ${data.asn || 'N/A'}</div>
        <div><strong>Category:</strong> ${data.category || 'Standard Node'}</div>
        <div style="margin-top:4px; color:#cbd5e1;"><em>${data.notes || ''}</em></div>
      </div>
    `;
  } catch (err) {
    display.innerHTML = `<div style="color:var(--accent-red);">Lookup error: ${err.message}</div>`;
  }
}

// --------------------------------------------------------------------------
// 7. Inject Cyber Attack Scenario
// --------------------------------------------------------------------------
async function injectScenario(scenario) {
  try {
    const res = await fetch(`${API_BASE}/api/telemetry/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenario, count: 1 })
    });
    const result = await res.json();
    // Visual refresh
    await fetchAllData();
  } catch (err) {
    alert("Error simulating attack: " + err);
  }
}

// --------------------------------------------------------------------------
// 8. Deep-Dive Modal (Agentic ReAct Chain of Thought)
// --------------------------------------------------------------------------
async function openIncidentDetails(incidentId) {
  try {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}`);
    if (!res.ok) throw new Error("Incident not found");
    const inc = await res.json();
    currentModalIncident = inc;

    document.getElementById("modal-incident-id").textContent = `INCIDENT DOSSIER: ${inc.incident_id}`;
    document.getElementById("modal-incident-summary").textContent = `${inc.verdict} • Risk: ${inc.composite_risk_score}% • Confidence: ${inc.confidence_score * 100}%`;

    const content = document.getElementById("modal-content");
    const mitre = inc.mitre_technique || {};
    const cot = inc.chain_of_thought || [];

    content.innerHTML = `
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:14px; background:var(--bg-surface); padding:16px; border-radius:8px; border:1px solid var(--border-color);">
        <div>
          <div style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Target Asset</div>
          <div style="font-weight:700; color:#fff;">${inc.target_host} (User: ${inc.target_user})</div>
        </div>
        <div>
          <div style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Attacker Indicator</div>
          <div style="font-weight:700; font-family:var(--font-mono); color:var(--accent-cyan);">${inc.source_indicator}</div>
        </div>
        <div>
          <div style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">MITRE ATT&CK</div>
          <div style="font-weight:700; color:var(--accent-amber);">${mitre.id}: ${mitre.name} (${mitre.tactic})</div>
        </div>
        <div>
          <div style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Status & Actions</div>
          <div style="font-weight:700; color:var(--accent-green);">${inc.status} (${inc.containment_actions ? inc.containment_actions.length : 0} SOAR Actions)</div>
        </div>
      </div>

      <div>
        <h4 style="font-size:13px; color:#fff; margin-bottom:6px;">Executive Root Cause Analysis</h4>
        <p style="font-size:12px; color:#cbd5e1; background:rgba(0,0,0,0.3); padding:12px; border-radius:6px; border-left:3px solid var(--accent-cyan);">
          ${inc.root_cause_analysis}
        </p>
      </div>

      <div class="cot-container">
        <div class="cot-header">🧠 Autonomous AI Agent Chain-of-Thought (ReAct Loop)</div>
        ${cot.map(step => `
          <div class="cot-step">
            <div class="cot-step-title">STEP ${step.step}: ${step.phase}</div>
            <div class="cot-thought"><strong>Thought:</strong> ${step.thought}</div>
            <div class="cot-action"><strong>Action:</strong> ${step.action} ${step.action_input ? `(${step.action_input})` : ''}</div>
            <div class="cot-obs"><strong>Observation:</strong> ${step.observation}</div>
          </div>
        `).join("")}
      </div>

      <div>
        <h4 style="font-size:13px; color:#fff; margin-bottom:6px;">Recommended Engineering Remediation</h4>
        <div style="font-size:12px; color:var(--text-muted); background:var(--bg-surface); padding:10px; border-radius:6px;">
          ${inc.remediation_guidance}
        </div>
      </div>
    `;

    document.getElementById("investigation-modal").classList.add("open");
  } catch (err) {
    alert("Could not load incident: " + err.message);
  }
}

function closeModal() {
  document.getElementById("investigation-modal").classList.remove("open");
  currentModalIncident = null;
}

async function triggerManualPlaybook() {
  if (!currentModalIncident) return;
  const playbook = prompt("Enter playbook to execute ('block_ip', 'isolate_host', 'revoke_credentials'):", "block_ip");
  if (!playbook) return;

  try {
    const res = await fetch(`${API_BASE}/api/incidents/${currentModalIncident.incident_id}/respond`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ playbook })
    });
    const result = await res.json();
    alert("SOAR Playbook Dispatched:\n" + JSON.stringify(result, null, 2));
    closeModal();
    fetchAllData();
  } catch (err) {
    alert("Playbook execution failed: " + err.message);
  }
}

function exportIncidentReport() {
  if (!currentModalIncident) return;
  const inc = currentModalIncident;
  const md = `# CYBERSECURITY INCIDENT INVESTIGATION REPORT
**Incident ID:** ${inc.incident_id}
**Classification:** ${inc.verdict} (Severity: ${inc.severity})
**Timestamp:** ${inc.timestamp}
**Target Host:** ${inc.target_host}
**Adversary Indicator:** ${inc.source_indicator}

---

## 1. Executive Summary
${inc.executive_summary}

## 2. MITRE ATT&CK Attribution
- **Technique:** ${inc.mitre_technique ? inc.mitre_technique.id + ' - ' + inc.mitre_technique.name : 'N/A'}
- **Tactic:** ${inc.mitre_technique ? inc.mitre_technique.tactic : 'N/A'}
- **Threat Actor:** ${inc.threat_intel ? inc.threat_intel.threat_actor : 'Unattributed'}

## 3. Technical Root Cause
${inc.root_cause_analysis}

## 4. Autonomous SOAR Response Actions Taken
${inc.containment_actions && inc.containment_actions.length > 0 ? JSON.stringify(inc.containment_actions, null, 2) : 'No automated containment actions logged.'}

## 5. Engineering Remediation & Hardening Plan
${inc.remediation_guidance}

---
*Report generated automatically by AISTAR Agentic AI Cybersecurity SOC Analyst.*
`;

  const blob = new Blob([md], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `incident_report_${inc.incident_id}.md`;
  a.click();
}

// --------------------------------------------------------------------------
// 9. Cybersecurity Interactive Data Analytics & Charts
// --------------------------------------------------------------------------
let chartTemporal = null;
let chartSeverity = null;
let chartVectors = null;
let chartMitreRadar = null;
let chartAssets = null;

async function loadAnalytics() {
  try {
    const res = await fetch(`${API_BASE}/api/analytics`);
    if (!res.ok) return;
    const data = await res.json();

    // Check if Chart.js is loaded
    if (typeof Chart !== "undefined") {
      updateTemporalChart(data.temporal_timeline || []);
      updateSeverityChart(data.severity_distribution || []);
      updateVectorsChart(data.threat_vector_distribution || []);
      updateMitreRadarChart(data.mitre_tactic_distribution || []);
      updateAssetsChart(data.target_asset_risk_matrix || []);
    }

    // Render Target Asset Risk Exposure Table
    const assetTbody = document.getElementById("analytics-asset-tbody");
    const assets = data.target_asset_risk_matrix || [];
    if (assetTbody) {
      if (assets.length === 0) {
        assetTbody.innerHTML = `<tr><td colspan="5" class="text-center text-dim">No compromised internal assets.</td></tr>`;
      } else {
        assetTbody.innerHTML = assets.map(a => {
          const sevClass = `sev-${a.max_severity.toLowerCase()}`;
          const isCompromised = a.compromised;
          return `
            <tr>
              <td><strong style="font-family:var(--font-mono); color:#fff;">${a.host}</strong></td>
              <td>${a.incident_count}</td>
              <td><span class="badge-sev ${sevClass}">${a.max_severity}</span></td>
              <td><strong style="color:${a.average_risk > 70 ? 'var(--accent-red)' : 'var(--accent-amber)'}">${a.average_risk}%</strong></td>
              <td>
                <span class="badge-status ${isCompromised ? 'status-open' : 'status-contained'}">
                  ${isCompromised ? 'ATTACK TARGET' : 'NOMINAL'}
                </span>
              </td>
            </tr>
          `;
        }).join("");
      }
    }

    // Render SOAR BI & Operational Metrics
    const soar = data.soar_efficiency || {};
    const summary = data.summary || {};

    const hoursEl = document.getElementById("bi-hours-saved");
    if (hoursEl) hoursEl.textContent = `${soar.analyst_hours_saved_est || 0} hrs`;

    const rateEl = document.getElementById("bi-auto-rate");
    if (rateEl) rateEl.textContent = `${soar.containment_percentage || 100}%`;

    const mttdEl = document.getElementById("bi-mttd");
    if (mttdEl) mttdEl.textContent = `${summary.mean_time_to_detect_sec || 1.4}s`;

    const quarEl = document.getElementById("bi-quarantine-count");
    if (quarEl) quarEl.textContent = summary.active_perimeter_quarantines || 0;

  } catch (err) {
    console.warn("Analytics loading error:", err);
  }
}

// Chart 1: Time Series Area Chart (IST)
function updateTemporalChart(timeline) {
  const ctx = document.getElementById("chart-temporal");
  if (!ctx) return;

  const labels = timeline.map(t => `${t.time} IST`);
  const volumes = timeline.map(t => t.volume);

  if (!chartTemporal) {
    chartTemporal = new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [{
          label: "Telemetry Flow Volume",
          data: volumes,
          borderColor: "#06b6d4",
          backgroundColor: "rgba(6, 182, 212, 0.15)",
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointBackgroundColor: "#06b6d4",
          pointRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#94a3b8", font: { size: 10 } }
          },
          y: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#94a3b8", font: { size: 10 } }
          }
        }
      }
    });
  } else {
    chartTemporal.data.labels = labels;
    chartTemporal.data.datasets[0].data = volumes;
    chartTemporal.update();
  }
}

// Chart 2: Threat Severity Donut Chart
function updateSeverityChart(severities) {
  const ctx = document.getElementById("chart-severity");
  if (!ctx) return;

  const labels = severities.map(s => s.severity);
  const counts = severities.map(s => s.count);

  if (!chartSeverity) {
    chartSeverity = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: counts,
          backgroundColor: ["#ef4444", "#f59e0b", "#3b82f6", "#10b981"],
          borderColor: "#0c1220",
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: {
            position: "right",
            labels: { color: "#cbd5e1", font: { size: 11, family: "Inter" } }
          }
        }
      }
    });
  } else {
    chartSeverity.data.labels = labels;
    chartSeverity.data.datasets[0].data = counts;
    chartSeverity.update();
  }
}

// Chart 3: Horizontal Bar Chart of Attack Vectors
function updateVectorsChart(vectors) {
  const ctx = document.getElementById("chart-vectors");
  if (!ctx) return;

  const labels = vectors.map(v => v.vector.length > 20 ? v.vector.substring(0, 18) + "..." : v.vector);
  const counts = vectors.map(v => v.count);

  if (!chartVectors) {
    chartVectors = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Hits",
          data: counts,
          backgroundColor: "rgba(139, 92, 246, 0.8)",
          borderColor: "#8b5cf6",
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#94a3b8", font: { size: 10 } }
          },
          y: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#e2e8f0", font: { size: 10 } }
          }
        }
      }
    });
  } else {
    chartVectors.data.labels = labels;
    chartVectors.data.datasets[0].data = counts;
    chartVectors.update();
  }
}

// Chart 4: MITRE ATT&CK Tactic Radar Chart
function updateMitreRadarChart(tactics) {
  const ctx = document.getElementById("chart-mitre-radar");
  if (!ctx) return;

  const labels = tactics.map(t => t.tactic);
  const percentages = tactics.map(t => t.percentage);

  if (!chartMitreRadar) {
    chartMitreRadar = new Chart(ctx, {
      type: "radar",
      data: {
        labels: labels,
        datasets: [{
          label: "Threat Exposure %",
          data: percentages,
          backgroundColor: "rgba(6, 182, 212, 0.25)",
          borderColor: "#06b6d4",
          borderWidth: 2,
          pointBackgroundColor: "#10b981"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            angleLines: { color: "rgba(255, 255, 255, 0.1)" },
            grid: { color: "rgba(255, 255, 255, 0.08)" },
            pointLabels: { color: "#94a3b8", font: { size: 9 } },
            ticks: { display: false, backdropColor: "transparent" }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  } else {
    chartMitreRadar.data.labels = labels;
    chartMitreRadar.data.datasets[0].data = percentages;
    chartMitreRadar.update();
  }
}

// Chart 5: Target Asset Vulnerability & Incident Load Grouped Bar Chart
function updateAssetsChart(assets) {
  const ctx = document.getElementById("chart-assets");
  if (!ctx) return;

  const labels = assets.map(a => a.host);
  const incidentCounts = assets.map(a => a.incident_count);
  const riskScores = assets.map(a => a.average_risk);

  if (!chartAssets) {
    chartAssets = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Incident Count",
            data: incidentCounts,
            backgroundColor: "rgba(245, 158, 11, 0.8)",
            borderColor: "#f59e0b",
            borderWidth: 1,
            borderRadius: 4
          },
          {
            label: "Average Risk Score (%)",
            data: riskScores,
            backgroundColor: "rgba(239, 68, 68, 0.8)",
            borderColor: "#ef4444",
            borderWidth: 1,
            borderRadius: 4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: { color: "#cbd5e1", font: { size: 10 } }
          }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#94a3b8", font: { size: 10 } }
          },
          y: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#94a3b8", font: { size: 10 } }
          }
        }
      }
    });
  } else {
    chartAssets.data.labels = labels;
    chartAssets.data.datasets[0].data = incidentCounts;
    chartAssets.data.datasets[1].data = riskScores;
    chartAssets.update();
  }
}


