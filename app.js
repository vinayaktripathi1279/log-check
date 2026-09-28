/**
 * app.js - CyberGuard Web Demo Engine
 * Implements synthetic log generation, regex parsing, sliding window brute-force detection,
 * and dynamic CSV export in the browser.
 */

// Preset Attackers & Legitimate IPs
const ATTACKERS = [
  { ip: "203.0.113.45", attempts: 25, burstMinutes: 3, label: "Critical Attacker" },
  { ip: "198.51.100.89", attempts: 14, burstMinutes: 2.5, label: "High Attacker" },
  { ip: "192.0.2.14",   attempts: 7,  burstMinutes: 1.5, label: "Medium Attacker" }
];

const LEGIT_IPS = [
  "192.168.1.15", "192.168.1.42", "192.168.1.105",
  "10.0.0.12", "10.0.0.55", "172.16.5.20"
];

const VALID_USERS = ["vinay", "ubuntu", "devops", "deploy", "alice", "bob"];
const TARGET_USERS = ["root", "admin", "test", "oracle", "guest", "postgres", "user"];

// Regular expression matching syslog SSH failure lines
const SSH_FAILED_REGEX = /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})/;

// Application State
let currentLogEvents = [];
let analyzedSuspects = [];
let currentFilterSeverity = "ALL";

// Helper: Format Month Day HH:MM:SS
function formatSyslogTimestamp(date) {
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const m = months[date.getMonth()];
  const d = String(date.getDate()).padStart(2, " ");
  const h = String(date.getHours()).padStart(2, "0");
  const min = String(date.getMinutes()).padStart(2, "0");
  const s = String(date.getSeconds()).padStart(2, "0");
  return `${m} ${d} ${h}:${min}:${s}`;
}

// Generate Realistic In-Memory Log Events
function generateLogs() {
  const events = [];
  const baseTime = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
  const hostname = "secure-srv01";
  let pidCounter = 12000;

  // 1. Inject Attacker Bursts
  ATTACKERS.forEach((att, idx) => {
    let t = new Date(baseTime.getTime() + (idx * 3 + 2) * 60 * 60 * 1000);
    for (let i = 0; i < att.attempts; i++) {
      t = new Date(t.getTime() + (Math.floor(Math.random() * 8) + 3) * 1000); // 3-10 sec gap
      const user = TARGET_USERS[Math.floor(Math.random() * TARGET_USERS.length)];
      const port = Math.floor(Math.random() * 30000) + 32000;
      const pid = ++pidCounter;
      const isInvalid = Math.random() > 0.5;
      const msg = isInvalid
        ? `Failed password for invalid user ${user} from ${att.ip} port ${port} ssh2`
        : `Failed password for ${user} from ${att.ip} port ${port} ssh2`;

      events.push({
        timestamp: new Date(t),
        rawTs: formatSyslogTimestamp(t),
        line: `${formatSyslogTimestamp(t)} ${hostname} sshd[${pid}]: ${msg}`,
        type: "failed",
        isAttacker: true,
        ip: att.ip,
        user: user
      });
    }
  });

  // 2. Inject Normal Traffic (~450 lines)
  let normalTime = new Date(baseTime);
  for (let i = 0; i < 450; i++) {
    normalTime = new Date(normalTime.getTime() + (Math.floor(Math.random() * 150) + 20) * 1000);
    const ip = LEGIT_IPS[Math.floor(Math.random() * LEGIT_IPS.length)];
    const user = VALID_USERS[Math.floor(Math.random() * VALID_USERS.length)];
    const port = Math.floor(Math.random() * 20000) + 40000;
    const pid = ++pidCounter;

    const roll = Math.random();
    if (roll < 0.45) {
      // Accepted public key
      events.push({
        timestamp: new Date(normalTime),
        rawTs: formatSyslogTimestamp(normalTime),
        line: `${formatSyslogTimestamp(normalTime)} ${hostname} sshd[${pid}]: Accepted publickey for ${user} from ${ip} port ${port} ssh2: RSA SHA256:7f9a...`,
        type: "success",
        isAttacker: false,
        ip: ip,
        user: user
      });
    } else if (roll < 0.8) {
      // Accepted password
      events.push({
        timestamp: new Date(normalTime),
        rawTs: formatSyslogTimestamp(normalTime),
        line: `${formatSyslogTimestamp(normalTime)} ${hostname} sshd[${pid}]: Accepted password for ${user} from ${ip} port ${port} ssh2`,
        type: "success",
        isAttacker: false,
        ip: ip,
        user: user
      });
    } else {
      // Single typo then success
      events.push({
        timestamp: new Date(normalTime),
        rawTs: formatSyslogTimestamp(normalTime),
        line: `${formatSyslogTimestamp(normalTime)} ${hostname} sshd[${pid}]: Failed password for ${user} from ${ip} port ${port} ssh2`,
        type: "failed",
        isAttacker: false,
        ip: ip,
        user: user
      });
      normalTime = new Date(normalTime.getTime() + 5000);
      events.push({
        timestamp: new Date(normalTime),
        rawTs: formatSyslogTimestamp(normalTime),
        line: `${formatSyslogTimestamp(normalTime)} ${hostname} sshd[${pid + 1}]: Accepted password for ${user} from ${ip} port ${port + 1} ssh2`,
        type: "success",
        isAttacker: false,
        ip: ip,
        user: user
      });
    }
  }

  // Chronological sort
  events.sort((a, b) => a.timestamp - b.timestamp);
  return events;
}

// Sliding Window Detection Algorithm (Identical to analyzer.py)
function detectBruteForce(timestamps, windowMinutes) {
  if (!timestamps.length) return 0;
  let maxBurst = 0;
  const windowMs = windowMinutes * 60 * 1000;

  for (let i = 0; i < timestamps.length; i++) {
    const windowEnd = timestamps[i].getTime() + windowMs;
    let burst = 0;
    for (let j = i; j < timestamps.length; j++) {
      if (timestamps[j].getTime() <= windowEnd) {
        burst++;
      } else {
        break;
      }
    }
    if (burst > maxBurst) maxBurst = burst;
  }
  return maxBurst;
}

// Severity Calculation
function calculateSeverity(failures) {
  if (failures >= 20) return "Critical";
  if (failures >= 10) return "High";
  if (failures >= 5)  return "Medium";
  return "Low";
}

// Core Analysis Engine
function runAnalysis() {
  const threshold = parseInt(document.getElementById("inputThreshold").value) || 5;
  const windowMinutes = parseInt(document.getElementById("inputWindow").value) || 5;

  const failedByIp = {};
  let totalFailures = 0;

  currentLogEvents.forEach(evt => {
    if (evt.type === "failed") {
      totalFailures++;
      if (!failedByIp[evt.ip]) failedByIp[evt.ip] = [];
      failedByIp[evt.ip].push(evt);
    }
  });

  const suspects = [];

  Object.entries(failedByIp).forEach(([ip, events]) => {
    events.sort((a, b) => a.timestamp - b.timestamp);
    const timestamps = events.map(e => e.timestamp);
    const peakBurst = detectBruteForce(timestamps, windowMinutes);

    if (peakBurst >= threshold) {
      const targets = [...new Set(events.map(e => e.user))];
      suspects.push({
        ip: ip,
        failedAttempts: events.length,
        peakBurst: peakBurst,
        firstSeen: events[0].rawTs,
        lastSeen: events[events.length - 1].rawTs,
        targets: targets,
        hasRoot: targets.includes("root"),
        severity: calculateSeverity(events.length)
      });
    }
  });

  const severityRank = { Critical: 3, High: 2, Medium: 1, Low: 0 };
  suspects.sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0) || b.failedAttempts - a.failedAttempts);

  analyzedSuspects = suspects;

  // Update UI Elements
  updateKpis(currentLogEvents.length, totalFailures, suspects);
  renderSuspectsTable();
  renderConsoleStream();
  updateIntelMetrics(suspects);
}

// Update Top KPI Cards
function updateKpis(totalEvents, totalFailures, suspects) {
  document.getElementById("kpiTotalEvents").textContent = totalEvents;
  document.getElementById("kpiFailedLogins").textContent = totalFailures;
  const pct = ((totalFailures / totalEvents) * 100).toFixed(1);
  document.getElementById("kpiFailedPct").textContent = `${pct}% of total volume`;
  document.getElementById("kpiFlaggedIps").textContent = suspects.length;

  const highestBurst = suspects.length ? Math.max(...suspects.map(s => s.peakBurst)) : 0;
  const highestIp = suspects.length ? suspects[0].ip : "None";
  document.getElementById("kpiPeakBurst").innerHTML = `${highestBurst} <span class="unit">/ 5m</span>`;
  document.querySelector(".kpi-card.critical .kpi-sub").textContent = `Top: ${highestIp}`;
}

// Render Table
function renderSuspectsTable() {
  const tbody = document.getElementById("suspectsTableBody");
  tbody.innerHTML = "";

  const filtered = currentFilterSeverity === "ALL"
    ? analyzedSuspects
    : analyzedSuspects.filter(s => s.severity === currentFilterSeverity);

  document.getElementById("tableRecordCount").textContent = `Showing ${filtered.length} Flagged IPs`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted)">No suspects match current threshold or filter.</td></tr>`;
    return;
  }

  filtered.forEach(s => {
    const tr = document.createElement("tr");

    const targetBadges = s.targets.map(u => {
      const cls = u === "root" ? "target-badge root" : "target-badge";
      return `<span class="${cls}">${u}</span>`;
    }).join("");

    tr.innerHTML = `
      <td class="ip-cell">${s.ip}</td>
      <td><strong>${s.failedAttempts}</strong></td>
      <td><span class="badge badge-info">${s.peakBurst} / window</span></td>
      <td class="ts-cell">${s.firstSeen}</td>
      <td class="ts-cell">${s.lastSeen}</td>
      <td>${targetBadges}</td>
      <td><span class="badge badge-${s.severity.toLowerCase()}">${s.severity}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// Update Intel Breakdown
function updateIntelMetrics(suspects) {
  const total = suspects.length || 1;
  const critical = suspects.filter(s => s.severity === "Critical").length;
  const high = suspects.filter(s => s.severity === "High").length;
  const medium = suspects.filter(s => s.severity === "Medium").length;

  document.getElementById("countCritical").textContent = `${critical} IP (${Math.round((critical / total) * 100)}%)`;
  document.getElementById("countHigh").textContent = `${high} IP (${Math.round((high / total) * 100)}%)`;
  document.getElementById("countMedium").textContent = `${medium} IP (${Math.round((medium / total) * 100)}%)`;
}

// Render Raw Log Stream Screen
function renderConsoleStream() {
  const screen = document.getElementById("logStreamScreen");
  const onlyFailures = document.getElementById("checkOnlyFailures").checked;
  screen.innerHTML = "";

  const displayList = onlyFailures
    ? currentLogEvents.filter(e => e.type === "failed")
    : currentLogEvents;

  document.getElementById("logCounterDisplay").textContent = `Showing ${displayList.length} entries`;

  // Render recent 150 items to keep DOM performant
  displayList.slice(-150).forEach(evt => {
    const div = document.createElement("div");
    let cls = "log-line";
    if (evt.isAttacker) cls += " attacker";
    else if (evt.type === "failed") cls += " fail";
    else cls += " ok";
    div.className = cls;
    div.textContent = evt.line;
    screen.appendChild(div);
  });
}

// Export CSV Functionality
function exportCsv() {
  if (!analyzedSuspects.length) {
    alert("No flagged suspects to export!");
    return;
  }

  let csvContent = "IP,failed attempts,first seen,last seen,severity\r\n";
  analyzedSuspects.forEach(s => {
    csvContent += `${s.ip},${s.failedAttempts},${s.firstSeen},${s.lastSeen},${s.severity}\r\n`;
  });

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", "report.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// Event Listeners
document.getElementById("btnExportCsv").addEventListener("click", exportCsv);
document.getElementById("btnRunAnalysis").addEventListener("click", runAnalysis);
document.getElementById("inputThreshold").addEventListener("input", runAnalysis);
document.getElementById("inputWindow").addEventListener("input", runAnalysis);
document.getElementById("checkOnlyFailures").addEventListener("change", renderConsoleStream);

document.getElementById("btnRegenerateLogs").addEventListener("click", () => {
  currentLogEvents = generateLogs();
  runAnalysis();
});

document.querySelectorAll("#severityFilterGroup .pill").forEach(btn => {
  btn.addEventListener("click", (e) => {
    document.querySelectorAll("#severityFilterGroup .pill").forEach(p => p.classList.remove("active"));
    e.target.classList.add("active");
    currentFilterSeverity = e.target.dataset.severity;
    renderSuspectsTable();
  });
});

// Initialization
currentLogEvents = generateLogs();
runAnalysis();
