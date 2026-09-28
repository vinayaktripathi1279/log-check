/**
 * app.js - CyberGuard Web Demo Engine & Enterprise Audit Hub
 * Implements:
 *   - Raw log file upload & parsing
 *   - Sliding window brute-force detection
 *   - Role-Based Access Control (Admin vs SOC Analyst)
 *   - Centralized Admin Security Audit Hub with cross-team inspection & CSV export
 *   - Live System Audit Trail logging (system_audit.log)
 */

// Users & Roles
const USERS = {
  "vinay_admin": {
    id: "vinay_admin",
    name: "Vinay Tripathi",
    role: "Super Administrator",
    avatar: "V",
    isAdmin: true
  },
  "sarah_soc": {
    id: "sarah_soc",
    name: "Sarah Jenkins",
    role: "Senior SOC Analyst",
    avatar: "S",
    isAdmin: false
  },
  "rahul_devops": {
    id: "rahul_devops",
    name: "Rahul Sharma",
    role: "Cloud Infrastructure Lead",
    avatar: "R",
    isAdmin: false
  }
};

let currentUser = USERS["vinay_admin"];

// Default Seed Audit Reports
const DEFAULT_AUDIT_REPORTS = [
  {
    id: "AUD-2026-0891",
    submitter: "Sarah Jenkins",
    submitterId: "sarah_soc",
    server: "production-bastion-01",
    timestamp: "2026-09-28 14:15 UTC",
    lineCount: 49,
    threatCount: 3,
    peakSeverity: "Critical",
    status: "Incident Escalated",
    suspects: [
      { ip: "185.220.101.5", failed_attempts: 22, burst_count: 22, first_seen: "Sep 28 10:01:05", last_seen: "Sep 28 10:02:40", severity: "Critical" },
      { ip: "45.33.32.156", failed_attempts: 12, burst_count: 12, first_seen: "Sep 28 10:05:10", last_seen: "Sep 28 10:06:05", severity: "High" },
      { ip: "194.26.29.112", failed_attempts: 6, burst_count: 6, first_seen: "Sep 28 10:12:00", last_seen: "Sep 28 10:12:38", severity: "Medium" }
    ],
    rawLog: `Sep 28 10:01:05 production-srv sshd[20105]: Failed password for root from 185.220.101.5 port 41001 ssh2
Sep 28 10:01:09 production-srv sshd[20106]: Failed password for root from 185.220.101.5 port 41002 ssh2
Sep 28 10:01:14 production-srv sshd[20107]: Failed password for admin from 185.220.101.5 port 41003 ssh2
Sep 28 10:05:10 production-srv sshd[20140]: Failed password for root from 45.33.32.156 port 38101 ssh2
Sep 28 10:12:00 production-srv sshd[20170]: Failed password for admin from 194.26.29.112 port 52101 ssh2`
  },
  {
    id: "AUD-2026-0890",
    submitter: "Rahul Sharma",
    submitterId: "rahul_devops",
    server: "k8s-ingress-cluster-ap-south",
    timestamp: "2026-09-28 12:40 UTC",
    lineCount: 180,
    threatCount: 2,
    peakSeverity: "High",
    status: "Firewall Rule Applied",
    suspects: [
      { ip: "198.51.100.89", failed_attempts: 14, burst_count: 14, first_seen: "Sep 28 11:20:00", last_seen: "Sep 28 11:22:45", severity: "High" },
      { ip: "192.0.2.14", failed_attempts: 7, burst_count: 7, first_seen: "Sep 28 11:35:10", last_seen: "Sep 28 11:36:20", severity: "Medium" }
    ],
    rawLog: `Sep 28 11:20:00 k8s-ingress sshd[4401]: Failed password for root from 198.51.100.89 port 52100 ssh2
Sep 28 11:20:12 k8s-ingress sshd[4402]: Failed password for deploy from 198.51.100.89 port 52101 ssh2
Sep 28 11:35:10 k8s-ingress sshd[4410]: Failed password for admin from 192.0.2.14 port 43010 ssh2`
  },
  {
    id: "AUD-2026-0889",
    submitter: "Alex Chen (Intern)",
    submitterId: "alex_intern",
    server: "staging-api-server",
    timestamp: "2026-09-27 18:22 UTC",
    lineCount: 95,
    threatCount: 1,
    peakSeverity: "Medium",
    status: "Under Triage",
    suspects: [
      { ip: "192.0.2.77", failed_attempts: 6, burst_count: 6, first_seen: "Sep 27 18:10:04", last_seen: "Sep 27 18:11:15", severity: "Medium" }
    ],
    rawLog: `Sep 27 18:10:04 staging-api sshd[102]: Failed password for ubuntu from 192.0.2.77 port 39100 ssh2
Sep 27 18:10:15 staging-api sshd[103]: Failed password for ubuntu from 192.0.2.77 port 39101 ssh2`
  },
  {
    id: "AUD-2026-0888",
    submitter: "DevSecOps Bot",
    submitterId: "bot",
    server: "db-secondary-replica",
    timestamp: "2026-09-27 09:10 UTC",
    lineCount: 220,
    threatCount: 0,
    peakSeverity: "Low",
    status: "Resolved",
    suspects: [
      { ip: "192.168.1.15", failed_attempts: 2, burst_count: 1, first_seen: "Sep 27 09:05:00", last_seen: "Sep 27 09:05:12", severity: "Low" }
    ],
    rawLog: `Sep 27 09:05:00 db-replica sshd[501]: Failed password for vinay from 192.168.1.15 port 41200 ssh2
Sep 27 09:05:12 db-replica sshd[502]: Accepted password for vinay from 192.168.1.15 port 41201 ssh2`
  }
];

// Persistent Reports in localStorage
let auditReports = [];
try {
  const stored = localStorage.getItem("cyberguard_audit_reports");
  auditReports = stored ? JSON.parse(stored) : [...DEFAULT_AUDIT_REPORTS];
} catch (e) {
  auditReports = [...DEFAULT_AUDIT_REPORTS];
}

function saveAuditReports() {
  try {
    localStorage.setItem("cyberguard_audit_reports", JSON.stringify(auditReports));
  } catch (e) {}
}

// System Audit Trail (system_audit.log)
let systemAuditLogs = [];
const DEFAULT_SYSTEM_AUDIT_TRAIL = [
  `2026-09-28 14:10:05 UTC [AUDIT] USER="sarah_soc" ROLE="Senior SOC Analyst" ACTION="USER_LOGIN" RESOURCE="session_auth" STATUS="SUCCESS" DETAILS="Logged in from IP 192.168.1.42"`,
  `2026-09-28 14:12:30 UTC [AUDIT] USER="sarah_soc" ROLE="Senior SOC Analyst" ACTION="FILE_INGEST" RESOURCE="production-bastion.log" STATUS="SUCCESS" DETAILS="Ingested 49 lines, 42 failures"`,
  `2026-09-28 14:13:12 UTC [WARN]  USER="sarah_soc" ROLE="Senior SOC Analyst" ACTION="THREAT_ANALYSIS" RESOURCE="5_in_5m_rule" STATUS="ALERT" DETAILS="Detected 3 brute-force attackers (Peak: Critical)"`,
  `2026-09-28 14:15:20 UTC [AUDIT] USER="sarah_soc" ROLE="Senior SOC Analyst" ACTION="AUDIT_SUBMIT" RESOURCE="AUD-2026-0891" STATUS="SUCCESS" DETAILS="Created audit report for server: production-bastion-01"`,
  `2026-09-28 14:20:00 UTC [AUDIT] USER="rahul_devops" ROLE="Cloud Infrastructure Lead" ACTION="USER_LOGIN" RESOURCE="session_auth" STATUS="SUCCESS" DETAILS="Logged in from IP 10.0.0.12"`,
  `2026-09-28 14:22:15 UTC [AUDIT] USER="rahul_devops" ROLE="Cloud Infrastructure Lead" ACTION="FILE_INGEST" RESOURCE="k8s-ingress.log" STATUS="SUCCESS" DETAILS="Ingested 180 lines"`,
  `2026-09-28 14:24:45 UTC [AUDIT] USER="rahul_devops" ROLE="Cloud Infrastructure Lead" ACTION="AUDIT_SUBMIT" RESOURCE="AUD-2026-0890" STATUS="SUCCESS" DETAILS="Created audit report for cluster: k8s-ingress-cluster-ap-south"`,
  `2026-09-28 14:30:10 UTC [AUDIT] USER="vinay_admin" ROLE="Super Administrator" ACTION="USER_LOGIN" RESOURCE="session_auth" STATUS="SUCCESS" DETAILS="Administrator session initialized"`,
  `2026-09-28 14:32:05 UTC [AUDIT] USER="vinay_admin" ROLE="Super Administrator" ACTION="AUDIT_INSPECT" RESOURCE="AUD-2026-0891" STATUS="SUCCESS" DETAILS="Inspected Sarah Jenkins' raw log submission"`,
  `2026-09-28 14:33:20 UTC [AUDIT] USER="vinay_admin" ROLE="Super Administrator" ACTION="REPORT_DOWNLOAD" RESOURCE="AUD-2026-0891.csv" STATUS="SUCCESS" DETAILS="Downloaded incident triage report CSV"`
];

try {
  const storedLogs = localStorage.getItem("cyberguard_system_audit_logs");
  systemAuditLogs = storedLogs ? JSON.parse(storedLogs) : [...DEFAULT_SYSTEM_AUDIT_TRAIL];
} catch (e) {
  systemAuditLogs = [...DEFAULT_SYSTEM_AUDIT_TRAIL];
}

function recordAuditLog(action, resource, status = "SUCCESS", details = "") {
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const sev = status === "ALERT" ? "WARN " : "AUDIT";
  const entry = `${now} [${sev}] USER="${currentUser.id}" ROLE="${currentUser.role}" ACTION="${action}" RESOURCE="${resource}" STATUS="${status}" DETAILS="${details}"`;
  systemAuditLogs.unshift(entry);
  try {
    localStorage.setItem("cyberguard_system_audit_logs", JSON.stringify(systemAuditLogs));
  } catch (e) {}
  renderSystemAuditScreen();
}

function renderSystemAuditScreen() {
  const screen = document.getElementById("systemAuditLogScreen");
  if (screen) {
    screen.textContent = systemAuditLogs.join("\n");
  }
}

// Built-in Sample Attack Scenario
const SAMPLE_ATTACK_TEXT = `Sep 28 10:00:01 production-srv sshd[20101]: Accepted publickey for vinay from 192.168.1.50 port 51234 ssh2: RSA SHA256:4a8b...
Sep 28 10:00:15 production-srv sshd[20102]: Accepted publickey for deploy from 10.0.0.12 port 49120 ssh2: RSA SHA256:7c9d...
Sep 28 10:01:05 production-srv sshd[20105]: Failed password for root from 185.220.101.5 port 41001 ssh2
Sep 28 10:01:09 production-srv sshd[20106]: Failed password for root from 185.220.101.5 port 41002 ssh2
Sep 28 10:01:14 production-srv sshd[20107]: Failed password for admin from 185.220.101.5 port 41003 ssh2
Sep 28 10:01:18 production-srv sshd[20108]: Failed password for invalid user test from 185.220.101.5 port 41004 ssh2
Sep 28 10:01:23 production-srv sshd[20109]: Failed password for invalid user guest from 185.220.101.5 port 41005 ssh2
Sep 28 10:01:27 production-srv sshd[20110]: Failed password for oracle from 185.220.101.5 port 41006 ssh2
Sep 28 10:01:31 production-srv sshd[20111]: Failed password for postgres from 185.220.101.5 port 41007 ssh2
Sep 28 10:01:36 production-srv sshd[20112]: Failed password for root from 185.220.101.5 port 41008 ssh2
Sep 28 10:01:40 production-srv sshd[20113]: Failed password for root from 185.220.101.5 port 41009 ssh2
Sep 28 10:01:45 production-srv sshd[20114]: Failed password for admin from 185.220.101.5 port 41010 ssh2
Sep 28 10:01:49 production-srv sshd[20115]: Failed password for invalid user devops from 185.220.101.5 port 41011 ssh2
Sep 28 10:01:54 production-srv sshd[20116]: Failed password for root from 185.220.101.5 port 41012 ssh2
Sep 28 10:01:59 production-srv sshd[20117]: Failed password for root from 185.220.101.5 port 41013 ssh2
Sep 28 10:02:04 production-srv sshd[20118]: Failed password for admin from 185.220.101.5 port 41014 ssh2
Sep 28 10:02:08 production-srv sshd[20119]: Failed password for user from 185.220.101.5 port 41015 ssh2
Sep 28 10:02:13 production-srv sshd[20120]: Failed password for ftpuser from 185.220.101.5 port 41016 ssh2
Sep 28 10:02:17 production-srv sshd[20121]: Failed password for root from 185.220.101.5 port 41017 ssh2
Sep 28 10:02:22 production-srv sshd[20122]: Failed password for root from 185.220.101.5 port 41018 ssh2
Sep 28 10:02:26 production-srv sshd[20123]: Failed password for admin from 185.220.101.5 port 41019 ssh2
Sep 28 10:02:30 production-srv sshd[20124]: Failed password for root from 185.220.101.5 port 41020 ssh2
Sep 28 10:02:35 production-srv sshd[20125]: Failed password for root from 185.220.101.5 port 41021 ssh2
Sep 28 10:02:40 production-srv sshd[20126]: Failed password for invalid user support from 185.220.101.5 port 41022 ssh2
Sep 28 10:03:00 production-srv sshd[20130]: Accepted password for alice from 192.168.1.100 port 55120 ssh2
Sep 28 10:05:10 production-srv sshd[20140]: Failed password for root from 45.33.32.156 port 38101 ssh2
Sep 28 10:05:15 production-srv sshd[20141]: Failed password for root from 45.33.32.156 port 38102 ssh2
Sep 28 10:05:20 production-srv sshd[20142]: Failed password for root from 45.33.32.156 port 38103 ssh2
Sep 28 10:05:25 production-srv sshd[20143]: Failed password for admin from 45.33.32.156 port 38104 ssh2
Sep 28 10:05:30 production-srv sshd[20144]: Failed password for admin from 45.33.32.156 port 38105 ssh2
Sep 28 10:05:35 production-srv sshd[20145]: Failed password for service from 45.33.32.156 port 38106 ssh2
Sep 28 10:05:40 production-srv sshd[20146]: Failed password for root from 45.33.32.156 port 38107 ssh2
Sep 28 10:05:45 production-srv sshd[20147]: Failed password for root from 45.33.32.156 port 38108 ssh2
Sep 28 10:05:50 production-srv sshd[20148]: Failed password for test from 45.33.32.156 port 38109 ssh2
Sep 28 10:05:55 production-srv sshd[20149]: Failed password for ubuntu from 45.33.32.156 port 38110 ssh2
Sep 28 10:06:00 production-srv sshd[20150]: Failed password for deploy from 45.33.32.156 port 38111 ssh2
Sep 28 10:06:05 production-srv sshd[20151]: Failed password for root from 45.33.32.156 port 38112 ssh2
Sep 28 10:08:20 production-srv sshd[20160]: Failed password for bob from 192.168.1.75 port 42100 ssh2
Sep 28 10:08:26 production-srv sshd[20161]: Accepted password for bob from 192.168.1.75 port 42101 ssh2
Sep 28 10:12:00 production-srv sshd[20170]: Failed password for admin from 194.26.29.112 port 52101 ssh2
Sep 28 10:12:08 production-srv sshd[20171]: Failed password for admin from 194.26.29.112 port 52102 ssh2
Sep 28 10:12:15 production-srv sshd[20172]: Failed password for root from 194.26.29.112 port 52103 ssh2
Sep 28 10:12:22 production-srv sshd[20173]: Failed password for root from 194.26.29.112 port 52104 ssh2
Sep 28 10:12:30 production-srv sshd[20174]: Failed password for oracle from 194.26.29.112 port 52105 ssh2
Sep 28 10:12:38 production-srv sshd[20175]: Failed password for test from 194.26.29.112 port 52106 ssh2
Sep 28 10:15:00 production-srv sshd[20180]: Accepted publickey for devops from 10.0.0.55 port 48999 ssh2: RSA SHA256:91aa...
Sep 28 10:20:10 production-srv sshd[20190]: Failed password for vinay from 192.168.1.15 port 39110 ssh2
Sep 28 10:20:16 production-srv sshd[20191]: Accepted password for vinay from 192.168.1.15 port 39111 ssh2`;

// Regex matching
const SSH_FAILED_REGEX = /([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?).*?sshd\[\d+\]:\s+Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})/;
const SSH_SUCCESS_REGEX = /([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?).*?sshd\[\d+\]:\s+Accepted (?:password|publickey) for\s+(\S+)\s+from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})/;

// State
let currentLogEvents = [];
let analyzedSuspects = [];
let currentFilterSeverity = "ALL";
let currentFileName = "sample_attack.log";
let currentRawText = SAMPLE_ATTACK_TEXT;
let activeAuditFilter = "ALL";
let currentInspectedAudit = null;

// Helpers
function showNotification(message, type = "success") {
  const banner = document.getElementById("notifBanner");
  const icon = document.getElementById("notifIcon");
  const text = document.getElementById("notifText");
  text.textContent = message;
  if (type === "warning") {
    banner.className = "notification-banner alert-warning";
    icon.textContent = "⚠️";
  } else {
    banner.className = "notification-banner";
    icon.textContent = "✅";
  }
}

function parseTimestamp(tsStr) {
  const currentYear = new Date().getFullYear();
  const syslogMatch = tsStr.match(/^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (syslogMatch) {
    const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const month = months[syslogMatch[1]];
    const day = parseInt(syslogMatch[2], 10);
    const hour = parseInt(syslogMatch[3], 10);
    const min = parseInt(syslogMatch[4], 10);
    const sec = parseInt(syslogMatch[5], 10);
    return new Date(currentYear, month, day, hour, min, sec);
  }
  const parsed = new Date(tsStr);
  return isNaN(parsed.getTime()) ? new Date() : parsed;
}

function parseRawLogText(content, fileName) {
  currentRawText = content;
  const lines = content.split(/\r?\n/);
  const events = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const failMatch = line.match(SSH_FAILED_REGEX);
    if (failMatch) {
      events.push({
        timestamp: parseTimestamp(failMatch[1]),
        rawTs: failMatch[1],
        line: line,
        type: "failed",
        isAttacker: false,
        ip: failMatch[3],
        user: failMatch[2]
      });
      continue;
    }

    const successMatch = line.match(SSH_SUCCESS_REGEX);
    if (successMatch) {
      events.push({
        timestamp: parseTimestamp(successMatch[1]),
        rawTs: successMatch[1],
        line: line,
        type: "success",
        isAttacker: false,
        ip: successMatch[3],
        user: successMatch[2]
      });
      continue;
    }

    events.push({
      timestamp: new Date(),
      rawTs: "syslog",
      line: line,
      type: "other",
      isAttacker: false,
      ip: null,
      user: null
    });
  }

  currentFileName = fileName || "uploaded-auth.log";
  document.getElementById("activeLogBadge").textContent = `Active: ${currentFileName} (${events.length} lines)`;
  return events;
}

function detectBruteForce(timestamps, windowMinutes) {
  if (!timestamps.length) return 0;
  let maxBurst = 0;
  const windowMs = windowMinutes * 60 * 1000;

  for (let i = 0; i < timestamps.length; i++) {
    const windowEnd = timestamps[i].getTime() + windowMs;
    let burst = 0;
    for (let j = i; j < timestamps.length; j++) {
      if (timestamps[j].getTime() <= windowEnd) burst++;
      else break;
    }
    if (burst > maxBurst) maxBurst = burst;
  }
  return maxBurst;
}

function calculateSeverity(failures) {
  if (failures >= 20) return "Critical";
  if (failures >= 10) return "High";
  if (failures >= 5)  return "Medium";
  return "Low";
}

function runAnalysis(autoScroll = false) {
  const threshold = parseInt(document.getElementById("inputThreshold").value) || 5;
  const windowMinutes = parseInt(document.getElementById("inputWindow").value) || 5;
  document.getElementById("activeRuleBadge").textContent = `Rule: ≥ ${threshold} Failures / ${windowMinutes} Minutes`;

  const failedByIp = {};
  let totalFailures = 0;

  currentLogEvents.forEach(evt => {
    if (evt.type === "failed" && evt.ip) {
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

    if (peakBurst >= threshold || threshold <= 1) {
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

  updateKpis(currentLogEvents.length, totalFailures, suspects);
  renderSuspectsTable();
  renderConsoleStream();
  updateIntelMetrics(suspects);

  document.querySelectorAll("#severityFilterGroup .pill").forEach(pill => {
    const sev = pill.dataset.severity;
    if (sev === "ALL") {
      pill.textContent = `All (${suspects.length})`;
    } else {
      const count = suspects.filter(s => s.severity === sev).length;
      pill.textContent = `${sev} (${count})`;
    }
  });

  if (autoScroll) {
    const el = document.getElementById("resultsSection");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function updateKpis(totalEvents, totalFailures, suspects) {
  document.getElementById("kpiTotalEvents").textContent = totalEvents;
  document.getElementById("kpiFailedLogins").textContent = totalFailures;
  const pct = totalEvents > 0 ? ((totalFailures / totalEvents) * 100).toFixed(1) : 0;
  document.getElementById("kpiFailedPct").textContent = `${pct}% of total volume`;
  document.getElementById("kpiFlaggedIps").textContent = suspects.length;

  const highestBurst = suspects.length ? Math.max(...suspects.map(s => s.peakBurst)) : 0;
  const highestIp = suspects.length ? suspects[0].ip : "None";
  document.getElementById("kpiPeakBurst").innerHTML = `${highestBurst} <span class="unit">/ window</span>`;
  document.getElementById("kpiPeakIp").textContent = `Top: ${highestIp}`;
}

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

function updateIntelMetrics(suspects) {
  const total = suspects.length || 1;
  const critical = suspects.filter(s => s.severity === "Critical").length;
  const high = suspects.filter(s => s.severity === "High").length;
  const medium = suspects.filter(s => s.severity === "Medium").length;
  const low = suspects.filter(s => s.severity === "Low").length;

  document.getElementById("countCritical").textContent = `${critical} IP (${Math.round((critical / total) * 100)}%)`;
  document.getElementById("countHigh").textContent = `${high} IP (${Math.round((high / total) * 100)}%)`;
  document.getElementById("countMedium").textContent = `${medium} IP (${Math.round((medium / total) * 100)}%)`;
  document.getElementById("countLow").textContent = `${low} IP (${Math.round((low / total) * 100)}%)`;

  document.getElementById("barCritical").style.width = `${Math.round((critical / total) * 100)}%`;
  document.getElementById("barHigh").style.width = `${Math.round((high / total) * 100)}%`;
  document.getElementById("barMedium").style.width = `${Math.round((medium / total) * 100)}%`;
  document.getElementById("barLow").style.width = `${Math.round((low / total) * 100)}%`;

  const topAttacker = suspects.length ? suspects[0] : null;
  const mitigationList = document.getElementById("mitigationList");
  if (topAttacker) {
    mitigationList.innerHTML = `
      <li><strong>Immediate Null-Route:</strong> Block <code>${topAttacker.ip}</code> (Peak attacker).</li>
      <li><strong>Targeted Accounts:</strong> ${topAttacker.targets.map(t => `<code>${t}</code>`).join(", ")}.</li>
      <li><strong>Enforce Key-Only:</strong> Disable password login in <code>sshd_config</code>.</li>
    `;
  }
}

function renderConsoleStream() {
  const screen = document.getElementById("logStreamScreen");
  const onlyFailures = document.getElementById("checkOnlyFailures").checked;
  screen.innerHTML = "";

  const displayList = onlyFailures
    ? currentLogEvents.filter(e => e.type === "failed")
    : currentLogEvents;

  document.getElementById("logCounterDisplay").textContent = `Showing ${displayList.length} entries`;

  displayList.slice(-200).forEach(evt => {
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

function exportCsv(data = analyzedSuspects, filename = "report.csv") {
  if (!data.length) {
    alert("No flagged suspects to export!");
    return;
  }
  let csvContent = "IP,failed attempts,first seen,last seen,severity\r\n";
  data.forEach(s => {
    const attempts = s.failedAttempts || s.failed_attempts;
    const firstSeen = s.firstSeen || s.first_seen;
    const lastSeen = s.lastSeen || s.last_seen;
    csvContent += `${s.ip},${attempts},${firstSeen},${lastSeen},${s.severity}\r\n`;
  });
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  recordAuditLog("REPORT_DOWNLOAD", filename, "SUCCESS", `Downloaded ${data.length} records`);
}

// ==========================================
// ADMIN & MULTI-USER AUDIT HUB
// ==========================================
function renderAuditHub() {
  const tbody = document.getElementById("auditReportsTableBody");
  tbody.innerHTML = "";

  const titleEl = document.getElementById("auditHubTitle");
  const descEl = document.getElementById("auditHubDesc");
  const badgeEl = document.getElementById("auditStatsBadge");

  // Filter based on User Role: Admin sees all, Non-Admin sees only their own!
  let accessibleReports = currentUser.isAdmin
    ? [...auditReports]
    : auditReports.filter(r => r.submitterId === currentUser.id);

  if (currentUser.isAdmin) {
    titleEl.textContent = "👑 Enterprise Security Audit Repository (All Teams)";
    descEl.textContent = "Super Administrator View: You can inspect any analyst's submitted logs, review incidents, and download reports.";
    badgeEl.textContent = `Admin Mode: ${accessibleReports.length} Total Submissions`;
  } else {
    titleEl.textContent = `📁 My Submitted Security Audits (${currentUser.name})`;
    descEl.textContent = `Analyst View: Showing reports submitted by you. Sign in as Admin to review reports across all company servers.`;
    badgeEl.textContent = `${accessibleReports.length} Personal Submissions`;
  }

  document.getElementById("auditReportCounter").textContent = accessibleReports.length;

  let list = [...accessibleReports];

  // Search filter
  const query = document.getElementById("inputAuditSearch").value.toLowerCase().trim();
  if (query) {
    list = list.filter(r =>
      r.submitter.toLowerCase().includes(query) ||
      r.server.toLowerCase().includes(query) ||
      r.id.toLowerCase().includes(query) ||
      r.suspects.some(s => s.ip.includes(query))
    );
  }

  // Tag filter
  if (activeAuditFilter !== "ALL") {
    if (activeAuditFilter === "Resolved") {
      list = list.filter(r => r.status === "Resolved");
    } else {
      list = list.filter(r => r.peakSeverity === activeAuditFilter);
    }
  }

  if (list.length === 0) {
    const emptyMsg = currentUser.isAdmin
      ? "No audit reports match your search criteria."
      : `You (${currentUser.name}) haven't submitted any audits yet. Run an analysis and click 'Save to Audit Hub', or sign in as Admin to see all reports.`;
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 2.5rem; color: var(--text-muted)">${emptyMsg}</td></tr>`;
    return;
  }

  list.forEach(rep => {
    const tr = document.createElement("tr");
    const sevBadge = `<span class="badge badge-${rep.peakSeverity.toLowerCase()}">${rep.peakSeverity}</span>`;
    const statusBadge = rep.status === "Resolved"
      ? `<span class="badge badge-success">Resolved</span>`
      : rep.status === "Incident Escalated"
      ? `<span class="badge badge-critical">Escalated</span>`
      : `<span class="badge badge-high">${rep.status}</span>`;

    tr.innerHTML = `
      <td><strong>${rep.id}</strong></td>
      <td>
        <strong>${rep.submitter}</strong>
        <span style="display:block; font-size: 0.7rem; color: var(--text-muted)">${rep.timestamp}</span>
      </td>
      <td><code>${rep.server}</code></td>
      <td>${rep.lineCount} lines</td>
      <td><strong>${rep.threatCount} Flagged</strong></td>
      <td>${sevBadge}</td>
      <td>${statusBadge}</td>
      <td>
        <div style="display:flex; gap: 0.35rem;">
          <button class="btn btn-xs btn-outline btn-inspect" data-id="${rep.id}">Inspect Logs</button>
          <button class="btn btn-xs btn-primary btn-download-csv" data-id="${rep.id}">Download CSV</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Attach inspection handlers
  document.querySelectorAll(".btn-inspect").forEach(btn => {
    btn.addEventListener("click", () => inspectAuditReport(btn.dataset.id));
  });

  document.querySelectorAll(".btn-download-csv").forEach(btn => {
    btn.addEventListener("click", () => {
      const rep = auditReports.find(r => r.id === btn.dataset.id);
      if (rep) {
        exportCsv(rep.suspects, `${rep.id}_${rep.server}_report.csv`);
        recordAuditLog("REPORT_DOWNLOAD", `${rep.id}.csv`, "SUCCESS", `Exported audit ${rep.id} submitted by ${rep.submitter}`);
      }
    });
  });
}

function inspectAuditReport(reportId) {
  const rep = auditReports.find(r => r.id === reportId);
  if (!rep) return;
  currentInspectedAudit = rep;

  const drawer = document.getElementById("auditDetailDrawer");
  drawer.style.display = "block";

  document.getElementById("drawerTitle").textContent = `Inspecting Audit: ${rep.id} (${rep.server})`;
  document.getElementById("drawerSubmitter").textContent = `${rep.submitter} (${rep.submitterId})`;
  document.getElementById("drawerServer").textContent = rep.server;
  document.getElementById("drawerTime").textContent = rep.timestamp;
  document.getElementById("drawerStatus").textContent = rep.status;
  document.getElementById("drawerLogContent").textContent = rep.rawLog;

  recordAuditLog("AUDIT_INSPECT", rep.id, "SUCCESS", `Inspected raw logs submitted by ${rep.submitter} for ${rep.server}`);
  drawer.scrollIntoView({ behavior: "smooth", block: "start" });
}

function saveCurrentToAuditHub() {
  if (!analyzedSuspects.length && currentLogEvents.length === 0) {
    alert("Please analyze or upload a log file first!");
    return;
  }

  const serverName = prompt("Enter Server / Cluster Identifier for this Audit Report:", "prod-bastion-gateway") || "unnamed-server";
  const newId = `AUD-2026-0${Math.floor(100 + Math.random() * 900)}`;
  const peakSev = analyzedSuspects.length ? analyzedSuspects[0].severity : "Low";

  const newReport = {
    id: newId,
    submitter: currentUser.name,
    submitterId: currentUser.id,
    server: serverName,
    timestamp: new Date().toLocaleString(),
    lineCount: currentLogEvents.length,
    threatCount: analyzedSuspects.length,
    peakSeverity: peakSev,
    status: peakSev === "Critical" ? "Incident Escalated" : "Under Triage",
    suspects: analyzedSuspects.map(s => ({
      ip: s.ip,
      failed_attempts: s.failedAttempts,
      burst_count: s.peakBurst,
      first_seen: s.firstSeen,
      last_seen: s.lastSeen,
      severity: s.severity
    })),
    rawLog: currentRawText.slice(0, 5000)
  };

  auditReports.unshift(newReport);
  saveAuditReports();

  recordAuditLog("AUDIT_SUBMIT", newId, "SUCCESS", `Submitted new security audit for ${serverName} with ${analyzedSuspects.length} threats`);

  showNotification(`✅ Successfully saved and submitted report ${newId} to Audit Hub!`, "success");
  switchToTab("AUDIT_HUB");
}

function switchToTab(tabName) {
  const viewAnalyzer = document.getElementById("viewAnalyzer");
  const viewAuditHub = document.getElementById("viewAuditHub");
  const viewAuditTrail = document.getElementById("viewAuditTrail");

  const btnAnalyzer = document.getElementById("tabBtnAnalyzer");
  const btnAuditHub = document.getElementById("tabBtnAuditHub");
  const btnAuditTrail = document.getElementById("tabBtnAuditTrail");

  [viewAnalyzer, viewAuditHub, viewAuditTrail].forEach(el => el.style.display = "none");
  [btnAnalyzer, btnAuditHub, btnAuditTrail].forEach(el => el.classList.remove("active"));

  if (tabName === "ANALYZER") {
    viewAnalyzer.style.display = "flex";
    btnAnalyzer.classList.add("active");
  } else if (tabName === "AUDIT_HUB") {
    viewAuditHub.style.display = "flex";
    btnAuditHub.classList.add("active");
    renderAuditHub();
  } else if (tabName === "AUDIT_TRAIL") {
    viewAuditTrail.style.display = "flex";
    btnAuditTrail.classList.add("active");
    renderSystemAuditScreen();
  }
}

// User Management & Modal Handlers
function openRoleModal() {
  const modal = document.getElementById("roleModal");
  if (modal) {
    modal.classList.add("active");
    const input = document.getElementById("inputCustomUser");
    if (input) setTimeout(() => input.focus(), 150);
  }
}

function closeRoleModal() {
  const modal = document.getElementById("roleModal");
  if (modal) {
    modal.classList.remove("active");
  }
}

function setCurrentUser(userKey, customObj = null) {
  if (customObj) {
    currentUser = customObj;
  } else if (USERS[userKey]) {
    currentUser = USERS[userKey];
  } else {
    currentUser = {
      id: userKey,
      name: userKey,
      role: "Security Analyst",
      avatar: userKey.charAt(0).toUpperCase(),
      isAdmin: false
    };
  }

  const avatarEl = document.getElementById("userAvatar");
  const nameEl = document.getElementById("displayUserName");
  const roleEl = document.getElementById("displayUserRole");

  if (avatarEl) avatarEl.textContent = currentUser.avatar;
  if (nameEl) nameEl.textContent = currentUser.name;
  if (roleEl) roleEl.textContent = currentUser.role + " ▾";

  document.querySelectorAll(".role-card").forEach(c => {
    c.classList.toggle("active", c.dataset.user === currentUser.id);
  });

  closeRoleModal();

  recordAuditLog("USER_LOGIN", "session_auth", "SUCCESS", `User ${currentUser.name} signed in as ${currentUser.role}`);

  if (currentUser.isAdmin) {
    showNotification(`Admin Session: Vinay (Administrator). Full cross-team audit access enabled.`, "success");
  } else {
    showNotification(`Analyst Session: ${currentUser.name} (${currentUser.role}). Viewing your audits.`, "success");
  }

  renderAuditHub();
  renderSystemAuditScreen();
}

function handleCustomSignIn() {
  const input = document.getElementById("inputCustomUser");
  if (!input) return;
  const val = input.value.trim();
  if (!val) {
    showNotification("Please enter a username or analyst ID!", "warning");
    return;
  }
  const customUser = {
    id: val.toLowerCase().replace(/\s+/g, "_"),
    name: val,
    role: "Security Analyst",
    avatar: val.charAt(0).toUpperCase(),
    isAdmin: false
  };
  setCurrentUser(customUser.id, customUser);
  input.value = "";
}

// Make functions globally available for inline onclick and external calls
window.openRoleModal = openRoleModal;
window.closeRoleModal = closeRoleModal;
window.setCurrentUser = setCurrentUser;
window.handleCustomSignIn = handleCustomSignIn;
window.switchToTab = switchToTab;
window.exportCsv = exportCsv;
window.saveCurrentToAuditHub = saveCurrentToAuditHub;
window.inspectAuditReport = inspectAuditReport;
window.renderAuditHub = renderAuditHub;
window.renderSystemAuditScreen = renderSystemAuditScreen;

// File upload handler
function handleFileUpload(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    const content = e.target.result;
    currentLogEvents = parseRawLogText(content, file.name);
    runAnalysis(true);
    recordAuditLog("FILE_INGEST", file.name, "SUCCESS", `Parsed ${currentLogEvents.length} lines`);
    showNotification(`Ingested '${file.name}' (${currentLogEvents.length} log lines). Flagged ${analyzedSuspects.length} brute-force attackers!`, "success");
  };
  reader.readAsText(file);
}

// Safe listener helper to prevent any uncaught null TypeError
function safeOn(idOrEl, event, handler) {
  let el = typeof idOrEl === "string" ? document.getElementById(idOrEl) : idOrEl;
  if (el) {
    el.addEventListener(event, handler);
  }
}

// Setup Event Listeners safely
window.addEventListener("dragover", (e) => e.preventDefault(), false);
window.addEventListener("drop", (e) => e.preventDefault(), false);

const dropzone = document.getElementById("logDropzone");
if (dropzone) {
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });
}

const fileInput = document.getElementById("fileInput");
if (fileInput) {
  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
      fileInput.value = "";
    }
  });
}

// Quick Scenarios
safeOn("btnLoadSampleAttack", "click", () => {
  currentLogEvents = parseRawLogText(SAMPLE_ATTACK_TEXT, "sample_attack.log");
  runAnalysis(true);
  recordAuditLog("PRESET_LOAD", "sample_attack.log", "SUCCESS", "Loaded 3-attacker scenario");
  showNotification("Loaded 'sample_attack.log': 3 external attackers detected!", "success");
});

safeOn("btnLoadSimulatedLog", "click", () => {
  let generatedText = "";
  for (let i = 0; i < 200; i++) {
    generatedText += `Sep 28 12:00:${String(i%60).padStart(2, "0")} server sshd[${10000+i}]: Failed password for root from 203.0.113.45 port ${30000+i} ssh2\n`;
  }
  currentLogEvents = parseRawLogText(generatedText, "enterprise_simulated.log");
  runAnalysis(true);
  recordAuditLog("PRESET_LOAD", "enterprise_simulated.log", "SUCCESS", "Loaded 200-line simulated enterprise dataset");
  showNotification("Loaded enterprise simulated dataset.", "success");
});

// Analysis & Export Controls
safeOn("btnExportCsv", "click", () => exportCsv());
safeOn("btnSaveToAuditHub", "click", saveCurrentToAuditHub);
safeOn("btnRunAnalysis", "click", () => {
  runAnalysis(false);
  recordAuditLog("THREAT_ANALYSIS", "sliding_window", "SUCCESS", `Evaluated ${currentLogEvents.length} log events`);
});
safeOn("inputThreshold", "input", () => runAnalysis(false));
safeOn("inputWindow", "input", () => runAnalysis(false));
safeOn("checkOnlyFailures", "change", renderConsoleStream);

document.querySelectorAll("#severityFilterGroup .pill").forEach(btn => {
  btn.addEventListener("click", (e) => {
    document.querySelectorAll("#severityFilterGroup .pill").forEach(p => p.classList.remove("active"));
    e.target.classList.add("active");
    currentFilterSeverity = e.target.dataset.severity;
    renderSuspectsTable();
  });
});

// Navigation Tabs
safeOn("tabBtnAnalyzer", "click", () => switchToTab("ANALYZER"));
safeOn("tabBtnAuditHub", "click", () => switchToTab("AUDIT_HUB"));
safeOn("tabBtnAuditTrail", "click", () => switchToTab("AUDIT_TRAIL"));

// Modal & User Account Controls
safeOn("btnSwitchRole", "click", openRoleModal);
safeOn("btnUserMenu", "click", openRoleModal);
safeOn("btnCloseModal", "click", closeRoleModal);

const roleModalEl = document.getElementById("roleModal");
if (roleModalEl) {
  roleModalEl.addEventListener("click", (e) => {
    if (e.target === roleModalEl) closeRoleModal();
  });
}

document.querySelectorAll(".role-card, .btn-login-select").forEach(el => {
  el.addEventListener("click", (e) => {
    e.stopPropagation();
    const user = el.dataset.user || el.closest(".role-card")?.dataset.user;
    if (user) {
      setCurrentUser(user);
    }
  });
});

safeOn("btnSignInCustom", "click", handleCustomSignIn);
const customInput = document.getElementById("inputCustomUser");
if (customInput) {
  customInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleCustomSignIn();
  });
}

// Audit Hub controls
safeOn("inputAuditSearch", "input", renderAuditHub);
safeOn("btnSeedSampleReports", "click", () => {
  auditReports = [...DEFAULT_AUDIT_REPORTS];
  saveAuditReports();
  renderAuditHub();
  showNotification("Reset Audit Hub to original organization reports.", "success");
});

document.querySelectorAll(".audit-filter-tags .pill").forEach(btn => {
  btn.addEventListener("click", (e) => {
    document.querySelectorAll(".audit-filter-tags .pill").forEach(p => p.classList.remove("active"));
    e.target.classList.add("active");
    activeAuditFilter = e.target.dataset.auditFilter;
    renderAuditHub();
  });
});

safeOn("btnCloseDrawer", "click", () => {
  const drawer = document.getElementById("auditDetailDrawer");
  if (drawer) drawer.style.display = "none";
});

safeOn("btnDownloadAuditCsv", "click", () => {
  if (currentInspectedAudit) {
    exportCsv(currentInspectedAudit.suspects, `${currentInspectedAudit.id}_audit_report.csv`);
  }
});

safeOn("btnLoadAuditIntoAnalyzer", "click", () => {
  if (currentInspectedAudit) {
    currentLogEvents = parseRawLogText(currentInspectedAudit.rawLog, `${currentInspectedAudit.server}.log`);
    switchToTab("ANALYZER");
    runAnalysis(true);
    recordAuditLog("AUDIT_RELOAD", currentInspectedAudit.id, "SUCCESS", `Loaded logs into analyzer`);
    showNotification(`Loaded '${currentInspectedAudit.server}' logs from audit ${currentInspectedAudit.id} into Analyzer!`, "success");
  }
});

safeOn("btnDownloadSystemAuditLog", "click", () => {
  const blob = new Blob([systemAuditLogs.join("\n")], { type: "text/plain;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", "system_audit.log");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  recordAuditLog("AUDIT_EXPORT", "system_audit.log", "SUCCESS", "Exported system audit trail");
});

// Initial startup execution
currentLogEvents = parseRawLogText(SAMPLE_ATTACK_TEXT, "sample_attack.log");
runAnalysis(false);
renderAuditHub();
renderSystemAuditScreen();
