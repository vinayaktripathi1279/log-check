#!/usr/bin/env python3
"""
audit_logger.py - Application Security & User Activity Audit Logger
-------------------------------------------------------------------
Demonstrates the cybersecurity concept of "Application Audit Logging":
While `auth.log` records OS/SSH authentication events, an application's
`system_audit.log` records what users (analysts, admins, engineers) do
INSIDE the security tool:
  - User Logins & Session Starts
  - Log File Ingestions & File Uploads
  - Security Threat Detections & Threshold Tweaks
  - Audit Report Submissions
  - Admin Inspections & CSV Report Downloads
"""

import os
from datetime import datetime, timezone

AUDIT_LOG_FILE = "system_audit.log"


def log_audit_event(user_id: str, role: str, action: str, resource: str, status: str = "SUCCESS", details: str = ""):
    """
    Appends a standardized SIEM-compatible audit log entry to system_audit.log.

    Format:
      TIMESTAMP [SEVERITY] USER="<user>" ROLE="<role>" ACTION="<action>" RESOURCE="<resource>" STATUS="<status>" DETAILS="<details>"
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    severity = "AUDIT" if status == "SUCCESS" else "WARN"

    log_entry = (
        f"{timestamp} [{severity}] USER=\"{user_id}\" ROLE=\"{role}\" "
        f"ACTION=\"{action}\" RESOURCE=\"{resource}\" STATUS=\"{status}\" DETAILS=\"{details}\"\n"
    )

    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)

    return log_entry.strip()


def seed_sample_audit_trail():
    """
    Creates an educational sample audit trail demonstrating non-admin user activity
    and subsequent admin oversight actions.
    """
    events = [
        ("sarah_soc", "SOC Analyst", "USER_LOGIN", "session_auth", "SUCCESS", "Logged in from IP 192.168.1.42"),
        ("sarah_soc", "SOC Analyst", "FILE_INGEST", "production-bastion.log", "SUCCESS", "Ingested 49 lines, 42 failures"),
        ("sarah_soc", "SOC Analyst", "THREAT_ANALYSIS", "5_in_5m_rule", "ALERT", "Detected 3 brute-force attackers (Peak: Critical)"),
        ("sarah_soc", "SOC Analyst", "AUDIT_SUBMIT", "AUD-2026-0891", "SUCCESS", "Created audit report for server: production-bastion-01"),
        ("rahul_devops", "DevOps Lead", "USER_LOGIN", "session_auth", "SUCCESS", "Logged in from IP 10.0.0.12"),
        ("rahul_devops", "DevOps Lead", "FILE_INGEST", "k8s-ingress.log", "SUCCESS", "Ingested 180 lines"),
        ("rahul_devops", "DevOps Lead", "AUDIT_SUBMIT", "AUD-2026-0890", "SUCCESS", "Created audit report for cluster: k8s-ingress-cluster"),
        ("vinay_admin", "Super Admin", "USER_LOGIN", "session_auth", "SUCCESS", "Admin session initialized"),
        ("vinay_admin", "Super Admin", "AUDIT_INSPECT", "AUD-2026-0891", "SUCCESS", "Inspected Sarah Jenkins' raw log submission"),
        ("vinay_admin", "Super Admin", "REPORT_DOWNLOAD", "AUD-2026-0891.csv", "SUCCESS", "Exported incident triage report to CSV"),
    ]

    with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
        for u, r, a, res, s, d in events:
            entry = log_audit_event(u, r, a, res, s, d)
            print(f"[+] {entry}")

    print(f"\n[+] Successfully generated '{AUDIT_LOG_FILE}'.")


if __name__ == "__main__":
    seed_sample_audit_trail()
