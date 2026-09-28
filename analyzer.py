#!/usr/bin/env python3
"""
analyzer.py - SSH Brute-Force Log Analyzer & Incident Reporter
--------------------------------------------------------------
A beginner-friendly cybersecurity script that:
  1. Reads an SSH authentication log file ('auth.log').
  2. Extracts failed login attempts (timestamps, usernames, IP addresses) using regular expressions.
  3. Detects brute-force attack patterns using a sliding time window (5+ failures within 5 minutes).
  4. Assigns risk severity levels (Medium: 5-9, High: 10-19, Critical: 20+).
  5. Exports findings to 'report.csv' and displays an executive terminal summary.

Standard Library only: re, csv, datetime, collections, pathlib, sys
"""

import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# ==============================================================================
# CONFIGURATION & THRESHOLDS
# ==============================================================================
DEFAULT_LOG_FILE = "auth.log"
DEFAULT_REPORT_FILE = "report.csv"

# Detection Rule: Flag any IP with >= 5 failures within a 5-minute sliding window
WINDOW_MINUTES = 5
FAILURE_THRESHOLD = 5

# Severity thresholds (based on failures within the detection window or attack total)
SEVERITY_CRITICAL_THRESHOLD = 20
SEVERITY_HIGH_THRESHOLD = 10
SEVERITY_MEDIUM_THRESHOLD = 5

# Regular expression to match SSH authentication failures.
#
# Line example:
# "Oct 24 10:14:02 secure-srv01 sshd[14205]: Failed password for root from 203.0.113.45 port 42102 ssh2"
#
# Breakdown:
#   ^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) -> Group 1: Timestamp (e.g. 'Oct 24 10:14:02')
#   \s+\S+\s+sshd\[\d+\]:\s+                   -> Matches hostname and sshd[pid] prefix
#   Failed password for\s+                      -> Matches failure prefix
#   (?:invalid user\s+)?                        -> Non-capturing optional group for invalid users
#   (\S+)\s+                                   -> Group 2: Target username (e.g. 'root', 'admin')
#   from\s+                                    -> Matches 'from '
#   ([0-9]{1,3}(?:\.[0-9]{1,3}){3})            -> Group 3: Attacker IPv4 address (e.g. '203.0.113.45')
SSH_FAILED_REGEX = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
)


def parse_syslog_timestamp(raw_timestamp: str) -> datetime:
    """
    Converts a syslog timestamp string (e.g. 'Oct 24 10:14:02') into a Python datetime object.

    Why this is necessary:
      Real syslog timestamps do not include the year. To perform mathematical time
      comparisons (e.g. 'did these 5 events happen within 5 minutes?'), we parse the
      string and anchor it to the current calendar year.
    """
    current_year = datetime.now().year
    # In Python 3.14+, parsing a date without a year raises a DeprecationWarning.
    # Prepending the current year ensures robust parsing across all Python versions.
    return datetime.strptime(f"{current_year} {raw_timestamp}", "%Y %b %d %H:%M:%S")


def parse_log_file(filepath: str):
    """
    Reads the SSH log file line-by-line and extracts all failed login attempts.

    Returns:
      total_lines (int): Total number of lines scanned in the log file.
      failed_attempts_by_ip (dict): Mapping of IP address to a list of event dictionaries:
        {
          "203.0.113.45": [
              {"timestamp": datetime(...), "raw_ts": "Oct 24 10:14:02", "user": "root"},
              ...
          ]
        }
    """
    total_lines = 0
    failed_attempts_by_ip = defaultdict(list)

    log_path = Path(filepath)
    if not log_path.exists():
        print(f"[!] Error: Log file '{filepath}' not found.")
        print("    Please run 'python generate_logs.py' first to create synthetic logs.")
        sys.exit(1)

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            match = SSH_FAILED_REGEX.search(line)
            if match:
                raw_ts, user, ip = match.groups()
                event_time = parse_syslog_timestamp(raw_ts)

                failed_attempts_by_ip[ip].append({
                    "timestamp": event_time,
                    "raw_ts": raw_ts,
                    "user": user
                })

    return total_lines, failed_attempts_by_ip


def detect_brute_force(timestamps: list, window_minutes: int = WINDOW_MINUTES) -> int:
    """
    Sliding Window Detection Algorithm:
    Determines the maximum number of failed attempts that occurred within ANY 5-minute window.

    How it works:
      1. Ensure timestamps are in chronological order.
      2. For each failure timestamp (t_i), define a 5-minute window [t_i, t_i + 5 minutes].
      3. Count how many subsequent failures fell inside that specific window.
      4. Track and return the highest burst count observed.

    Why this matters in cybersecurity:
      An attacker performing brute-force attempts submits dozens of passwords in seconds
      or minutes (high velocity). A legitimate user who mistypes their password once on
      Monday and once on Wednesday will have 2 failures over days, which is NOT an attack.
    """
    if not timestamps:
        return 0

    max_failures_in_window = 0
    window_duration = timedelta(minutes=window_minutes)

    for i in range(len(timestamps)):
        current_time = timestamps[i]
        window_end = current_time + window_duration

        # Count how many attempts from index i onwards occurred before window_end
        burst_count = sum(1 for t in timestamps[i:] if t <= window_end)

        if burst_count > max_failures_in_window:
            max_failures_in_window = burst_count

    return max_failures_in_window


def calculate_severity(failure_count: int) -> str:
    """
    Assigns an incident severity rating based on the number of failed attempts:
      - Critical : 20 or more failed attempts (High-volume brute force)
      - High     : 10 to 19 failed attempts (Moderate brute force / dictionary attack)
      - Medium   : 5 to 9 failed attempts (Targeted credential probe / threshold breach)
      - Low      : Fewer than 5 failures (Normal benign typo / noise)
    """
    if failure_count >= SEVERITY_CRITICAL_THRESHOLD:
        return "Critical"
    elif failure_count >= SEVERITY_HIGH_THRESHOLD:
        return "High"
    elif failure_count >= SEVERITY_MEDIUM_THRESHOLD:
        return "Medium"
    else:
        return "Low"


def write_csv_report(suspects: list, output_filepath: str = DEFAULT_REPORT_FILE):
    """
    Exports the flagged brute-force suspects to a standard CSV triage report.

    Columns:
      - IP: Attacker IP address
      - failed attempts: Total count of failed authentication attempts
      - first seen: Earliest recorded timestamp of the attack
      - last seen: Latest recorded timestamp of the attack
      - severity: Assessed threat level (Medium, High, Critical)
    """
    fieldnames = ["IP", "failed attempts", "first seen", "last seen", "severity"]

    with open(output_filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for suspect in suspects:
            writer.writerow({
                "IP": suspect["ip"],
                "failed attempts": suspect["failed_attempts"],
                "first seen": suspect["first_seen"],
                "last seen": suspect["last_seen"],
                "severity": suspect["severity"]
            })


def display_terminal_summary(total_lines: int, total_failures: int, suspects: list):
    """
    Prints a clear, executive-ready summary table of the analysis results in the terminal.
    """
    print("\n" + "=" * 78)
    print("                     SSH LOG SECURITY ANALYZER REPORT")
    print("=" * 78)
    print(f" Total Log Lines Processed : {total_lines}")
    print(f" Total Failed Logins Found : {total_failures}")
    print(f" Brute-Force Suspects      : {len(suspects)}")
    print("=" * 78)

    if not suspects:
        print("[+] No brute-force activity detected matching current thresholds.\n")
        return

    # Table Header
    print(f"{'IP Address':<18} {'Failures':<10} {'First Seen':<16} {'Last Seen':<16} {'Severity':<10}")
    print("-" * 78)

    # Table Rows
    for s in suspects:
        print(f"{s['ip']:<18} {s['failed_attempts']:<10} {s['first_seen']:<16} {s['last_seen']:<16} {s['severity']:<10}")

    print("-" * 78)
    print(f"[+] Detailed incident report saved to: '{DEFAULT_REPORT_FILE}'\n")


def main():
    """
    Main execution pipeline:
      1. Parse CLI arguments (allowing any file path and custom thresholds).
      2. Ingest and parse log file.
      3. Evaluate each IP against sliding window brute-force rules.
      4. Classify severity (Low, Medium, High, Critical).
      5. Export CSV and print terminal summary.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="SSH Brute-Force Log Analyzer - Ingest any Linux auth log and detect brute-force activity."
    )
    parser.add_argument("logfile", nargs="?", default=DEFAULT_LOG_FILE, help="Path to any auth.log or syslog file")
    parser.add_argument("-t", "--threshold", type=int, default=FAILURE_THRESHOLD, help="Failure count threshold (default: 5)")
    parser.add_argument("-w", "--window", type=int, default=WINDOW_MINUTES, help="Sliding window in minutes (default: 5)")
    parser.add_argument("-o", "--output", default=DEFAULT_REPORT_FILE, help="Output CSV path (default: report.csv)")
    parser.add_argument("--include-low", "--all", action="store_true", help="Include Low severity IPs (1-4 failures) in report")

    args = parser.parse_args()

    # Step 1: Scan and parse the logs
    total_lines, failed_by_ip = parse_log_file(args.logfile)
    total_failed_events = sum(len(events) for events in failed_by_ip.values())

    suspects = []

    # Step 2: Analyze each IP address
    for ip, events in failed_by_ip.items():
        events.sort(key=lambda e: e["timestamp"])
        timestamps = [e["timestamp"] for e in events]

        max_burst = detect_brute_force(timestamps, window_minutes=args.window)

        # Flag if burst exceeds threshold, or if user requested --include-low / --all
        if max_burst >= args.threshold or args.include_low:
            total_attempts = len(events)
            severity = calculate_severity(total_attempts)

            suspects.append({
                "ip": ip,
                "failed_attempts": total_attempts,
                "burst_count": max_burst,
                "first_seen": events[0]["raw_ts"],
                "last_seen": events[-1]["raw_ts"],
                "severity": severity
            })

    # Sort suspects by severity order (Critical -> High -> Medium -> Low)
    severity_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    suspects.sort(key=lambda s: (severity_rank.get(s["severity"], 0), s["failed_attempts"]), reverse=True)

    # Step 3: Write CSV report
    write_csv_report(suspects, args.output)

    # Step 4: Display terminal summary
    display_terminal_summary(total_lines, total_failed_events, suspects)


if __name__ == "__main__":
    main()
