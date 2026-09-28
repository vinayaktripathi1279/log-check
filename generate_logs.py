#!/usr/bin/env python3
"""
generate_logs.py - Synthetic SSH Authentication Log Generator
--------------------------------------------------------------
Generates a realistic Linux `/var/log/auth.log` file containing:
  - Normal successful logins (Accepted password / publickey)
  - Occasional benign user typos (1-2 failed logins)
  - 3 targeted brute-force attacker IPs with rapid bursts of failed attempts:
      * 203.0.113.45 -> 25 failed attempts in ~3 minutes (Critical severity)
      * 198.51.100.89 -> 14 failed attempts in ~3 minutes (High severity)
      * 192.0.2.14   -> 7 failed attempts in ~2 minutes (Medium severity)
  - Approximately 500 total log lines in realistic chronological order.

Standard Library only: random, datetime, sys
"""

import random
from datetime import datetime, timedelta

# Configuration constants
LOG_FILE_NAME = "auth.log"
TARGET_LINE_COUNT = 500
HOSTNAME = "secure-srv01"

# Realistic attacker IP addresses (using RFC 5737 TEST-NET reserved ranges for safety)
ATTACKER_CRITICAL = "203.0.113.45"   # Will generate 25 failed attempts (Critical: >= 20)
ATTACKER_HIGH     = "198.51.100.89"  # Will generate 14 failed attempts (High: 10 - 19)
ATTACKER_MEDIUM   = "192.0.2.14"     # Will generate 7 failed attempts (Medium: 5 - 9)

# Benign internal and external IP addresses
LEGITIMATE_IPS = [
    "192.168.1.15",
    "192.168.1.42",
    "192.168.1.105",
    "10.0.0.12",
    "10.0.0.55",
    "172.16.5.20",
]

# Common user accounts
VALID_USERS = ["vinay", "ubuntu", "devops", "deploy", "alice", "bob"]
COMMON_ATTACK_TARGETS = ["root", "admin", "test", "oracle", "guest", "postgres", "user", "ftpuser"]


def create_log_line(timestamp: datetime, pid: int, message: str) -> str:
    """
    Format a single syslog-compatible line.
    Example: Oct 24 10:14:02 secure-srv01 sshd[14205]: Failed password for root from 203.0.113.45 port 42102 ssh2
    """
    # Standard syslog timestamp format: 'Mmm dd HH:MM:SS' (e.g. 'Oct 24 09:15:30')
    ts_str = timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts_str} {HOSTNAME} sshd[{pid}]: {message}"


def generate_brute_force_events(attacker_ip: str, attempt_count: int, start_time: datetime) -> list:
    """
    Generates a burst of rapid failed login attempts for a specific attacker IP.
    Attempts occur a few seconds apart, fitting comfortably within a 5-minute window.
    """
    events = []
    current_time = start_time
    pid_base = random.randint(10000, 30000)

    for i in range(attempt_count):
        # 3 to 10 seconds between attacker password tries
        current_time += timedelta(seconds=random.randint(3, 10))
        target_user = random.choice(COMMON_ATTACK_TARGETS)
        port = random.randint(32000, 65000)
        pid = pid_base + i

        # Some SSH scanners try non-existent users, triggering 'invalid user' log lines
        is_invalid = random.choice([True, False])
        if is_invalid:
            msg = f"Failed password for invalid user {target_user} from {attacker_ip} port {port} ssh2"
        else:
            msg = f"Failed password for {target_user} from {attacker_ip} port {port} ssh2"

        events.append((current_time, pid, msg))

    return events


def generate_normal_events(start_time: datetime, count: int) -> list:
    """
    Generates normal, realistic server authentication activity:
      - Successful password logins
      - Successful public key logins
      - Occasional benign user typos (1-2 failed logins followed by success)
      - Session disconnects
    """
    events = []
    current_time = start_time

    for _ in range(count):
        # Normal traffic spread: between 15 seconds to 3 minutes apart
        current_time += timedelta(seconds=random.randint(15, 180))
        ip = random.choice(LEGITIMATE_IPS)
        user = random.choice(VALID_USERS)
        port = random.randint(40000, 60000)
        pid = random.randint(10000, 50000)

        event_type = random.choices(
            population=["publickey", "password", "typo", "closed"],
            weights=[40, 35, 15, 10],
            k=1
        )[0]

        if event_type == "publickey":
            msg = f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:{random.getrandbits(64):016x}"
            events.append((current_time, pid, msg))
        elif event_type == "password":
            msg = f"Accepted password for {user} from {ip} port {port} ssh2"
            events.append((current_time, pid, msg))
        elif event_type == "typo":
            # A benign user mistyped their password once, then logged in successfully
            msg_fail = f"Failed password for {user} from {ip} port {port} ssh2"
            events.append((current_time, pid, msg_fail))

            current_time += timedelta(seconds=random.randint(4, 12))
            pid_next = pid + 1
            msg_ok = f"Accepted password for {user} from {ip} port {port + 1} ssh2"
            events.append((current_time, pid_next, msg_ok))
        else:
            msg = f"Received disconnect from {ip} port {port}:11: disconnected by user"
            events.append((current_time, pid, msg))

    return events


def main():
    """
    Main orchestration function to combine normal traffic and attacker bursts,
    sort them by timestamp, and write out auth.log.
    """
    # Start timeline from yesterday morning
    base_time = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(days=1)

    all_events = []

    # 1. Attacker 1 (Critical: 25 attempts in ~3 minutes) starting at hour 2
    burst1_start = base_time + timedelta(hours=2, minutes=15)
    all_events.extend(generate_brute_force_events(ATTACKER_CRITICAL, 25, burst1_start))

    # 2. Attacker 2 (High: 14 attempts in ~2.5 minutes) starting at hour 5
    burst2_start = base_time + timedelta(hours=5, minutes=40)
    all_events.extend(generate_brute_force_events(ATTACKER_HIGH, 14, burst2_start))

    # 3. Attacker 3 (Medium: 7 attempts in ~1.5 minutes) starting at hour 8
    burst3_start = base_time + timedelta(hours=8, minutes=10)
    all_events.extend(generate_brute_force_events(ATTACKER_MEDIUM, 7, burst3_start))

    # 4. Normal background traffic to bring the total to ~500 lines
    remaining_lines = TARGET_LINE_COUNT - len(all_events)
    all_events.extend(generate_normal_events(base_time, remaining_lines))

    # Sort all events chronologically so the log file is 100% realistic
    all_events.sort(key=lambda event: event[0])

    # Write formatted lines to auth.log
    with open(LOG_FILE_NAME, "w", encoding="utf-8") as f:
        for timestamp, pid, message in all_events:
            line = create_log_line(timestamp, pid, message)
            f.write(line + "\n")

    print(f"[+] Successfully generated '{LOG_FILE_NAME}' with {len(all_events)} log entries.")
    print(f"    - Injected Critical Attacker : {ATTACKER_CRITICAL} (25 failures)")
    print(f"    - Injected High Attacker     : {ATTACKER_HIGH} (14 failures)")
    print(f"    - Injected Medium Attacker   : {ATTACKER_MEDIUM} (7 failures)")
    print(f"    - Injected Normal traffic    : ~{remaining_lines} events across benign IPs\n")


if __name__ == "__main__":
    main()
