import json
import time
import os
from collections import defaultdict

LOG_FILE = "/var/log/suricata/eve.json"
BLOCK_DURATION = 300  # 5 minutes
RATE_LIMIT = 10  # Max SYN requests per second

ip_tracker = defaultdict(list)
blocked_ips = {}

def block_ip(ip):
    """Blocks an IP using iptables for 5 minutes"""
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    blocked_ips[ip] = time.time()
    print(f"Blocked {ip} for {BLOCK_DURATION} seconds.")

def unblock_ip(ip):
    """Unblocks an IP after 5 minutes"""
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    print(f"Unblocked {ip}")

def process_log_entry(entry):
    """Processes a Suricata log entry to check for SYN floods"""
    if entry.get("event_type") == "alert":
        src_ip = entry.get("src_ip")
        alert_signature = entry.get("alert", {}).get("signature", "")

        if "SYN" in alert_signature:  # Adjust this based on Suricata rule signature
            current_time = time.time()
            ip_tracker[src_ip].append(current_time)

            # Remove old entries beyond 1 second
            ip_tracker[src_ip] = [t for t in ip_tracker[src_ip] if t > current_time - 1]

            if len(ip_tracker[src_ip]) > RATE_LIMIT and src_ip not in blocked_ips:
                block_ip(src_ip)

def monitor_logs():
    """Monitors Suricata logs in real time"""
    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)  # Move to end of file

        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)  # Wait for new log entry
                continue

            try:
                log_entry = json.loads(line.strip())
                process_log_entry(log_entry)
            except json.JSONDecodeError:
                continue

            # Unblock IPs after BLOCK_DURATION
            for ip in list(blocked_ips.keys()):
                if time.time() - blocked_ips[ip] > BLOCK_DURATION:
                    unblock_ip(ip)
                    del blocked_ips[ip]

if __name__ == "__main__":
    print("Monitoring Suricata logs for SYN flood attacks...")
    monitor_logs()
