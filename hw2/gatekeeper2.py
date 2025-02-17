import json
import subprocess
import time
import threading
from collections import defaultdict
from threading import Lock

# Path to Suricata's eve.json log file
EVE_LOG_PATH = "/var/log/suricata/eve.json"

# Thresholds for blocking (adjust based on your needs)
SYN_FLOOD_THRESHOLD = 3  # Lower threshold for testing
UDP_FLOOD_THRESHOLD = 10  # Lower threshold for testing
TIME_WINDOW = 1  # Time window in seconds

# Track IPs and their packet counts (thread-safe)
ip_syn_count = defaultdict(int)
ip_udp_count = defaultdict(int)

# Locks for thread-safe access to the dictionaries
syn_lock = Lock()
udp_lock = Lock()

def block_ip(ip):
    """Block an IP address using iptables."""
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        pass  # Silently handle errors

def monitor_log():
    """Monitor the Suricata eve.json log file for flood alerts."""
    with open(EVE_LOG_PATH, "r") as logfile:
        logfile.seek(0, 2)  # Move to the end of the file
        while True:
            line = logfile.readline()
            if line:
                try:
                    event = json.loads(line)
                    if event["event_type"] == "alert":
                        alert = event["alert"]
                        src_ip = event["src_ip"]
                        if "SYN Flood Detected" in alert["signature"]:
                            with syn_lock:  # Thread-safe access
                                ip_syn_count[src_ip] += 1
                        elif "UDP Flood Detected" in alert["signature"]:
                            with udp_lock:  # Thread-safe access
                                ip_udp_count[src_ip] += 1
                except json.JSONDecodeError:
                    continue
            else:
                time.sleep(0.1)  # Sleep briefly to avoid high CPU usage

def check_thresholds():
    """Check if any IPs have exceeded the flood thresholds."""
    while True:
        with syn_lock:  # Thread-safe access
            for ip, count in list(ip_syn_count.items()):  # Create a copy of items to avoid runtime errors
                if count >= SYN_FLOOD_THRESHOLD:
                    block_ip(ip)
                    ip_syn_count[ip] = 0  # Reset the count after blocking
        with udp_lock:  # Thread-safe access
            for ip, count in list(ip_udp_count.items()):  # Create a copy of items to avoid runtime errors
                if count >= UDP_FLOOD_THRESHOLD:
                    block_ip(ip)
                    ip_udp_count[ip] = 0  # Reset the count after blocking
        time.sleep(TIME_WINDOW)

def main():
    """Main function to start the script."""
    # Start the log monitoring thread
    log_thread = threading.Thread(target=monitor_log)
    log_thread.daemon = True
    log_thread.start()

    # Start the threshold checking thread
    threshold_thread = threading.Thread(target=check_thresholds)
    threshold_thread.daemon = True
    threshold_thread.start()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass  # Silently handle keyboard interrupt

# Call the main function to start the script
main()