import json
import subprocess

def ensure_nftables_table_exists():
    """
    Ensures that the nftables 'filter' table and 'input' chain exist.
    Uses the 'ip' family instead of 'inet' to avoid conflicts with existing configurations.
    """
    try:
        # Check if the 'filter' table exists under the 'ip' family
        result = subprocess.run(['sudo', 'nft', 'list tables'], capture_output=True, text=True, check=True)
        if 'filter' not in result.stdout:
            print("Creating 'filter' table in 'ip' family...")
            subprocess.run(['sudo', 'nft', 'add', 'table', 'ip', 'filter'], check=True)

        # Check if the 'input' chain exists in the 'filter' table
        result = subprocess.run(['sudo', 'nft', 'list ruleset'], capture_output=True, text=True, check=True)
        if 'chain input' not in result.stdout:
            print("Creating 'input' chain in 'filter' table...")
            subprocess.run([
                'sudo', 'nft', 'add', 'chain', 'ip', 'filter', 'input',
                '{ type filter hook input priority 0; }'
            ], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error ensuring nftables table: {e}")
        if e.stderr:
            print(f"stderr: {e.stderr.decode()}")
        else:
            print("stderr: None")

def block_ip_with_nft(ip):
    try:
        print(f"Blocking IP: {ip} using nftables")

        # Ensure the correct nftables table and chain exist before adding the rule
        ensure_nftables_table_exists()

        # Add rule to block the IP
        result = subprocess.run([
            'sudo', 'nft', 'add', 'rule', 'ip', 'filter', 'input', 'ip', 'saddr', ip, 'drop'
        ], check=True, capture_output=True)

        print(f"IP {ip} blocked successfully.")
        print(f"nftables result: {result.stdout.decode()}")

    except subprocess.CalledProcessError as e:
        print(f"Error applying nftables rule: {e}")
        if e.stderr:
            print(f"stderr: {e.stderr.decode()}")
        else:
            print("stderr: None")

def read_json_file(file_path, allowed_ports):
    ips_to_block = []  # List of IPs to block

    try:
        with open(file_path, 'r') as file:
            for line in file:
                try:
                    entry = json.loads(line.strip())
                    if entry.get("event_type") == "alert" and entry.get("alert", {}).get("signature") == "Possible Syn Scan":
                        src_ip = entry.get("src_ip")
                        dst_port = entry.get("dest_port")
                        if dst_port not in allowed_ports:
                            if src_ip not in ips_to_block:  # Avoid duplicate IPs
                                ips_to_block.append(src_ip)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}")

    except Exception as e:
        print(f"Error reading JSON file: {e}")

    # Block IPs that are found in the list
    for ip in ips_to_block:
        block_ip_with_nft(ip)

def main():
    # Specify the path to your Suricata eve.json log file
    eve_log_path = '/var/log/suricata/eve.json'
    allowed_ports = ["22","53","80"]
    # Read the log and block IPs
    read_json_file(eve_log_path, allowed_ports)

if __name__ == "__main__":
    main()
