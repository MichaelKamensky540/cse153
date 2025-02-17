import subprocess

def find_rule_handle(ip):
    try:
        # List all rules
        result = subprocess.run(['sudo', 'nft', 'list', 'ruleset'], capture_output=True, text=True, check=True)
        
        # Search for the rule that matches the IP
        lines = result.stdout.splitlines()
        for line in lines:
            if ip in line:
                # Extract the handle (it's usually the last field in the rule line)
                if 'handle' in line:
                    parts = line.split()
                    handle_index = parts.index('handle') + 1
                    return parts[handle_index]
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error listing nftables rules: {e}")
        return None

def unblock_ip_with_nft(ip):
    try:
        handle = find_rule_handle(ip)
        if handle:
            # Delete the rule by its handle
            print(f"Unblocking IP: {ip} using nftables (handle {handle})")
            result = subprocess.run(['sudo', 'nft', 'delete', 'rule', 'inet', 'filter', 'input', 'handle', handle],
                                    check=True, capture_output=True)
            print(f"nftables result: {result.stdout.decode()}")
            print(f"Unbanned IP: {ip}")
        else:
            print(f"No rule found for IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error removing nftables rule: {e}")
        print(f"stderr: {e.stderr.decode()}")

# Example usage
unblock_ip_with_nft('192.168.124.139')

