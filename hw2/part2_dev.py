#import all the required fields. 
from scapy.all import *

# Target IP and port range
#target_ip = "44.243.113.123"  # Replace with the target IP address from the DNS Guardian
target_ip = "192.168.124.1"  # my personal ip going to attack my own computer
start_port = 0  # Replace with the starting port from the DNS Guardian
end_port = 13380  # Replace with the ending port from the DNS Guardian
timeout = 3  # Timeout in seconds to wait for a response

# Function to perform SYN scan on a single port
def scan_port(port):
    try:
        pass
        # Create a SYN packet
        ip = IP(dst=target_ip)
        tcp = TCP(dport=port, flags="S")
        syn_packet = ip / tcp

        # Send the SYN packet and wait for a response
        send(syn_packet, verbose=False)

    
        # Check if a response is received
        response = sr1(syn_packet, timeout=2, verbose=False)
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12: 
                print(f"Received SYN-ACK on port {port}")
        
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

# Main function to scan a range of ports
def syn_scan():
    print(f"Starting SYN scan on {target_ip} for ports {start_port}-{end_port}")
    for port in range(start_port, end_port + 1):
        scan_port(port)
    print("SYN scan completed.")


syn_scan()