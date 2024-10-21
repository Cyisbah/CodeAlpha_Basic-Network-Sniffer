from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import signal
import sys


captured_packets = []


def packet_callback(packet):
   
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        # Capture protocol details
        if proto == 6: 
            packet_info = f"TCP Packet: {ip_src} -> {ip_dst}"
        elif proto == 17:  
            packet_info = f"UDP Packet: {ip_src} -> {ip_dst}"
        elif proto == 1: 
            packet_info = f"ICMP Packet: {ip_src} -> {ip_dst}"
        else:
            packet_info = f"Other IP Packet: {ip_src} -> {ip_dst} (Protocol: {proto})"
        
       
        captured_packets.append(packet_info)


def signal_handler(sig, frame):
    print("\nSniffing stopped. Displaying captured packets:")
    for packet in captured_packets:
        print(packet)
    sys.exit(0)

def main():
    print("Starting packet sniffer... (Press CTRL+C to stop)")
    
   
    sniff(prn=packet_callback, store=False)  
if __name__ == "__main__":
   
    signal.signal(signal.SIGINT, signal_handler)
    main()
