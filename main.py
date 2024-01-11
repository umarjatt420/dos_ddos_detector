from scapy.all import *

def detect_dos(packet):
    # Count the number of packets from the source IP
    source_ip = packet[IP].src
    if source_ip in packet_counts:
        packet_counts[source_ip] += 1
    else:
        packet_counts[source_ip] = 1

    # Check if the packet count exceeds the threshold
    if packet_counts[source_ip] > THRESHOLD:
        print(f"Possible DoS/DDoS attack detected from {source_ip}")

# Dictionary to store packet counts per source IP
packet_counts = {}

# Set a threshold for the number of packets from a single source IP
THRESHOLD = 100

# Sniff network packets and call the detect_dos function for each packet
sniff(prn=detect_dos, filter="ip", store=0)