import binascii
import pandas as pd
import subprocess
import json
import os
from scapy.all import rdpcap, ARP, Ether

# Function to determine if a packet exhibits suspicious behavior
def is_suspicious(packet):
    if len(packet) > 10000:
        return True

    if packet.haslayer(ARP) and packet[ARP].op == 2 and packet[Ether].src != packet[ARP].hwsrc:
        return True

    return False

# Function to analyze pcap file using Suricata
def analyze_with_suricata(pcap_file, rule_file):
    if not os.path.exists("./output"):
        os.makedirs("./output")

    command = f"suricata -r {pcap_file} -S {rule_file} -l ./output"
    subprocess.run(command, shell=True)

    with open('./output/fast.log', 'r') as file:
        lines = file.readlines()

    threats = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 15 and "HTTP" in parts:
            src_ip = parts[2]
            dst_ip = parts[4]
            protocol = parts[7]
            
            try:
                length = int(parts[8])
            except ValueError:
                length = None

            threat_detected = True

            threats.append([src_ip, dst_ip, protocol, length, threat_detected])

    return threats

pcap_file = "4.pcap"
rule_directory = "/etc/suricata/rules/"
rule_files = [os.path.join(rule_directory, f) for f in os.listdir(rule_directory) if f.endswith('.rules')]

pcap = rdpcap(pcap_file)

features = []
all_suricata_threats = []

for rule_file in rule_files:
    suricata_threats = analyze_with_suricata(pcap_file, rule_file)
    all_suricata_threats.extend(suricata_threats)

    for pkt in pcap:
        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst
            protocol = pkt["IP"].proto
            length = len(pkt)

            if is_suspicious(pkt):
                threat_detected = True
            else:
                threat_detected = False

            if pkt.haslayer("TCP"):
                payload = binascii.hexlify(bytes(pkt["TCP"].payload)).decode('utf-8')
                
                features.append([src_ip, dst_ip, protocol, length, payload, threat_detected])
            else:
                features.append([src_ip, dst_ip, protocol, length, None, threat_detected])

data = pd.DataFrame(features, columns=["src_ip", "dst_ip", "protocol", "length", "payload", "threat_detected"])
suricata_data = pd.DataFrame(all_suricata_threats, columns=["src_ip", "dst_ip", "protocol", "length", "threat_detected"])

print("\nThreats detected by Suricata:")
print(suricata_data)
