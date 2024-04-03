import binascii
import pandas as pd
import subprocess
import json
import os
from scapy.all import rdpcap, ARP, Ether

# Function to determine if a packet exhibits suspicious behavior
def is_suspicious(packet):
    # Example: Check if packet has a large amount of data (DDoS attack)
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
        if len(parts) >= 15:
            src_ip = parts[2]
            dst_ip = parts[4]
            protocol = parts[7]
            length = int(parts[8])
            threat_detected = True

            threats.append([src_ip, dst_ip, protocol, length, threat_detected])

    return threats

pcap_file = "4.pcap"

# List of Suricata rule files to test
rule_files = [
    "/etc/suricata/rules/app-layer-events.rules",
    "/etc/suricata/rules/decoder-events.rules",
    "/etc/suricata/rules/dhcp-events.rules",
    "/etc/suricata/rules/dns-events.rules",
    "/etc/suricata/rules/dnp3-events.rules",
    "/etc/suricata/rules/files.rules",
    "/etc/suricata/rules/http-events.rules",
    "/etc/suricata/rules/http2-events.rules",
    "/etc/suricata/rules/ipsec-events.rules",
    "/etc/suricata/rules/kerberos-events.rules",
    "/etc/suricata/rules/modbus-events.rules",
    "/etc/suricata/rules/mqtt-events.rules",
    "/etc/suricata/rules/nfs-events.rules",
    "/etc/suricata/rules/ntp-events.rules",
    "/etc/suricata/rules/smb-events.rules",
    "/etc/suricata/rules/smtp-events.rules",
    "/etc/suricata/rules/ssh-events.rules",
    "/etc/suricata/rules/stream-events.rules",
    "/etc/suricata/rules/tls-events.rules"
]

features = []
suricata_threats_data = {}

# Analyze pcap file using each Suricata rule file
for rule_file in rule_files:
    suricata_threats = analyze_with_suricata(pcap_file, rule_file)
    suricata_data = pd.DataFrame(suricata_threats, columns=["src_ip", "dst_ip", "protocol", "length", "threat_detected"])
    
    suricata_threats_data[rule_file.split('/')[-1]] = suricata_data

    with rdpcap(pcap_file) as pcap:
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

# Convert features list to DataFrame
data = pd.DataFrame(features, columns=["src_ip", "dst_ip", "protocol", "length", "payload", "threat_detected"])

# Print threats detected by each Suricata rule
for rule, suricata_data in suricata_threats_data.items():
    print(f"\nThreats detected by {rule}:")
    print(suricata_data)

print("\nGeneral threats detected by Suricata rules:")
print(data[data['threat_detected'] == True])