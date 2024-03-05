from scapy.all import rdpcap
import pandas as pd

# Read PCAPNG file and extract features using scapy
pcap = rdpcap("network_traffic.pcapng")

# Extract relevant features from the packets
features = []
for pkt in pcap:
    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        protocol = pkt["IP"].proto
        length = len(pkt)
        # You can extract more features as needed
        features.append([src_ip, dst_ip, protocol, length])

# Convert the extracted features into a DataFrame
data = pd.DataFrame(features, columns=["src_ip", "dst_ip", "protocol", "length"])