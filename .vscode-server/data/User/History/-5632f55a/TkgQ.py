import binascii
from scapy.all import rdpcap
import pandas as pd

pcap = rdpcap("test.pcapng")

features = []
for pkt in pcap:
    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        protocol = pkt["IP"].proto
        length = len(pkt)
        

        if pkt.haslayer("TCP"):
            # Extract payload (application layer data) and convert to hexadecimal            payload = binascii.hexlify(bytes(pkt["TCP"].payload)).decode('utf-8')
            
            # Append payload data to the features
            features.append([src_ip, dst_ip, protocol, length, payload])
        else:
            features.append([src_ip, dst_ip, protocol, length, None])

# Create a DataFrame from the features
data = pd.DataFrame(features, columns=["src_ip", "dst_ip", "protocol", "length", "payload"])

print(data)
