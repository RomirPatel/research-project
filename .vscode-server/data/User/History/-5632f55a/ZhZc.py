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
            payload = binascii.hexlify(bytes(pkt["TCP"].payload)).decode('utf-8')
            
            features.append([src_ip, dst_ip, protocol, length, payload])
        else:
            features.append([src_ip, dst_ip, protocol, length, None])

data = pd.DataFrame(features, columns=["src_ip", "dst_ip", "protocol", "length", "payload"])

print(data)
