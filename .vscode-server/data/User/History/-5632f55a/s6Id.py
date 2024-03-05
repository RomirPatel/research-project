import binascii
from scapy.all import rdpcap
import pandas as pd

def is_suspicious(packet):
    # Example: Check if packet has a large amount of data (DDoS attack)
    if len(packet) > 10000:
        return True
    
    # Example: Check if packet is an ARP reply from a different MAC address (ARP spoofing)
    if packet.haslayer(ARP) and packet[ARP].op == 2 and packet[Ether].src != packet[ARP].hwsrc:
        return True

    # Add more threat detection rules as needed

    return False

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
