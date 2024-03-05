import zeekclient
pcap = zeek.PcapFile("")

for packet in pcap:

    src_ip = packet.src_ip
    dst_ip = packet.dst_ip
    src_port = packet.src_port
    dst_port = packet.dst_port
    protocol = packet.protocol

    
    print(f"{src_ip} -> {dst_ip}: {src_port} -> {dst_port} ({protocol})")


pcap.close()
