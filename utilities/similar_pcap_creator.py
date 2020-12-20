import sys
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

if __name__ == '__main__':
    pcap=rdpcap(sys.argv[1])
    IP2replace = sys.argv[2]
    
    for pkt in pcap:
        if (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and \
            (pkt[IP].src == IP2replace or pkt[IP].dst == IP2replace)):
            if pkt[IP].src == IP2replace:
                pkt[IP].src = "111.111.111.111"

            if pkt[IP].dst == IP2replace:
                pkt[IP].dst = "111.111.111.111"
    
    wrpcap(sys.argv[1], pcap)