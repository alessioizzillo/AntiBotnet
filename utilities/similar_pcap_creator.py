import sys
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from tqdm import tqdm

if __name__ == '__main__':
    pcap=rdpcap(sys.argv[1])
    IPs2replace_file = sys.argv[2]
    fake_IPs_file = sys.argv[3]
    
    with open(IPs2replace_file, "r") as f:
        IPs2replace_list = f.read().split("\n")

    while ("" in IPs2replace_list):
        IPs2replace_list.remove("")

    with open(fake_IPs_file, "r") as f:
        fake_IPs_list = f.read().split("\n")

    while ("" in fake_IPs_list):
        fake_IPs_list.remove("")
    
    print("START")
    for pkt in tqdm(pcap):
        if (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
            if pkt[IP].src in IPs2replace_list:
                i = IPs2replace_list.index(pkt[IP].src)
                pkt[IP].src = fake_IPs_list[i]

            if pkt[IP].dst in IPs2replace_list:
                i = IPs2replace_list.index(pkt[IP].dst)
                pkt[IP].dst = fake_IPs_list[i]
    
    wrpcap(sys.argv[1], pcap)