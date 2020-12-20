import socket
import signal
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utilities.network import *

IP2replace = None
# n = 0


def signal_handler(signalNumber, frame):
    sys.exit(0)


def replay_pkt(pkt):
    global IP2replace

    host_IP = socket.gethostbyname(socket.gethostname())

    if (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
        if (pkt[IP].src == host_IP or pkt[IP].dst == host_IP):
            try:
                sendp(pkt, verbose=False)
            except Exception as e:
                print("***ERROR sendp: "+str(e)+" ***\n")

    if IP2replace != None:
        if (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and \
            (pkt[IP].src == IP2replace or pkt[IP].dst == IP2replace)):

            if pkt[IP].src == IP2replace:
                pkt[IP].src = host_IP

            if pkt[IP].dst == IP2replace:
                pkt[IP].dst = host_IP

            try:
                sendp(pkt, verbose=False)
            except Exception as e:
                print("***ERROR sendp: "+str(e)+" ***\n")


def replay_pcap(pcapfile, IPs2replace_file, IP2replace_pos):
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)
    
    global IP2replace

    with open(IPs2replace_file, "r") as f:
        IPs2replace_list = f.read().split("\n")
    while ("" in IPs2replace_list):
        IPs2replace_list.remove("")
    
    IP2replace = IPs2replace_list[IP2replace_pos]

    print("IP to replace in the test file: "+IP2replace+" (pos: "+str(IP2replace_pos)+")")
    print()

    sniff(offline=pcapfile, prn=replay_pkt, store=0)

    os.kill(os.getppid(), signal.SIGUSR1)

