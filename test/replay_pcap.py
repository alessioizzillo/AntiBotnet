import socket
from time import perf_counter
import signal
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utilities.network import *

target_IPs = []
# n = 0


def signal_handler(signalNumber, frame):
    sys.exit(0)


def replay_pkt(pkt):
    global target_IPs

    host_IP = socket.gethostbyname(socket.gethostname())

    if (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
        if (pkt[IP].src == host_IP or pkt[IP].dst == host_IP):
            sendp(pkt, verbose=False)

    if target_IPs != None:
        if (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and \
            (pkt[IP].src in target_IPs or pkt[IP].dst in target_IPs)):

            if pkt[IP].src in target_IPs:
                pkt[IP].src = host_IP

            if pkt[IP].dst in target_IPs:
                pkt[IP].dst = host_IP

            sendp(pkt, verbose=False)


def replay_pcap(pcapfile, IPs2replace_file):
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)
    
    global target_IPs

    with open(IPs2replace_file, "r") as f:
        target_IPs = f.read().split("\n")[:-1]
    
    print("IPs to replace in the test file:\n", target_IPs)
    print()
    start_time = perf_counter()
    sniff(offline=pcapfile, prn=replay_pkt, store=0)
    end_time = perf_counter()
    print("TEST FINISHED! ("+str(end_time-start_time)+")\n")
    input()

    os.kill(os.getppid(), signal.SIGUSR1)
