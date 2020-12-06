import socket
import time
import signal
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utilities.network import *

target_IP = None


def signal_handler(signalNumber, frame):
    sys.exit(0)


def replay_pkt(pkt):
    global target_IP

    if target_IP != None:
        if (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and \
            (pkt[IP].src == target_IP or pkt[IP].dst == target_IP)):

            if pkt[IP].src == target_IP:
                pkt[IP].src = socket.gethostbyname(socket.gethostname())

            if pkt[IP].dst == target_IP:
                pkt[IP].dst = socket.gethostbyname(socket.gethostname())

            sendp(pkt, verbose=False)
    else:
        sendp(pkt, verbose=False)


def replay_pcap(pcapfile, ip2replace):
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)
    
    global target_IP
    target_IP = ip2replace
    
    sniff(offline=pcapfile, prn=replay_pkt, store=0)
    
    os.kill(os.getppid(), signal.SIGUSR1)
