import sys
import os
import signal
from bcc import BPF
import ctypes
import pandas as pd
import time
import signal
from multiprocessing import Process
from multiprocessing.managers import SyncManager

from utilities.network import *
from utilities.task_queue import *
from p2p.gnutella_p2p import Start_P2P
from BotnetDetection import BotnetDetection

if os.path.dirname(os.path.abspath(__file__))+'/test' not in sys.path:
    sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/test')

from replay_pcap import replay_pcap


taskqueue_thread = None
p2p_process = None
test_process = None



def signal_handler(signalNumber, frame):
    global p2p_process
    global test_process
    global taskqueue_thread
    
    if signalNumber == signal.SIGUSR1:
        os.kill(p2p_process.pid, signal.SIGINT)
        os.kill(test_process.pid, signal.SIGINT)

    try:
        p2p_process.join()
        taskqueue_thread.stop()
        test_process.join()
    except:
        pass

    sys.exit(0)


def manager_init():
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTSTP, signal.default_int_handler)


def AntiBotnet(mode, interface, n_packets, test_pcapfile, ip2replace, test_malicious_IPs_list, targetIP):
    print("\n---ANTIBOTNET ("+mode.upper()+" MODE)---\n")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)

    manager = SyncManager()
    manager.start(manager_init)
    p2p_IPs_list = manager.list()

    # Initialize BPF - load source code from 'ebpf/eBPF_program.c.'
    bpf = BPF(src_file=os.path.dirname(os.path.abspath(__file__))+"/eBPF/eBPF_program.c", debug=0)

    print("Connecting to P2P network:")

    global p2p_process
    p2p_process = Process(target=Start_P2P, args=(p2p_IPs_list, bpf, target_P2P_IP, ))
    p2p_process.start()

    local_ip = bpf['local_ip']
    local_ip.push(ctypes.c_uint(ip2int(socket.gethostbyname(socket.gethostname()))))

    # Load eBPF program ebpf_program of type SOCKET_FILTER into the kernel eBPF vm.
    function_ebpf_program = bpf.load_func("ebpf_program", BPF.SOCKET_FILTER)

    # Create raw socket, bind it to interface and attach bpf program to socket created.
    try:
        BPF.attach_raw_socket(function_ebpf_program, interface)
    except:
        print("\n**ERROR**: interface (arg 1) not valid!")
        os.kill(p2p_process.pid, signal.SIGTSTP)
        print("\nUSAGE: sudo python3 AntiBotnet.py <interface> <number of packets to capture>")
        print("USAGE: sudo python3 AntiBotnet.py <interface> <number of packets to capture> <IP of an active host of the P2P network>\n")
        sys.exit(-1)

    # Get file descriptor of the socket previously created inside BPF.attach_raw_socket.
    socket_fd = function_ebpf_program.sock

    # Create python socket object, from the file descriptor
    sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Set it as blocking socket
    sock.setblocking(True)

    # Get pointer to bpf map 'queue' of type 'BPF_QUEUE'
    bpf_queue = bpf['queue']

    n = 0
    # Dataframe to store the captured packets
    Packets = pd.DataFrame(columns=['Time', 'Source', 'Destination', 'Source Port', 'Destination Port', \
        'EtherType', 'Protocol', 'TCP Flags', 'Length', 'TCP Payload Length', 'UDP Length', 'TTL'])

    flowbased_dataset = pd.read_hdf(os.path.dirname(os.path.abspath(__file__))+"/flow_based_detection/training_dataset/training.hdf5")
    graphbased_dataset = pd.read_hdf(os.path.dirname(os.path.abspath(__file__))+"/graph_based_detection/training_dataset/training.hdf5")

    global taskqueue_thread
    taskqueue_thread = TaskQueue()
    taskqueue_thread.start()

    if (mode == 'test'):
        global test_process
        test_process = Process(target=replay_pcap, args=(test_pcapfile, ip2replace))
        test_process.start()

        signal.signal(signal.SIGUSR1, signal_handler)

        df_test_results = pd.DataFrame(columns=['False Positive', 'False Negative', 'Total predictions'])
        df_test_results.to_csv("test_results.csv", index=False)            


    while 1:
        n = 0
        while n < n_packets:
            try:
                # Get infos of the captured packet
                k = bpf_queue.pop()
            except KeyError:
                continue

            if (n == 0):
                start = k.timestamp

            # Compute the timestamp (in seconds) and add it to Unix epoch
            ts = (k.timestamp-start)/1000000000+time.time()

            # Update the Dataframe of the captured packets
            Packets.loc[len(Packets)] = [ts, k.src_ip, k.dst_ip, k.src_port, \
                k.dst_port, k.ethertype, k.protocol, k.tcp_Flags, k.len, k.tcp_payload_len, k.udp_len, k.ttl]

            n += 1

        # Start a thread to detect the normal and sospicious IPs present in captured traffic
        if mode == 'test':
            taskqueue_thread.put(BotnetDetection(mode, bpf, test_malicious_IPs_list, Packets.copy(), flowbased_dataset, graphbased_dataset))
        else:
            taskqueue_thread.put(BotnetDetection(mode, bpf, None, Packets.copy(), flowbased_dataset, graphbased_dataset))
        Packets.drop(Packets.index, inplace=True)


if __name__ == '__main__':
    error = 0

    if (len(sys.argv) > 1):
        mode = sys.argv[1]
    else:
        error = 1

    if error == 0 and mode == 'test' or mode == 'real-world':
        if (len(sys.argv) == 4):
            interface = sys.argv[2]
            try:
                n_packets = int(sys.argv[3])
            except:
                print("\n**ERROR**: 'number of packets' (arg 3) is not numeric!")
                error = 1
            target_P2P_IP = None

        elif (len(sys.argv) == 5):
            interface = sys.argv[2]
            try:
                n_packets = int(sys.argv[3])
            except:
                print("\n**ERROR**: 'number of packets' (arg 3) is not numeric!")
                error = 1

            if not error:
                target_P2P_IP = sys.argv[4]
                if str(ip2int(target_P2P_IP)) == 'nan':
                    print("\n**ERROR**: 'P2P IP' (arg 4) is not valid!")
                    error = 1
        else:
            error = 1

    else:
        error = 1


    if error:
        print("\nUSAGE (TEST MODE)")
        print("sudo python3 AntiBotnet.py test <interface> <number of packets to capture>")
        print("sudo python3 AntiBotnet.py test <interface> <number of packets to capture> <IP of an active host of the P2P network>")
        print("\nUSAGE (REAL-WORLD MODE)")
        print("sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture>")
        print("sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <IP of an active host of the P2P network>\n")
        sys.exit(-1)

    if mode == 'test':
        print("\nPut the path of the pcap file to test:")
        test_pcapfile = input()
        while not os.path.exists(test_pcapfile):
            print("\n**ERROR**: inserted 'test pcap file' does not exist!\n")
            print("Put the path of the pcap file to test:")
            test_pcapfile = input()
        
        print("\nPut the IP to replace into test pcap file:")
        ip2replace = input()
        while str(ip2int(ip2replace)) == 'nan':
            print("\n**ERROR**: inserted 'IP to replace' is not valid!\n")
            print("Put the IP to replace into test pcap file:")
            ip2replace = input()

        print("\nPut the path of the file where malicious IPs of the test pcap file are listed:")
        test_malicious_IPs_file = input()
        while not os.path.exists(test_malicious_IPs_file):
            print("\n**ERROR**: inserted 'test pcap file' does not exist!\n")
            print("Put the path of the pcap file to test:")
            test_malicious_IPs_file = input()

        with open(test_malicious_IPs_file) as malicious_IPs:
            test_malicious_IPs_list = malicious_IPs.read()
        
        test_malicious_IPs_list = test_malicious_IPs_list.split('\n')

    if (mode == 'test'):
        AntiBotnet(mode, interface, n_packets, test_pcapfile, ip2replace, test_malicious_IPs_list, target_P2P_IP)
    else:
        AntiBotnet(mode, interface, n_packets, None, None, None, target_P2P_IP)
