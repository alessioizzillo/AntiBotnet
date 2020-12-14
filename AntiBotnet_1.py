import sys
import os
import signal
from bcc import BPF
from bcc.table import QueueStack
import ctypes
import pandas as pd
from time import time
import signal
from multiprocessing import Process
from multiprocessing.managers import SyncManager
from readerwriterlock import rwlock

from utilities.network import *
from utilities.task_queue import *
from p2p.gnutella_p2p import Start_P2P
from BotnetDetection import BotnetDetection
from ml.random_forest_classifier import RandomForestClassifier_train

if os.path.dirname(os.path.abspath(__file__))+'/test' not in sys.path:
    sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/test')

from replay_pcap import replay_pcap


bpf = None
BotnetDetection_threads = None
IncrementalLearning_threads = None
p2p_process = None
test_process = None
ignored_IPs = ['192.168.1.1']


def signal_handler(signalNumber, frame):
    global bpf
    global p2p_process
    global test_process
    global BotnetDetection_threads
    global IncrementalLearning_threads
    
    if signalNumber == signal.SIGUSR1:
        IncrementalLearning_threads.stop_when_empty()
        BotnetDetection_threads.stop_when_empty()
        IncrementalLearning_threads.join()
        BotnetDetection_threads.join()
        os.kill(p2p_process.pid, signal.SIGINT)
        os.kill(test_process.pid, signal.SIGINT)
        p2p_process.join()
        test_process.join()

        print("TEST FINISHED!\n")

        bpf_hash_sospicious_IPs = bpf['sospicious_IPs']

        sospicious_IPs_list = []
        for i in bpf_hash_sospicious_IPs.items():
            sospicious_IPs_list.append((int2ip(i[0].value), "GBD" if i[1].value == 1 else "FBD"))

        print("*****TEST RESULTS*****")
        print(sospicious_IPs_list)

    else:
        try:
            p2p_process.join()
            IncrementalLearning_threads.stop()
            BotnetDetection_threads.stop()
            IncrementalLearning_threads.join()
            BotnetDetection_threads.join()
            test_process.join()
        except:
            pass
    
    print("\n---ANTIBOTNET (EXIT)---\n")

    sys.exit(0)


def manager_init():
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTSTP, signal.default_int_handler)


def AntiBotnet(mode, interface, n_packets, fbd_n_estimators, gbd_n_estimators, test_pcapfile, IPs2replace_file, test_malicious_IPs_list, target_P2P_IP):
    print("\n---ANTIBOTNET ("+mode.upper()+" MODE)---\n")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)

    manager = SyncManager()
    manager.start(manager_init)
    GraphBasedDetection_lock = manager.list()
    
    global bpf
    # Initialize BPF - load source code from 'ebpf/eBPF_program.c.'
    bpf = BPF(src_file=os.path.dirname(os.path.abspath(__file__))+"/eBPF/eBPF_program.c", debug=0)

    print("Connecting to P2P network:")

    if not os.path.isdir(os.path.dirname(os.path.abspath(__file__))+"/global_P2P_traffic"):
        os.makedirs(os.path.dirname(os.path.abspath(__file__))+"/global_P2P_traffic")

    df_global_P2P_traffic = pd.DataFrame(columns=['Time', 'Source', 'Destination', 'Source Port', 'Destination Port', \
        'EtherType', 'Protocol', 'TCP Flags', 'Length', 'TCP Payload Length', 'UDP Length', 'TTL'])
    df_global_P2P_traffic.to_csv("global_P2P_traffic/traffic.csv", mode="w", index=False)     

    global p2p_process
    p2p_process = Process(target=Start_P2P, args=(GraphBasedDetection_lock, bpf, target_P2P_IP, ))
    p2p_process.start()

    local_ip = bpf['local_ip']
    local_ip.push(ctypes.c_uint(ip2int(socket.gethostbyname(socket.gethostname()))), flags=QueueStack.BPF_EXIST)

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

    bpf_hash_sospicious_IPs = bpf['sospicious_IPs']
    bpf_hash_sospicious_IPs.clear()

    n = 0
    # Dataframe to store the captured packets
    Packets = pd.DataFrame(columns=['Time', 'Source', 'Destination', 'Source Port', 'Destination Port', \
        'EtherType', 'Protocol', 'TCP Flags', 'Length', 'TCP Payload Length', 'UDP Length', 'TTL'])

    flowbased_dataset = pd.read_hdf(os.path.dirname(os.path.abspath(__file__))+"/flow_based_detection/training_dataset/training.hdf5")
    graphbased_dataset = pd.read_hdf(os.path.dirname(os.path.abspath(__file__))+"/graph_based_detection/training_dataset/training.hdf5")

    GBD_classifier = RandomForestClassifier_train(graphbased_dataset, gbd_n_estimators)

    global IncrementalLearning_threads
    IncrementalLearning_threads = TaskQueue(mode, "IncrementalLearning")
    IncrementalLearning_threads.start()

    global BotnetDetection_threads
    BotnetDetection_threads = TaskQueue(mode, "BotnetDetection")
    BotnetDetection_threads.start()

    if (mode == 'test'):
        global test_process
        test_process = Process(target=replay_pcap, args=(test_pcapfile, IPs2replace_file))
        test_process.start()

        signal.signal(signal.SIGUSR1, signal_handler)

        df_test_results = pd.DataFrame(columns=['Detection method', 'BotnetDetection  execution time', 'IncrementalLearning execution time'\
            'FlowBasedDetection execution time', 'GraphBasedDetection execution time', 'True Positives', 'True Negatives', 'False Positive', 'False Negative', 'Total predictions'])
        df_test_results.to_csv("test_results.csv", index=False)         

    flowbased_dataset_rwlock = rwlock.RWLockFairD()

    print("Started to capture packets...\n")
    while 1:
        n = 0
        while n < n_packets:
            try:
                # Get infos of the captured packet
                k = bpf_queue.pop()
            except KeyError:
                continue

            if (int2ip(k.src_ip) not in ignored_IPs) and (int2ip(k.dst_ip) not in ignored_IPs):
                if (n == 0):
                    start = k.timestamp

                # Compute the timestamp (in seconds) and add it to Unix epoch
                ts = (k.timestamp-start)/1000000000+time()

                # Update the Dataframe of the captured packets
                Packets.loc[len(Packets)] = [ts, k.src_ip, k.dst_ip, k.src_port, \
                    k.dst_port, k.ethertype, k.protocol, k.tcp_Flags, k.len, k.tcp_payload_len, k.udp_len, k.ttl]

                n += 1

        # Start a thread to detect the normal and sospicious IPs present in captured traffic
        if mode == 'test':
            BotnetDetection_threads.put(BotnetDetection(mode, fbd_n_estimators, GBD_classifier, bpf, test_malicious_IPs_list, Packets.copy(), flowbased_dataset, IncrementalLearning_threads, flowbased_dataset_rwlock, GraphBasedDetection_lock))
        else:
            BotnetDetection_threads.put(BotnetDetection(mode, fbd_n_estimators, GBD_classifier, bpf, None, Packets.copy(), flowbased_dataset, IncrementalLearning_threads, flowbased_dataset_rwlock, GraphBasedDetection_lock))
        Packets.drop(Packets.index, inplace=True)



if __name__ == '__main__':
    error = 0

    if (len(sys.argv) > 1):
        mode = sys.argv[1]
    else:
        error = 1

    if error == 0 and mode == 'test' or mode == 'real-world':
        if (len(sys.argv) == 6):
            interface = sys.argv[2]
            try:
                n_packets = int(sys.argv[3])
            except:
                print("\n**ERROR**: inserted 'number of packets' (arg 3) is not numeric!")
                error = 1

            if not error:
                try:
                    fbd_n_estimators = int(sys.argv[4])
                except:
                    print("\n**ERROR**: inserted 'number of RF estimators' (arg 4) is not numeric!\n")
                    error = 1

            if not error:
                try:
                    gbd_n_estimators = int(sys.argv[5])
                except:
                    print("\n**ERROR**: inserted 'number of RF estimators' (arg 5) is not numeric!\n")
                    error = 1

            target_P2P_IP = None

        elif (len(sys.argv) == 7):
            interface = sys.argv[2]
            try:
                n_packets = int(sys.argv[3])
            except:
                print("\n**ERROR**: inserted 'number of packets' (arg 3) is not numeric!")
                error = 1

            if not error:
                try:
                    fbd_n_estimators = int(sys.argv[4])
                except:
                    print("\n**ERROR**: inserted 'number of RF estimators' (arg 4) is not numeric!\n")
                    error = 1

            if not error:
                try:
                    gbd_n_estimators = int(sys.argv[5])
                except:
                    print("\n**ERROR**: inserted 'number of RF estimators' (arg 5) is not numeric!\n")
                    error = 1

            if not error:
                target_P2P_IP = sys.argv[6]
                if str(ip2int(target_P2P_IP)) == 'nan':
                    print("\n**ERROR**: inserted 'P2P IP' (arg 6) is not valid!")
                    error = 1
        else:
            error = 1

    else:
        error = 1


    if error:
        print("\nUSAGE (TEST MODE)")
        print("sudo python3 AntiBotnet.py test <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier>")
        print("sudo python3 AntiBotnet.py test <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier> <IP of an active host of the P2P network>")
        print("\nUSAGE (REAL-WORLD MODE)")
        print("sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier>")
        print("sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier> <IP of an active host of the P2P network>\n")
        sys.exit(-1)

    if mode == 'test':
        print("\nPut the path of the pcap file to test:")
        test_pcapfile = input()
        while not os.path.exists(test_pcapfile):
            print("\n**ERROR**: inserted 'test pcap' file does not exist!\n")
            print("Put the path of the pcap file to test:")
            test_pcapfile = input()
        
        print("\nPut the path of the file where IPs to replace into 'test pcap' file are listed:")
        IPs2replace_file = input()
        while not os.path.exists(IPs2replace_file):
            print("\n**ERROR**: inserted 'IPs to replace' file is not valid!\n")
            print("Put the path of the file where IPs to replace into 'test pcap' file are listed:")
            IPs2replace_file = input()

        print("\nPut the path of the file where malicious IPs of the 'test pcap' file are listed:")
        test_malicious_IPs_file = input()
        while not os.path.exists(test_malicious_IPs_file):
            print("\n**ERROR**: inserted 'test malicious IPs' file does not exist!\n")
            print("Put the path of the file where malicious IPs of the 'test pcap' file are listed:")
            test_malicious_IPs_file = input()

        with open(test_malicious_IPs_file) as malicious_IPs:
            test_malicious_IPs_list = malicious_IPs.read()
        
        test_malicious_IPs_list = test_malicious_IPs_list.split('\n')
        while ("" in test_malicious_IPs_list):
            test_malicious_IPs_list.remove("")

        print("\nTEST malicious IPs:", test_malicious_IPs_list)
        print()

        AntiBotnet(mode, interface, n_packets, fbd_n_estimators, gbd_n_estimators, test_pcapfile, IPs2replace_file, test_malicious_IPs_list, target_P2P_IP)
    else:
        AntiBotnet(mode, interface, n_packets, fbd_n_estimators, gbd_n_estimators, None, None, None, target_P2P_IP)

