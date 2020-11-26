import os, signal
from bcc import BPF
import sys
import ctypes
import pandas as pd
import time
from multiprocessing import Process, Manager

from utilities.network import *
from utilities.task_queue import *
from p2p.gnutella_p2p import Start_P2P
from BotnetDetection import BotnetDetection



if __name__ == '__main__':
    error = 0
    if (len(sys.argv) == 3):
        interface = sys.argv[1]
        try:
            n_packets = int(sys.argv[2])
        except:
            print("\n**ERROR**: n_packets (arg 2) not numeric!")
            error = 1
        targetIP = None
    elif (len(sys.argv) == 4):
        interface = sys.argv[1]
        try:
            n_packets = int(sys.argv[2])
        except:
            print("\n**ERROR**: n_packets (arg 2) not numeric!")
            error = 1
        if not error:
            targetIP = sys.argv[3]
            if str(ip2int(targetIP)) == 'nan':
                print("\n**ERROR**: tartetIP (arg 3) not in IPv4 format!")
                error = 1
    else:
        error = 1

    if error:
        print("\nUSAGE: sudo python3 AntiBotnet.py <interface> <number of packets to capture>")
        print("USAGE: sudo python3 AntiBotnet.py <interface> <number of packets to capture> <IP of an active host of the P2P network>\n")
        sys.exit(-1)

    print("\n---ANTIBOTNET---\n")
    manager = Manager()
    p2p_IPs_list = manager.list()

    print("Connecting to P2P network:")

    child_process = Process(target=Start_P2P, args=(p2p_IPs_list, targetIP, ))
    child_process.start()

    # Initialize BPF - load source code from 'ebpf/eBPF_program.c.'
    bpf = BPF(src_file="eBPF/eBPF_program.c", debug=0)

    local_ip = bpf['local_ip']
    local_ip.push(ctypes.c_uint(ip2int(socket.gethostbyname(socket.gethostname()))))

    # Load eBPF program ebpf_program of type SOCKET_FILTER into the kernel eBPF vm.
    function_ebpf_program = bpf.load_func("ebpf_program", BPF.SOCKET_FILTER)

    # Create raw socket, bind it to interface and attach bpf program to socket created.
    try:
        BPF.attach_raw_socket(function_ebpf_program, interface)
    except:
        print("\n**ERROR**: interface (arg 1) not valid!")
        os.kill(child_process.pid, signal.SIGTSTP)
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

    flowbased_dataset = pd.read_hdf("flow_based_detection/training_dataset/training.hdf5")
    graphbased_dataset = pd.read_hdf("graph_based_detection/training_dataset/training.hdf5")
    queue = TaskQueue()
    queue.start()

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
        queue.put(BotnetDetection(bpf, p2p_IPs_list, Packets.copy(), flowbased_dataset, graphbased_dataset))
        Packets.drop(Packets.index, inplace=True)
        