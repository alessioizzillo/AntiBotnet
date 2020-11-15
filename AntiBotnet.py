from bcc import BPF
import sys
import ctypes
import pandas as pd
import time

from utilities.network import *
from utilities.task_queue import *
from BotnetDetection import BotnetDetection


if (len(sys.argv) == 3):
    # Interface on which capture packets
    interface = sys.argv[1]
    # Number of packets to analyze at a time
    n_packets = int(sys.argv[2])
else:
    print("\nUSAGE: sudo python3 AntiBotnet.py <interface> <number of packets to capture>\n")
    sys.exit(-1)

print("Starting AntiBotnet...\n")

# Initialize BPF - load source code from 'ebpf/eBPF_program.c.'
bpf = BPF(src_file="eBPF/eBPF_program.c", debug=0)

# Get pointer to bpf map 'local_ip' of type 'BPF_QUEUE' and assign the local IP to send to eBPF
# program
local_ip = bpf['local_ip']
local_ip.push(ctypes.c_uint(ip2int(socket.gethostbyname(socket.gethostname()))))

# Load eBPF program ebpf_program of type SOCKET_FILTER into the kernel eBPF vm.
function_ebpf_program = bpf.load_func("ebpf_program", BPF.SOCKET_FILTER)

# Create raw socket, bind it to interface and attach bpf program to socket created.
BPF.attach_raw_socket(function_ebpf_program, interface)

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
queue = TaskQueue()
queue.start()

while 1:
    n = 0
    while n < n_packets:
        try:
            # Get infos of the captured packet
            k = bpf_queue.pop()  
        except KeyError:
            # Continue to loop if the bpf map is empty waiting for the next element
            continue

        if (n == 0):
            start = k.timestamp

        # Compute the timestamp (in seconds) and add it to Unix epoch
        ts = (k.timestamp-start)/1000000000+time.time()

        # Update the Dataframe of the captured packets
        Packets.loc[len(Packets)] = [ts, int2ip(k.src_ip), int2ip(k.dst_ip), k.src_port, \
            k.dst_port, k.ethertype, k.protocol, k.tcp_Flags, k.len, k.tcp_payload_len, k.udp_len, k.ttl]

        n += 1
    
    # Start a thread to detect the normal and sospicious IPs present in captured traffic
    queue.put(BotnetDetection(bpf, Packets.copy(), flowbased_dataset))
    Packets.drop(Packets.index, inplace=True)