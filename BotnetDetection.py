import threading
import ctypes
from filelock import FileLock
import pandas as pd
import requests
from csv import writer
import os

from utilities.network import *
from flow_based_detection.flow_based_detection import FlowBasedDetection
from graph_based_detection.graph_based_detection import GraphBasedDetection


class BotnetDetection(threading.Thread):
    def __init__(self, mode, bpf, test_malicious_IPs_list, captured_packets, graphbased_dataset):
        self.mode = mode
        self.bpf = bpf
        self.captured_packets = captured_packets
        self.flowbased_dataset = None
        self.graphbased_dataset = graphbased_dataset
        self.test_malicious_IPs_list = test_malicious_IPs_list
        self.p2p_IPs_list = []
        bpf_hash_P2P_IPs = self.bpf['P2P_IPs']
        for i in bpf_hash_P2P_IPs.items():
            self.p2p_IPs_list.append(i[0].value)
        
        threading.Thread.__init__(self)


    def run(self):
        self.flowbased_dataset = pd.read_csv(os.path.dirname(os.path.abspath(__file__))+"/flow_based_detection/training_dataset/incremental_learning.csv")
        
        print("Sending captured packets to the hosts of the P2P network")
        print("P2P IPs list:", self.p2p_IPs_list)      
        for ip in self.p2p_IPs_list:
            url = "http://{0}:9020".format(ip)
            response = requests.post(url, json=self.captured_packets.to_json())
            print("  * Response from", ip, ":", response)

        print("---------------ANALYZING "+str(len(self.captured_packets.index))+" PACKETS---------------\n")
        flows, flow_results = FlowBasedDetection(self.captured_packets, self.flowbased_dataset)
        print()
        
        if not os.path.isdir(os.path.dirname(os.path.abspath(__file__))+"/shared_traffic"):
            os.makedirs(os.path.dirname(os.path.abspath(__file__))+"/shared_traffic")
        
        lock = FileLock(os.path.dirname(os.path.abspath(__file__))+"/shared_traffic/traffic.csv.lock")
        with lock:
            try:
                df = pd.read_csv(os.path.dirname(os.path.abspath(__file__))+"/shared_traffic/traffic.csv")
                df = pd.concat([df, self.captured_packets], ignore_index=True)
                df = df.sort_values(['Time'])
                open(os.path.dirname(os.path.abspath(__file__))+"/shared_traffic/traffic.csv", "w")
            except:
                df = self.captured_packets
        
        graph_results = GraphBasedDetection(df, self.graphbased_dataset)

        print()
        print("Flow RESULTS: ", flow_results, "\n")
        print("Graph RESULTS: ", graph_results, "\n")

        print("   * Updating flow-based detection dataset (Incremental Learning)...\n")
        graph_malicious_IPs = []
        for i in graph_results:
            if i[1] == True:
                graph_malicious_IPs.append(ip2int(i[0]))

        flows['Label'] = flows.apply(lambda x: 1 if float(x['SrcIP']) in graph_malicious_IPs or \
            float(x['DstIP']) in graph_malicious_IPs else 0, axis=1)
        flows.to_csv("flow_based_detection/training_dataset/incremental_learning.csv", \
            header=False, index=False, mode='a')

        results = flow_results # TO CHANGE

        bpf_hash_sospicious_IPs = self.bpf['sospicious_IPs']
        
        sospicious_IPs_list = []
        for i in bpf_hash_sospicious_IPs.items():
            sospicious_IPs_list.append(i[0].value)

        n_false_pos = 0
        n_false_neg = 0
        for t in results:
            if self.mode == 'test':  
                if (t[0] in self.test_malicious_IPs_list and t[1] == False):
                    n_false_neg += 1
                elif (t[0] not in self.test_malicious_IPs_list and t[1] == True):
                    n_false_pos += 1

            if ip2int(t[0]) not in sospicious_IPs_list and t[1] == True:
                bpf_hash_sospicious_IPs[ctypes.c_uint(ip2int(t[0]))] = ctypes.c_uint(0)
            elif ip2int(t[0]) in sospicious_IPs_list and t[1] == False:
                del bpf_hash_sospicious_IPs[ctypes.c_uint(ip2int(t[0]))]

        if self.mode == 'test':       
            with open("test_results.csv", 'a+', newline='') as write_obj:
                csv_writer = writer(write_obj)
                csv_writer.writerow([n_false_pos, n_false_neg, len(results)])
