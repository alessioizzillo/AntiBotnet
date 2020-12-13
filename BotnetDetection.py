import threading
import ctypes
import pandas as pd
import requests
import os
from time import perf_counter

from utilities.network import *
from flow_based_detection.flow_based_detection import FlowBasedDetection
from IncrementalLearning import IncrementalLearning


class BotnetDetection(threading.Thread):
    def __init__(self, mode, fbd_n_estimators, gbd_n_estimators, bpf, test_malicious_IPs_list, captured_packets, flowbased_dataset, graphbased_dataset, IncrementalLearning_threads, flowbased_dataset_rwlock, GraphBasedDetection_lock):
        self.mode = mode
        self.fbd_n_estimators = fbd_n_estimators
        self.gbd_n_estimators = gbd_n_estimators
        self.bpf = bpf
        self.captured_packets = captured_packets
        self.flowbased_dataset = flowbased_dataset
        self.graphbased_dataset = graphbased_dataset
        self.IncrementalLearning_threads = IncrementalLearning_threads
        self.flowbased_dataset_rwlock = flowbased_dataset_rwlock
        self.GraphBasedDetection_lock = GraphBasedDetection_lock
        self.test_malicious_IPs_list = test_malicious_IPs_list
        self.p2p_IPs_list = []

        self.fbd_exec_time = 0

        self.n_true_pos = 0
        self.n_true_neg = 0
        self.n_false_pos = 0
        self.n_false_neg = 0
        self.len_results = 0

        threading.Thread.__init__(self)


    def run(self):
        print("---------------ANALYZING "+str(len(self.captured_packets.index))+" PACKETS---------------\n")
        print("Flow-baded detection dataset length:", len(self.flowbased_dataset))
        print()
        
        print("Sending captured packets to the hosts of the P2P network")
        bpf_hash_P2P_IPs = self.bpf['P2P_IPs']
        for i in bpf_hash_P2P_IPs.items():
            self.p2p_IPs_list.append(int2ip(i[0].value))

        print("P2P IPs list:", self.p2p_IPs_list)
        for ip in self.p2p_IPs_list:
            url = "http://{0}:9020".format(ip)
            try:
                print("  * Sending POST request to:", url)
                response = requests.post(url, json=self.captured_packets.to_json())
                print("  * Response from", ip, ":", response)
            except:
                print("  * ERROR: POST request to "+ip+" failed!")
                del bpf_hash_P2P_IPs[ctypes.c_uint(ip2int(ip))]


        print()

        with self.flowbased_dataset_rwlock.gen_rlock():
            start_time = perf_counter()
            flows, flow_results = FlowBasedDetection(self.captured_packets, self.flowbased_dataset, self.fbd_n_estimators)
            end_time = perf_counter()

        self.fbd_exec_time = end_time-start_time

        print("\n\nFLOW-BASED RESULTS: ", flow_results, "\n")

        self.IncrementalLearning_threads.put(IncrementalLearning(self.mode, self.gbd_n_estimators, self.bpf, self.test_malicious_IPs_list, self.captured_packets, flows, self.flowbased_dataset, self.graphbased_dataset, self.flowbased_dataset_rwlock, self.GraphBasedDetection_lock))

        bpf_hash_sospicious_IPs = self.bpf['sospicious_IPs']
        sospicious_IPs_list = []
        for i in bpf_hash_sospicious_IPs.items():
            sospicious_IPs_list.append((i[0].value, "GBD" if i[1].value == 1 else "FBD"))
        
        bpf_hash_P2P_IPs = self.bpf['P2P_IPs']
        P2P_IPs_list = []
        for i in bpf_hash_P2P_IPs.items():
            P2P_IPs_list.append((i[0].value, "GBD" if i[1].value == 1 else "FBD"))        

        self.len_results = len(flow_results)
        for t in flow_results:
            if self.mode == 'test':
                if (t[0] in self.test_malicious_IPs_list and t[1] == False):
                    self.n_false_neg += 1
                elif (t[0] not in self.test_malicious_IPs_list and t[1] == True):
                    self.n_false_pos += 1
                elif (t[0] not in self.test_malicious_IPs_list and t[1] == False):
                    self.n_true_neg += 1
                else:
                    self.n_true_pos += 1

            if (ip2int(t[0]), "GBD") not in sospicious_IPs_list and (ip2int(t[0]), "FBD") not in sospicious_IPs_list \
                and t[1] == True and ip2int(t[0]) not in P2P_IPs_list:
                bpf_hash_sospicious_IPs[ctypes.c_uint(ip2int(t[0]))] = ctypes.c_uint(0)

            elif (ip2int(t[0]), "FBD") in sospicious_IPs_list and t[1] == False:
                del bpf_hash_sospicious_IPs[ctypes.c_uint(ip2int(t[0]))]
        
        sospicious_IPs_list = []
        for i in bpf_hash_sospicious_IPs.items():
            sospicious_IPs_list.append((int2ip(i[0].value), "GBD" if i[1].value == 1 else "FBD"))
        print("SOSPICIOUS IPs LIST:",sospicious_IPs_list)
        print()

