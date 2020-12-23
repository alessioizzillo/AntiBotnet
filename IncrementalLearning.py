from filelock import FileLock
import threading
import ctypes
import pandas as pd
import os
from time import perf_counter
import socket
import time

from utilities.network import *
from graph_based_detection.graph_based_detection import GraphBasedDetection


class IncrementalLearning(threading.Thread):
    def __init__(self, mode, GBD_classifier, bpf, test_malicious_IPs_list, captured_packets, flows, flowbased_dataset, flowbased_dataset_rwlock):
        self.mode = mode
        self.bpf = bpf
        self.captured_packets = captured_packets
        self.flows = flows
        self.flowbased_dataset = flowbased_dataset
        self.GBD_classifier = GBD_classifier
        self.flowbased_dataset_rwlock = flowbased_dataset_rwlock
        self.test_malicious_IPs_list = test_malicious_IPs_list

        self.retry = 5

        self.gbd_exec_time = 0

        self.n_true_pos = 0
        self.n_true_neg = 0
        self.n_false_pos = 0
        self.n_false_neg = 0
        self.len_results = 0

        threading.Thread.__init__(self)


    def run(self):
        lock = FileLock("global_P2P_traffic/traffic.csv.lock")
        with lock:
            self.captured_packets.to_csv("global_P2P_traffic/traffic.csv", mode='a', header=False, index=False)
            df = pd.read_csv("global_P2P_traffic/traffic.csv")
            
        start_time = perf_counter()
        graph_results = GraphBasedDetection("incremental", self.GBD_classifier, df)
        end_time = perf_counter()

        self.gbd_exec_time = end_time-start_time
        
        print("GRAPH-BASED RESULTS: ", graph_results, "\n")

        bpf_hash_suspicious_IPs = self.bpf['suspicious_IPs']
        suspicious_IPs_list = []
        for i in bpf_hash_suspicious_IPs.items():
            suspicious_IPs_list.append((i[0].value, "GBD" if i[1].value == 1 else "FBD"))

        bpf_hash_P2P_IPs = self.bpf['P2P_IPs']
        P2P_IPs_list = []
        for i in bpf_hash_P2P_IPs.items():
            P2P_IPs_list.append(i[0].value)   

        self.len_results = len(graph_results)
        for t in graph_results:

            if self.mode == 'test':
                if (t[0] in self.test_malicious_IPs_list and t[1] == False):
                    self.n_false_neg += 1
                elif (t[0] not in self.test_malicious_IPs_list and t[1] == True):
                    self.n_false_pos += 1
                elif (t[0] not in self.test_malicious_IPs_list and t[1] == False):
                    self.n_true_neg += 1
                else:
                    self.n_true_pos += 1

            if t[1] == True and ip2int(t[0]) not in P2P_IPs_list:
                bpf_hash_suspicious_IPs[ctypes.c_uint(ip2int(t[0]))] = ctypes.c_uint(1)

            elif (ip2int(t[0]), "FBD") in suspicious_IPs_list and t[1] == False:
                del bpf_hash_suspicious_IPs[ctypes.c_uint(ip2int(t[0]))]
        
        suspicious_IPs_list = []
        for i in bpf_hash_suspicious_IPs.items():
            suspicious_IPs_list.append((int2ip(i[0].value), "GBD" if i[1].value == 1 else "FBD"))
        print("SUSPICIOUS IPs LIST:",suspicious_IPs_list)
        print()

        # print("   * Updating flow-based detection dataset (Incremental Learning)...\n")
        graph_malicious_IPs = []
        for i in graph_results:
            if i[1] == True and ip2int(i[0]) not in P2P_IPs_list:
                graph_malicious_IPs.append(ip2int(i[0]))

        self.flows['Label'] = self.flows.apply(lambda x: 1 if float(x['SrcIP']) in graph_malicious_IPs or \
            float(x['DstIP']) in graph_malicious_IPs else 0, axis=1)

        with self.flowbased_dataset_rwlock.gen_wlock():
            for i, r in self.flows.iterrows():
                self.flowbased_dataset.loc[len(self.flowbased_dataset)] = r