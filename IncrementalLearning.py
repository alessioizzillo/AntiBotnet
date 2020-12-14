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
    def __init__(self, mode, gbd_n_estimators, bpf, test_malicious_IPs_list, captured_packets, flows, flowbased_dataset, graphbased_dataset, flowbased_dataset_rwlock, GraphBasedDetection_lock):
        self.mode = mode
        self.gbd_n_estimators = gbd_n_estimators
        self.bpf = bpf
        self.captured_packets = captured_packets
        self.flows = flows
        self.flowbased_dataset = flowbased_dataset
        self.graphbased_dataset = graphbased_dataset
        self.flowbased_dataset_rwlock = flowbased_dataset_rwlock
        self.GraphBasedDetection_lock = GraphBasedDetection_lock
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
        # n = 0
        # # All P2P hosts must write into shared_traffic/traffic.csv at least
        # # once before Graph detection starts
        # try:
        #     while(n <= self.retry):
        #         cont = 1
        #         bpf_hash_P2P_IPs = self.bpf['P2P_IPs']
        #         for i in bpf_hash_P2P_IPs.items():
        #             if int2ip(i[0].value) not in self.GraphBasedDetection_lock:
        #                 cont = 0
        #                 break
        #         if cont:
        #             break
        #         time.sleep(1)
        #         n += 1
        # except:
        #     pass

        lock = FileLock("shared_traffic/traffic.csv.lock")
        with lock:
            self.captured_packets.to_csv("shared_traffic/traffic.csv", mode='a', header=False, index=False)
            df = pd.read_csv("shared_traffic/traffic.csv")
            try:    
                self.GraphBasedDetection_lock[:] = []
            except:
                pass
            
        df.to_csv("test_traffic.csv", mode='a', header=False, index=False)

        start_time = perf_counter()
        graph_results = GraphBasedDetection("incremental", df, self.graphbased_dataset, self.gbd_n_estimators)
        end_time = perf_counter()

        self.gbd_exec_time = end_time-start_time
        
        print("GRAPH-BASED RESULTS: ", graph_results, "\n")

        bpf_hash_sospicious_IPs = self.bpf['sospicious_IPs']
        sospicious_IPs_list = []
        for i in bpf_hash_sospicious_IPs.items():
            sospicious_IPs_list.append((i[0].value, "GBD" if i[1].value == 1 else "FBD"))

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
                bpf_hash_sospicious_IPs[ctypes.c_uint(ip2int(t[0]))] = ctypes.c_uint(1)

            elif (ip2int(t[0]), "FBD") in sospicious_IPs_list and t[1] == False:
                del bpf_hash_sospicious_IPs[ctypes.c_uint(ip2int(t[0]))]
        
        sospicious_IPs_list = []
        for i in bpf_hash_sospicious_IPs.items():
            sospicious_IPs_list.append((int2ip(i[0].value), "GBD" if i[1].value == 1 else "FBD"))
        print("SOSPICIOUS IPs LIST:",sospicious_IPs_list)
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