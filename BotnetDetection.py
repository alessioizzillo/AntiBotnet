from threading import Thread
import ctypes
from filelock import FileLock
import pandas as pd
import requests

from utilities.network import *
from flow_based_detection.flow_based_detection import FlowBasedDetection
from graph_based_detection.graph_based_detection import GraphBasedDetection


class BotnetDetection(Thread):
    def __init__(self, bpf, p2p_IPs_list, captured_packets, flowbased_dataset, graphbased_dataset):
        self.bpf = bpf
        self.captured_packets = captured_packets
        self.flowbased_dataset = flowbased_dataset
        self.graphbased_dataset = graphbased_dataset
        self.p2p_IPs_list = p2p_IPs_list
        Thread.__init__(self)


    def run(self):
        print("Sending captured packets to the hosts of the P2P network")
        print("P2P IPs list:", self.p2p_IPs_list)       
        for ip in self.p2p_IPs_list:
            url = "http://{0}:9020".format(ip)
            response = requests.post(url, json=self.captured_packets.to_json())
            print("  * Response from", ip, ":", response)

        print("---------------ANALYZING "+str(len(self.captured_packets.index))+" PACKETS---------------\n")
        flow_results = FlowBasedDetection(self.captured_packets, self.flowbased_dataset)
        print()

        print("Flow RESULTS \n", flow_results, "\n")
        
        # bpf_hash_sospicious_IPs = self.bpf['sospicious_IPs']
        # bpf_hash_sospicious_IPs.clear()
        # for ip in sospicious_IPs:
        #     bpf_hash_sospicious_IPs[ctypes.c_uint(ip)] = ctypes.c_byte(0)

    def raise_exception(self): 
        thread_id = self.get_id() 
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, ctypes.py_object(SystemExit)) 
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0) 
            print('**ERROR**: BotnetDetection thread exception raise failure')