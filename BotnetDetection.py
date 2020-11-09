from threading import Thread
import ctypes

from utilities.network import *
from flow_based_detection.flow_based_detection import FlowBasedDetection


class BotnetDetection(Thread):
    def __init__(self, bpf, captured_packets, flowbased_dataset):
        self.bpf = bpf
        self.captured_packets = captured_packets
        self.flowbased_dataset = flowbased_dataset
        Thread.__init__(self)

    def run(self):
        print("Analyzing "+str(len(self.captured_packets.index))+" packets...")
        sospicious_IPs = FlowBasedDetection(self.captured_packets, self.flowbased_dataset)

        bpf_hash_sospicious_IPs = self.bpf['sospicious_IPs']
        bpf_hash_sospicious_IPs.clear()
        for ip in sospicious_IPs:
            bpf_hash_sospicious_IPs[ctypes.c_uint(ip2int(ip))] = ctypes.c_byte(0)

    def raise_exception(self): 
        thread_id = self.get_id() 
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 
              ctypes.py_object(SystemExit)) 
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0) 
            print('Exception raise failure')