import sys
import socket
from flow_based_detection.flow_features_extractor import FlowFeaturesExtractor
sys.path.append("..")
from ml.random_forest_classifier import RandomForestClassifier
from utilities.network import *


def FlowBasedDetection(captured_packets, dataset):
    print("FLOW-BASED DETECTION:")

    local_ip = socket.gethostbyname(socket.gethostname())

    malicious_IPs_list = []
    with open("dataset/malicious_IPs.txt") as malicious_IPs:
        malicious_IPs_list = malicious_IPs.readlines()

    print("   * Extracting flow features...")
    flows = FlowFeaturesExtractor(captured_packets, 'predicting', malicious_IPs_list)

    print("   * Predicting...")
    Y_Pred = RandomForestClassifier(flows, dataset)

    results = []
    for i in range(0,len(Y_Pred)):
        results.append((int2ip(int(flows.iloc[i]['SrcIP'])) if int(flows.iloc[i]['SrcIP']) != ip2int(local_ip) else int2ip(int(flows.iloc[i]['DstIP'])), \
            True if Y_Pred[i] == 1 else False))

    results = list(dict.fromkeys(results))

    return results