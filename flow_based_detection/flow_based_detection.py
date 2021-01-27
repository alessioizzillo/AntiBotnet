import socket
import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flow_based_detection.flow_features_extractor import FlowFeaturesExtractor
from ml.random_forest_classifier import *
from utilities.network import *


def FlowBasedDetection(captured_packets, train_dataset, fbd_n_estimators):
    print("FLOW-BASED DETECTION:")

    local_ip = socket.gethostbyname(socket.gethostname())

    print("   * Extracting flow features...")
    flows = FlowFeaturesExtractor(captured_packets, 'predicting', None)

    print("\n   * Training...")
    classifier = RandomForestClassifier_train(train_dataset, fbd_n_estimators)
    print("\n   * Predicting...")
    Y_Pred = RandomForestClassifier_predict("proba", classifier, flows)

    proba_results_temp = []
    for i in range(0,len(Y_Pred)):
        proba_results_temp.append((int2ip(int(flows.iloc[i]['SrcIP'])) if int(flows.iloc[i]['SrcIP']) != ip2int(local_ip) else int2ip(int(flows.iloc[i]['DstIP'])), \
            Y_Pred[i]))
    
    proba_results = []
    results = []
    prev_ip = None
    sum_proba = 0
    count = 0
    for i in range(len(proba_results_temp)):
        if prev_ip != proba_results_temp[i][0]:
            if (i != 0):
                proba_results.append((prev_ip, sum_proba/count))
                results.append((prev_ip, True if sum_proba/count >= 0.5 else False))
            prev_ip = proba_results_temp[i][0]
            sum_proba = 0
            count = 0
        sum_proba += proba_results_temp[i][1]
        count += 1
    proba_results.append((prev_ip, sum_proba/count))
    results.append((prev_ip, True if sum_proba/count >= 0.5 else False))

    return flows, results