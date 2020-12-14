import sys
import os
import socket

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.random_forest_classifier import RandomForestClassifier_predict
from graph_based_detection.graph_features_extractor import GraphFeaturesExtractor
from utilities.network import *


def GraphBasedDetection(mode, GBD_classifier, traffic_file):
    if mode == 'oracle':
        print("GRAPH-BASED DETECTION:")
        print("   * Extracting graph features...")

    if mode == 'oracle':
        dataset = GraphFeaturesExtractor('predicting', traffic_file, None, verbose=True)
        print("\n   * Predicting...")
    else:
        dataset = GraphFeaturesExtractor('predicting', traffic_file, None, verbose=False)

    Y_Pred = RandomForestClassifier_predict("normal", GBD_classifier, dataset)

    results = []
    for i in range(0,len(Y_Pred)):
        if int2ip(int(dataset.loc[i]['IP'])) == socket.gethostbyname(socket.gethostname()):
            continue
        results.append((int2ip(int(dataset.loc[i]['IP'])), True if Y_Pred[i] == 1 else False))

    return results