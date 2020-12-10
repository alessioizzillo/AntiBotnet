import sys
import os
import socket

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.random_forest_classifier import *
from graph_based_detection.graph_features_extractor import GraphFeaturesExtractor



def GraphBasedDetection(mode, traffic_file, train_dataset, gbd_n_estimators):
    if mode == 'oracle':
        print("GRAPH-BASED DETECTION:")
        print("   * Extracting graph features...")

    if mode == 'oracle':
        dataset = GraphFeaturesExtractor('predicting', traffic_file, None, verbose=True)
        print("\n   * Predicting...")
    else:
        dataset = GraphFeaturesExtractor('predicting', traffic_file, None, verbose=False)

    Y_Pred = RandomForestClassifier("normal", dataset, train_dataset, gbd_n_estimators)

    results = []
    for i in range(0,len(Y_Pred)):
        if int2ip(int(dataset.loc[i]['IP'])) == socket.gethostbyname(socket.gethostname()):
            continue
        results.append((int2ip(int(dataset.loc[i]['IP'])), True if Y_Pred[i] == 1 else False))

    return results