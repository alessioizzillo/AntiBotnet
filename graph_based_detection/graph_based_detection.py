import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.random_forest_classifier import *
from graph_based_detection.graph_features_extractor import GraphFeaturesExtractor



def GraphBasedDetection(traffic_file, train_dataset):
    print("GRAPH-BASED DETECTION:")

    print("   * Extracting graph features...")
    dataset = GraphFeaturesExtractor('predicting', traffic_file, None, verbose=False)

    print("\n   * Predicting...")
    Y_Pred = RandomForestClassifier(dataset, train_dataset)

    results = []
    for i in range(0,len(Y_Pred)):
        results.append((int2ip(int(dataset.loc[i]['IP'])), True if Y_Pred[i] == 1 else False))

    results = list(dict.fromkeys(results))

    return results