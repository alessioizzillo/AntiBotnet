import sys

sys.path.append("..")
from ml.random_forest_classifier import *

sys.path.append("graph_based_detection")
import graph_features_extractor
import create_graph


def GraphBasedDetection(traffic_file, train_dataset):
    print("GRAPH-BASED DETECTION:")

    print("   * Extracting graph features...")
    dataset = graph_features_extractor.GraphFeaturesExtractor('predicting', traffic_file, None, \
        verbose = False)

    print("   * Predicting...")
    Y_Pred = RandomForestClassifier(dataset, train_dataset)

    results = []
    for i in range(0,len(Y_Pred)):
        results.append((int2ip(int(dataset.loc[i]['IP'])), True if Y_Pred[i] == 1 else False))

    results = list(dict.fromkeys(results))

    return results