import sys
import os
import pandas as pd
from time import perf_counter

from graph_based_detection.graph_based_detection import GraphBasedDetection
from ml.random_forest_classifier import RandomForestClassifier_train


if __name__ == '__main__':
    if (len(sys.argv) == 5):
        print("\n---GRAPH-BASED ORACLE---\n")

        print("Loading Traffic to analyze...")
        df = pd.read_csv(sys.argv[1])

        print("Loading Training Dataset...")
        training_dataset = pd.read_hdf(sys.argv[2])

        test_malicious_IPs_file = sys.argv[3]
        print("Reading malicious IPs...")
        with open(test_malicious_IPs_file) as malicious_IPs:
            test_malicious_IPs_list = malicious_IPs.read()
        test_malicious_IPs_list = test_malicious_IPs_list.split('\n')
        print("\nTEST malicious IPs:", test_malicious_IPs_list)
        print()

        gbd_n_estimators = int(sys.argv[4])

        start_time = perf_counter()
        GBD_classifier = RandomForestClassifier_train(training_dataset, gbd_n_estimators)
        results = GraphBasedDetection("oracle", GBD_classifier, df)
        end_time = perf_counter()
        
        len_results = len(results)
        n_false_neg = 0
        n_false_pos = 0
        n_true_neg = 0
        n_true_pos = 0
        for t in results:
            if (t[0] in test_malicious_IPs_list and t[1] == False):
                n_false_neg += 1
            elif (t[0] not in test_malicious_IPs_list and t[1] == True):
                n_false_pos += 1
            elif (t[0] not in test_malicious_IPs_list and t[1] == False):
                n_true_neg += 1
            else:
                n_true_pos += 1
        
        exec_time = end_time-start_time
        
        df_results = pd.DataFrame([[exec_time, n_true_pos, n_true_neg, n_false_pos, n_false_neg, len_results]], \
            columns=['GraphBasedDetection execution time', 'True Positives', \
            'True Negatives', 'False Positive', 'False Negative', 'Total predictions'])
        
        print("\nSAVING Results...")
        df_results.to_csv("oracle_results.csv", index=False)     

    else:
        print("python3 GraphBasedOracle.py <path of the csv file of the traffic to analyze> <path of the graph-based training dataset> <path of the file with the list of malicious IPs> <n of estimators for the Random Forest Classifier>")