import pandas as pd
from sklearn.preprocessing import StandardScaler
import sklearn.ensemble
import socket
import sys

sys.path.append("..")
from utilities.network import *


def RandomForestClassifier(flows, flowbased_dataset):
    local_ip = socket.gethostbyname(socket.gethostname())

    print("Random Forest Classifier...")
    sc_X = StandardScaler()
    print(len(flowbased_dataset.columns), flowbased_dataset.columns)
    # Load the features and the 'label' from the Training Dataset
    X_Train = flowbased_dataset.iloc[:, range(0, len(flowbased_dataset.columns)-1, 1)].values
    Y_Train = flowbased_dataset.iloc[:, len(flowbased_dataset.columns)-1].values
    print(X_Train)    
    print(flowbased_dataset)
    # Training features scaling 
    X_Train = sc_X.fit_transform(X_Train)

    # Fit the Classifier into the Training set
    classifier = sklearn.ensemble.RandomForestClassifier(n_estimators = 200, criterion = 'entropy', random_state = 0)
    classifier.fit(X_Train,Y_Train)

    # Load the features from the Flows captured
    X = flows.iloc[:, range(0, len(flowbased_dataset.columns)-1, 1)].values
    X = sc_X.transform(X)

    # Get results
    Y_Pred = classifier.predict(X) 
    print(flows)
    print("\nRESULTS:")
    Sospicious_IPs = []
    results = []
    for i in range(0,len(Y_Pred)):
        results.append((int2ip(int(flows.iloc[i]['SrcIP'])) if int2ip(int(flows.iloc[i]['SrcIP'])) != local_ip else int2ip(int(flows.iloc[i]['DstIP'])), \
            True if Y_Pred[i] == 1 else False))
        if Y_Pred[i] == 1:
            Sospicious_IPs.append(int(flows.iloc[i]['SrcIP']) if int2ip(int(flows.iloc[i]['SrcIP'])) != local_ip else int(flows.iloc[i]['DstIP']))

    Sospicious_IPs = list(dict.fromkeys(Sospicious_IPs))
    results = list(dict.fromkeys(results))
    print(results)
    print(Sospicious_IPs)

    del X_Train, Y_Train
    del X, flows

    return Sospicious_IPs


