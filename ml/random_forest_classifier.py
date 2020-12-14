import pandas as pd
from sklearn.preprocessing import StandardScaler
import sklearn.ensemble
import socket
import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
from utilities.network import *


def RandomForestClassifier_train(train_dataset, n_est):
    local_ip = socket.gethostbyname(socket.gethostname())

    # Load the features and the 'label' from the Training train_dataset
    X_Train = train_dataset.iloc[:, range(0, len(train_dataset.columns)-1, 1)].values
    Y_Train = train_dataset.iloc[:, len(train_dataset.columns)-1].values 

    # Fit the Classifier into the Training set
    classifier = sklearn.ensemble.RandomForestClassifier(n_estimators = n_est, criterion = 'entropy', random_state = 0, n_jobs=-1)
    classifier.fit(X_Train,Y_Train)

    del X_Train, Y_Train

    return classifier


def RandomForestClassifier_predict(mode, classifier, dataset):
    # Load the features from the dataset captured
    X = dataset.iloc[:, range(0, len(dataset.columns), 1)].values

    # Get results
    if mode == "proba":
        Y_Pred_proba = classifier.predict_proba(X)
        Y_Pred = []
        for i in range(len(Y_Pred_proba)):
            Y_Pred.append(Y_Pred_proba[i][1])

    else:
        Y_Pred = classifier.predict(X)

    del X, dataset

    return Y_Pred


