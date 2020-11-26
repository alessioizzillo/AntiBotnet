import pandas as pd
from sklearn.preprocessing import StandardScaler
import sklearn.ensemble
import socket
import sys

sys.path.append("..")
from utilities.network import *


def RandomForestClassifier(dataset, train_dataset):
    local_ip = socket.gethostbyname(socket.gethostname())

    sc_X = StandardScaler()

    # Load the features and the 'label' from the Training train_dataset
    X_Train = train_dataset.iloc[:, range(0, len(train_dataset.columns)-1, 1)].values
    Y_Train = train_dataset.iloc[:, len(train_dataset.columns)-1].values 

    # Training features scaling 
    X_Train = sc_X.fit_transform(X_Train)

    # Fit the Classifier into the Training set
    classifier = sklearn.ensemble.RandomForestClassifier(n_estimators = 5, criterion = 'entropy', random_state = 0, n_jobs=-1)
    classifier.fit(X_Train,Y_Train)

    # Load the features from the dataset captured
    X = dataset.iloc[:, range(0, len(dataset.columns), 1)].values
    X = sc_X.transform(X)

    # Get results
    Y_Pred = classifier.predict(X) 

    del X_Train, Y_Train
    del X, dataset

    return Y_Pred


