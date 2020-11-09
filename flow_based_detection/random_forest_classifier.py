import pandas as pd
from sklearn.preprocessing import StandardScaler
import sklearn.ensemble


def RandomForestClassifier(flows, flowbased_dataset):
    print("Random Forest Classifier...")
    sc_X = StandardScaler()

    # Load 45 features and the 'label' from the Training Dataset
    X_Train = flowbased_dataset.iloc[:, [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44]].values
    Y_Train = flowbased_dataset.iloc[:, 45].values

    # Training features scaling 
    X_Train = sc_X.fit_transform(X_Train)

    # Fit the Classifier into the Training set
    classifier = sklearn.ensemble.RandomForestClassifier(n_estimators = 200, criterion = 'entropy', random_state = 0)
    classifier.fit(X_Train,Y_Train)

    # Load 45 features from the Flows captured
    # The column 0 contains the IP to classify
    X = flows.iloc[:, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45]].values
    X = sc_X.transform(X)

    # Get results
    Y_Pred = classifier.predict(X) 

    print("\nRESULTS:")
    Sospicious_IPs = []
    results = []
    for i in range(0,len(Y_Pred)):
        results.append((flows.iloc[i]['IP'], True if Y_Pred[i] == 1 else False))
        if Y_Pred[i] == 1:
            Sospicious_IPs.append(flows.iloc[i]['IP'])

    Sospicious_IPs = list(dict.fromkeys(Sospicious_IPs))
    results = list(dict.fromkeys(results))
    print(results)

    del X_Train, Y_Train
    del X, flows

    return Sospicious_IPs


