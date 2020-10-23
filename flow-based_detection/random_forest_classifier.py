import sys
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
import pickle


sc_X = StandardScaler()

if (len(sys.argv) == 4 and sys.argv[1] == "train"):
    print("\nLoading the Training Dataset...")
    # Import the Training Dataset
    datasets = pd.read_hdf("../datasets/flow-based_datasets/train/"+str(sys.argv[2]))

    # Load 45 features and the 'label' from the Training Dataset
    X_Train = datasets.iloc[:, [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44]].values
    Y_Train = datasets.iloc[:, 45].values

    # Training features scaling 
    X_Train = sc_X.fit_transform(X_Train)

    print("\nTraining the Classifier...")
    # Fit the Classifier into the Training set
    classifier = RandomForestClassifier(n_estimators = 200, criterion = 'entropy', random_state = 0, verbose=1)
    classifier.fit(X_Train,Y_Train)
    
    print("\nSaving the Classifier...")
    # Save the Classifier
    with open('model/flow-based_classifier.pkl', 'wb') as fid:
        pickle.dump(classifier, fid) 

elif (len(sys.argv) == 4 and sys.argv[1] == "test"):
    print("\nLoading the pretrained Classifier...")
    # Load the pretrained Classifier
    with open('model/'+str(sys.argv[2]), 'rb') as f:
        classifier = pickle.load(f)

else:
    print("\nUsage:")
    print("# python3 random_forest_classifier.py train <training dataset filename in /datasets/flow-based_datasets/train> <testing dataset filename in /datasets/flow-based_datasets/test>")
    print("# python3 random_forest_classifier.py test <classifier filename in flow-based_detection/model> <testing dataset filename in /datasets/flow-based_datasets/test>")
    sys.exit()


print("\nLoading Testing Dataset...")
# Import the Testing Dataset
datasets_test = pd.read_hdf("../datasets/flow-based_datasets/test/"+str(sys.argv[3]))

# Load 45 features and the 'label' from the Testing Dataset
# The column 0 contains the IP to classify
X_Test = datasets_test.iloc[:, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45]].values
Y_Test = datasets_test.iloc[:, 46].values

if (sys.argv[1] == "train"):
    # Test features scaling
    X_Test = sc_X.transform(X_Test)

print("\nPrediction...")
# Predicting the test set results
Y_Pred = classifier.predict(X_Test) 

print("\nAccuracy:")
# Making the Confusion Matrix 
cm = confusion_matrix(Y_Test, Y_Pred)
cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
print(cm.diagonal())

print("\nRESULTS:")
print("\nSospicious IPs")
Sospicious_IPs = []
for i in range(0,len(Y_Pred)):
    if Y_Pred[i] == 1:
        Sospicious_IPs.append(datasets_test.iloc[i]['IP'])

Sospicious_IPs = list(dict.fromkeys(Sospicious_IPs))
print(Sospicious_IPs)

print("\nNormal IPs")
Normal_IPs = []
for i in range(0,len(Y_Pred)):
    if Y_Pred[i] == 0:
        Normal_IPs.append(datasets_test.iloc[i]['IP'])

Normal_IPs = list(dict.fromkeys(Normal_IPs))
print(Normal_IPs)

