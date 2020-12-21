# Master-Thesis-Project

**Instructions**:
1) Create the dataset for "flow-based detection system"
2) Create the dataset for "graph-based detection system"
3) Run "AntiBotnet.py" or "AntiBotnet_1.py"


**Creation of flow-based detection system**

Go to "flow_based_detection" directory and run: 

    python3 flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>

**Creation of graph-based detection system**

Go to "graph_based_detection" directory and run:

    python3 graph_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>



**"AntiBotnet.py" running:**

USAGE (TEST MODE)

    sudo python3 AntiBotnet.py test(_no_gbd) <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier> <path of pcap file to test> <path of the file with the list of the IPs to replace in the test pcap file> <position of the IP to replace (ex. '0' = in the first line)> <path of the file with the list of malicious IPs of test pcap file>

or
    
    sudo python3 AntiBotnet.py test(_no_gbd) <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier> <path of pcap file to test> <path of the file with the list of the IPs to replace in the test pcap file> <position of the IP to replace (ex. '0' = in the first line)> <path of the file with the list of malicious IPs of test pcap file> <IP of an active host of the P2P network>


USAGE (REAL-WORLD MODE)
    
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier>
    
or
    
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier> <IP of an active host of the P2P network>



**"AntiBotnet_1.py" running:**

USAGE (TEST MODE)
    
    sudo python3 AntiBotnet.py test(_no_gbd) <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier>
    
or
    
    sudo python3 AntiBotnet.py test(_no_gbd) <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier> <IP of an active host of the P2P network>


USAGE (REAL-WORLD MODE)
    
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier>
    
or
    
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <n estimators Flow-based RF Classifier> <n estimators Graph-based RF Classifier> <IP of an active host of the P2P network>
