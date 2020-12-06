# Master-Thesis-Project

"AntiBotnet.py" running:

Instructions:
1) Create the dataset for "flow-based detection system"
2) Create the dataset for "graph-based detection system"
3) Run "AntiBotnet.py" or "AntiBotnet_1.py"


Creation of flow-based detection system

1) Go to "flow_based_detection" directory and run:
    USAGE: python3 flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>

Creation of graph-based detection system

1) Go to "graph_based_detection" directory and run:
    USAGE: python3 graph_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>


"AntiBotnet.py" running:

USAGE (TEST MODE)
    sudo python3 AntiBotnet.py test <interface> <number of packets to capture> <path of pcap file to test> <IP to replace in the test pcap file> <path of txt with list of malicious IPs of test pcap file>
    (OR)
    sudo python3 AntiBotnet.py test <interface> <number of packets to capture> <path of pcap file to test> <IP to replace in the test pcap file> <path of txt with list of malicious IPs of test pcap file> <IP of an active host of the P2P network>

USAGE (REAL-WORLD MODE)
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture>
    (OR)
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <IP of an active host of the P2P network>


"AntiBotnet_1.py" running:

USAGE (TEST MODE)
    sudo python3 AntiBotnet.py test <interface> <number of packets to capture>
    (OR)
    sudo python3 AntiBotnet.py test <interface> <number of packets to capture> <IP of an active host of the P2P network>

USAGE (REAL-WORLD MODE)
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture>
    (OR)
    sudo python3 AntiBotnet.py real-world <interface> <number of packets to capture> <IP of an active host of the P2P network>
