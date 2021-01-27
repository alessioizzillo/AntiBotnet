# AntiBotnet

A Linux tool for detecting and mitigating Botnet attacks.

**Instructions**:
1) Create the dataset for the "flow-based detection system".
2) Create the dataset for the "graph-based detection system".
3) Run "AntiBotnet.py" python script.


**Creation of flow-based detection system**

Go to "flow_based_detection" directory and run: 

    python3 flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>

**Creation of graph-based detection system**

Go to "graph_based_detection" directory and run:

    python3 graph_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>



**"AntiBotnet.py" running:**

USAGE (TEST MODE)

    sudo python3 AntiBotnet.py <mode> <interface> <n_pkts> <n_rf_est_fbd> <n_rf_est_gbd> <test_pcap> <test_victim_IPs_file> <pos_victim_IP2replace> <test_malicious_IPs_file>

or
    
    sudo python3 AntiBotnet.py <mode> <interface> <n_pkts> <n_rf_est_fbd> <n_rf_est_gbd> <test_pcap> <test_victim_IPs_file> <pos_victim_IP2replace> <test_malicious_IPs_file> <P2P_IP>

<br/>
USAGE (REAL-WORLD MODE)
    
    sudo python3 AntiBotnet.py <mode> <interface> <n_pkts> <n_rf_est_fbd> <n_rf_est_gbd>
    
or
    
    sudo python3 AntiBotnet.py <mode> <interface> <n_pkts> <n_rf_est_fbd> <n_rf_est_gbd> <P2P_IP>

<br/>
Below, there is the description of the arguments passed to the script through the commands above.

* **mode** *(mandatory for both modes)*: the execution mode, "real-world" mode, "test" mode or "test_no_gbd" mode;
* **interface** *(mandatory for both modes)*: the Ethernet interface name fromwhich to capture the traffic to analyze;
* **n_pkts** *(mandatory for both modes)*: the size of the batch of packets toanalyze;
* **n_rf_est_fbd** *(mandatory for both modes)*: the number of estimators totrain the Random Forest Classifier in Flow-Based detection;
* **n_rf_est_gbd** *(mandatory for both modes)*: the number of estimators totrain the Random Forest Classifier in Graph-Based detection;
* **test_pcap** *(only for "test mode")*: path of pcap file from which to replay thepackets for testing the tool;
* **test_victim_IPs_file** *(only for "test mode")*: path of the text file where allthe victim IPs which communicate with the malicious host are listed (one perline);
* **pos_victim_IP2replace** *(only for "test mode")*: position (in the the file"test_victim_IPs_file") of the victim IP to assign to the host where the toolruns;
* **test_malicious_IPs_file** *(only for "test mode")*: path of the testfile wheremalicious IPs of test pcap file are listed (one per line);
* **P2P_IP** *(optional for both modes)*: IP of an active host of the P2P networkto connect to.
