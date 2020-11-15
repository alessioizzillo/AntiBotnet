from flow_based_detection.flow_features_extractor import FlowFeaturesExtractor
from flow_based_detection.random_forest_classifier import RandomForestClassifier


def FlowBasedDetection(captured_packets, flowbased_dataset):
    malicious_IPs_list = []
    with open("flow_based_detection/malicious_IPs.txt") as malicious_IPs:
        malicious_IPs_list = malicious_IPs.readlines()
    flows = FlowFeaturesExtractor(captured_packets, 'traffic', malicious_IPs_list)
    print("Flow features extracted...")
    sospicious_IPs = RandomForestClassifier(flows, flowbased_dataset)

    return sospicious_IPs