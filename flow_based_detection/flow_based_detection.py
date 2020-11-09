from flow_based_detection.flow_features_extractor import FlowFeaturesExtractor
from flow_based_detection.random_forest_classifier import RandomForestClassifier


def FlowBasedDetection(captured_packets, flowbased_dataset):
    flows = FlowFeaturesExtractor(captured_packets)
    print("Flow features extracted...")
    sospicious_IPs = RandomForestClassifier(flows, flowbased_dataset)

    return sospicious_IPs