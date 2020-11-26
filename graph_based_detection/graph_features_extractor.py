import numpy as np
import pandas as pd
from graph_tool.all import *
import sys, os

sys.path.append("..")
from utilities.network import *

sys.path.append("graph_based_detection")
import create_graph


# Disable print statements
def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Enable print stements
def enablePrint():
    sys.stdout = sys.__stdout__

"""
Vertex features - first 12 of these are calculated using graph-tool's functions
and the remaining 16 are my calculations of 'function' features - i.e. similar
to flow features but per node instead of per flow
["Out-degree", "In-degree", "# of in-neighbors", "# of out-neighbors", 
 "Page Rank", "Betweenness", "Closeness", "Eigenvector", "Katz",
 "Authority centrality", "Hub centrality", "Clustering coefficient", 
 "Average incoming packet size", "Max incoming packet size,"
 "Min incoming packet size", "Average outgoing packet size",
 "Max outgoing packet size", "Min outgoing packet size", "Number incoming bytes", 
 "Number outgoing bytes", "Number source ports", "Number destination ports",
 "Average incoming TTL", "Max incoming TTL", "Min incoming TTL", 
 "Average outgoing TTL", "Max outgoing TTL", "Min outgoing TTL"]
The above features will be normalized and placed in a vector for each vertex
in each time interval
"""
VECTOR_SIZE = 28


def normalize(array):
    try:
        array = 0.05 + 0.90 * (array - array.min()) / float(array.max() - array.min())
    except:
        array.fill(float('nan'))

    # Note that some measures of centrality can be NaN so I change the NaN
    # values to 0
    array = np.nan_to_num(array)

    return array


def to_float_or_nan(x):
    try:
        return float(x)
    except:
        return float('nan')


def convert_to_float(d):
    d['Time'] = d['Time'].progress_apply(lambda x: float(x))
    print("\'Time\' feature converted to float")
    d['Source'] = d['Source'].progress_apply(lambda x: float(ip2int(x)) if isinstance(x, str) else float(x))
    print("\'Source\' feature converted to float")
    d['Destination'] = d['Destination'].progress_apply(lambda x: float(ip2int(x)) if isinstance(x, str) else float(x))
    print("\'Destination\' feature converted to float")
    d['Source Port'] = d['Source Port'].progress_apply(lambda x: float(x))
    print("\'Source Port\' feature converted to float")
    d['Destination Port'] = d['Destination Port'].progress_apply(lambda x: float(x))
    print("\'Destination Port\' feature converted to float")
    d['EtherType'] = d['EtherType'].progress_apply(lambda x: float(2048) if str(x) == 'IPv4' else float(x) if (isinstance(x, float) or isinstance(x, int)) else float('nan'))
    print("\'EtherType\' feature converted to float")
    d['Protocol'] = d['Protocol'].progress_apply(lambda x: float(6) if str(x) == 'TCP' else float(17) if str(x) == 'UDP' else float(x) if (isinstance(x, float) or isinstance(x, int)) else float('nan'))
    print("\'Protocol\' feature converted to float")
    d['TCP Flags'] = d['TCP Flags'].progress_apply(lambda x: float(int(x, 16)) if 'x' in str(x) else float(x))
    print("\'TCP Flags\' feature converted to float")
    d['Length'] = d['Length'].progress_apply(lambda x: float(x))
    print("\'Length\' feature converted to float")
    d['TCP Payload Length'] = d['TCP Payload Length'].progress_apply(lambda x: float(x))
    print("\'TCP Payload Length\' feature converted to float")
    d['UDP Length'] = d['UDP Length'].progress_apply(lambda x: float(x))
    print("\'UDP Length\' feature converted to float")
    d['TTL'] = d['TTL'].progress_apply(lambda x: to_float_or_nan(x))
    print("\'TTL\' feature converted to float")

    return d


def GraphFeaturesExtractor(mode, dataset_file, botnet_nodes, verbose = True):
    if (mode == 'training'):
        convert_to_float(dataset_file)
        
    csv_graph = create_graph.CsvGraph(dataset_file)

    # Dictionary with IP addresses as keys and list of 12-vectors as the value
    dict_x = {}

    if (mode == 'training'):
        # Dictionary with IP addresses as keys and 1 or 0 as the value
        dict_y = {}

    if verbose == False:
        blockPrint()

    if (mode == 'training'):
        g = csv_graph.make_graph(save_graph=True)
    else:
        g = csv_graph.make_graph(save_graph=False)


    # Degree
    print("Out-degrees...")
    outd = normalize(g.get_out_degrees(g.get_vertices()))
    print("In-degrees...")
    ind = normalize(g.get_in_degrees(g.get_vertices()))

    # Number of neighbors
    print("In-neighbors...")
    inn = np.array([])
    print("Out-neighbors...")
    outn = np.array([])
    for v in g.get_vertices():
        inn = np.append(inn, len(g.get_in_neighbours(v)))
        outn = np.append(outn, len(g.get_out_neighbours(v)))
    inn = normalize(inn)
    outn = normalize(outn)

    # Other features
    print("Pagerank...")
    pr = normalize(pagerank(g).a)
    print("Betweenness...")
    b = normalize(betweenness(g)[0].a)
    print("Closeness...")
    c = normalize(closeness(g).a)
    print("Eigenvector...")
    ev = normalize(eigenvector(g, max_iter = 500)[1].a)
    print("Katz...")
    k = normalize(katz(g).a)
    print("Authority...")
    auth = normalize(hits(g)[1].a)
    print("Hub...")
    hub = normalize(hits(g)[2].a)
    print("Clustering...")
    # This seems to take a long time to run
    clustering = normalize(local_clustering(g).a)

    print("Extra 'function' features...")
    # Dictionaries containing vertex indices as keys and lists of their 
    # corresponding values -> used to calculate the "function" features
    incoming_packet_size = {} # in number of bytes
    outgoing_packet_size = {}
    source_ports = {} # unique source ports the host is receiving messages from
    dest_ports = {} # unique destination ports the host is sending messages to
    source_ttl = {} # outgoing packets' TTLs
    dest_ttl = {} # incoming packets' TTLs
    for v in g.get_vertices():
        incoming_packet_size[v] = []
        outgoing_packet_size[v] = []
        source_ports[v] = []
        dest_ports[v] = []
        source_ttl[v] = []
        dest_ttl[v] = []

    # I could iterate over the in and out edges per vertex - which could
    # probably save some RAM. But this will make it faster...
    for e in g.edges():
        port_source = g.ep.port_source[e]
        port_dest = g.ep.port_dest[e]
        ttl = g.ep.ttl[e]
        num_bytes = g.ep.num_bytes[e]
        incoming_packet_size[e.target()].append(num_bytes)
        outgoing_packet_size[e.source()].append(num_bytes)
        source_ports[e.target()].append(port_source)
        dest_ports[e.source()].append(port_dest)
        source_ttl[e.source()].append(ttl)
        dest_ttl[e.target()].append(ttl)

    # I don't like that I'm adding so many Python loops (it'll make things
    # slow) but we'll see how it goes
    avg_incoming_packet_size, max_incoming_packet_size, \
        min_incoming_packet_size = np.array([]), np.array([]), np.array([])
    avg_outgoing_packet_size, max_outgoing_packet_size, \
        min_outgoing_packet_size = np.array([]), np.array([]), np.array([])
    number_incoming_bytes, number_outgoing_bytes \
        = np.array([]), np.array([])
    number_source_ports, number_dest_ports = np.array([]), np.array([])
    avg_incoming_ttl, max_incoming_ttl, min_incoming_ttl \
        = np.array([]), np.array([]), np.array([])
    avg_outgoing_ttl, max_outgoing_ttl, min_outgoing_ttl \
        = np.array([]), np.array([]), np.array([])
    for v in g.get_vertices():
        if len(incoming_packet_size[v]) > 0:
            # and len(set(source_ports[v])) > 0 and len(dest_ttl[v]) > 0
            # All the above conditions are equivalent because of the way we
            # add to these lists (see the loop over the edges -> line 177)
            avg_incoming_packet_size = np.append(avg_incoming_packet_size, \
                sum(incoming_packet_size[v])/len(incoming_packet_size[v]))
            max_incoming_packet_size = np.append(max_incoming_packet_size, \
                max(incoming_packet_size[v]))
            min_incoming_packet_size = np.append(min_incoming_packet_size, \
                min(incoming_packet_size[v]))
            number_incoming_bytes = np.append(number_incoming_bytes, \
                sum(incoming_packet_size[v]))
            number_source_ports = np.append(number_source_ports, \
                len(set(source_ports[v])))
            avg_incoming_ttl = np.append(avg_incoming_ttl, \
                sum(dest_ttl[v])/len(dest_ttl[v]))
            max_incoming_ttl = np.append(max_incoming_ttl, \
                max(dest_ttl[v]))
            min_incoming_ttl = np.append(min_incoming_ttl, 
                min(dest_ttl[v]))
        # If there are no incoming packets, pad with 0s
        else:
            avg_incoming_packet_size = np.append(avg_incoming_packet_size, 0)
            max_incoming_packet_size = np.append(max_incoming_packet_size, 0)
            min_incoming_packet_size = np.append(min_incoming_packet_size, 0)
            number_incoming_bytes = np.append(number_incoming_bytes, 0)
            number_source_ports = np.append(number_source_ports, 0)
            avg_incoming_ttl = np.append(avg_incoming_ttl, 0)
            max_incoming_ttl = np.append(max_incoming_ttl, 0)
            min_incoming_ttl = np.append(min_incoming_ttl, 0)
        
        if len(outgoing_packet_size[v]) > 0:
            # and len(set(dest_ports[v]) > 0 and len(source_ttl[v]) > 0
            # All the above conditions are equivalent because of the way we
            # add to these lists (see the loop over the edges -> line 177)
            avg_outgoing_packet_size = np.append(avg_outgoing_packet_size, \
                sum(outgoing_packet_size[v])/len(outgoing_packet_size[v]))
            max_outgoing_packet_size = np.append(max_outgoing_packet_size, \
                max(outgoing_packet_size[v]))
            min_outgoing_packet_size = np.append(min_outgoing_packet_size, \
                min(outgoing_packet_size[v]))
            number_outgoing_bytes = np.append(number_outgoing_bytes, \
                sum(outgoing_packet_size[v]))
            number_dest_ports = np.append(number_dest_ports, \
                len(set(dest_ports[v])))
            avg_outgoing_ttl = np.append(avg_outgoing_ttl, \
                sum(source_ttl[v])/len(source_ttl[v]))
            max_outgoing_ttl = np.append(max_outgoing_ttl, \
                max(source_ttl[v]))
            min_outgoing_ttl = np.append(min_outgoing_ttl, \
                min(source_ttl[v]))
        # If there are no outgoing packets, pad with 0s
        else:
            avg_outgoing_packet_size = np.append(avg_outgoing_packet_size, 0)
            max_outgoing_packet_size = np.append(max_outgoing_packet_size, 0)
            min_outgoing_packet_size = np.append(min_outgoing_packet_size, 0)
            number_outgoing_bytes = np.append(number_outgoing_bytes, 0)
            number_dest_ports = np.append(number_dest_ports, 0)
            avg_outgoing_ttl = np.append(avg_outgoing_ttl, 0)
            max_outgoing_ttl = np.append(max_outgoing_ttl, 0)
            min_outgoing_ttl = np.append(min_outgoing_ttl, 0)
        
    avg_incoming_packet_size = normalize(avg_incoming_packet_size)
    max_incoming_packet_size = normalize(max_incoming_packet_size)
    min_incoming_packet_size = normalize(min_incoming_packet_size)
    avg_outgoing_packet_size = normalize(avg_outgoing_packet_size)
    max_outgoing_packet_size = normalize(max_outgoing_packet_size)
    min_outgoing_packet_size = normalize(min_outgoing_packet_size)
    number_incoming_bytes = normalize(number_incoming_bytes)
    number_outgoing_bytes = normalize(number_outgoing_bytes)
    number_source_ports = normalize(number_source_ports)
    number_dest_ports = normalize(number_dest_ports)

    avg_incoming_ttl = normalize(avg_incoming_ttl)
    max_incoming_ttl = normalize(max_incoming_ttl)
    min_incoming_ttl = normalize(min_incoming_ttl)
    avg_outgoing_ttl = normalize(avg_outgoing_ttl)
    max_outgoing_ttl = normalize(max_outgoing_ttl)
    min_outgoing_ttl = normalize(min_outgoing_ttl)

    print("Adding to dict_x...")
    temp = np.array([outd, ind, inn, outn, pr, b, c, ev, k, \
        auth, hub, clustering, avg_incoming_packet_size, \
        max_incoming_packet_size, min_incoming_packet_size, \
        avg_outgoing_packet_size, max_outgoing_packet_size, \
        min_outgoing_packet_size, number_incoming_bytes, \
        number_outgoing_bytes, number_source_ports, number_dest_ports, \
        avg_incoming_ttl, max_incoming_ttl, min_incoming_ttl, \
        avg_outgoing_ttl, max_outgoing_ttl, max_outgoing_ttl]).transpose()
    
    # Add vertex vectors to dict_x
    # Consider changing the dictionaries to sorted lists so you can
    # do a binary search
    for v in g.get_vertices():
        dict_x[g.vp.ip_address[v]] = temp[v]

    df = pd.DataFrame.from_dict(dict_x, orient='index', \
        columns= ['outd', 'ind', 'inn', 'outn', 'pr', 'b', 'c', 'ev', 'k', \
        'auth', 'hub', 'clustering', 'avg_incoming_packet_size', \
        'max_incoming_packet_size', 'min_incoming_packet_size', \
        'avg_outgoing_packet_size', 'max_outgoing_packet_size', \
        'min_outgoing_packet_size', 'number_incoming_bytes', \
        'number_outgoing_bytes', 'number_source_ports', 'number_dest_ports', \
        'avg_incoming_ttl', 'max_incoming_ttl', 'min_incoming_ttl', \
        'avg_outgoing_ttl', 'max_outgoing_ttl', 'max_outgoing_ttl'])

    if (mode == 'training'):
        for key in dict_x.keys():
            dict_y[key] = int(key in botnet_nodes)
        df['Label'] = df.index.to_series().map(dict_y)
    
    df.insert(0, 'IP', df.index)
    df.reset_index(inplace=True, drop=True)

    if verbose == False:
        enablePrint()

    return df


if __name__ == '__main__':
    if (len(sys.argv) == 3):
        dataset = pd.read_csv(sys.argv[1])
        malicious_IPs_list = []
        
        with open(sys.argv[2]) as malicious_IPs:
            malicious_IPs_list = malicious_IPs.read()
        
        malicious_IPs_list = malicious_IPs_list.split('\n')
        for i in range(len(malicious_IPs_list)):
            malicious_IPs_list[i] = float(ip2int(malicious_IPs_list[i]))
        graph_features = GraphFeaturesExtractor('training', dataset, malicious_IPs_list, verbose = True)
        
        print(graph_features)
        print("\nSaving extracted Graph Features")
        
        graph_features.fillna(0, inplace=True)
        graph_features.to_hdf('training_dataset/training.hdf5', key='graph_features', mode='w', format='table')
    else:
        print("\nUSAGE (Windows): python flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>")
        print("USAGE (Linux): python3 flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>\n")
        sys.exit(-1)
