from graph_tool.all import *
import bisect
from tqdm import tqdm
import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utilities.network import *


class CsvGraph:
    def __init__(self, dataset_file):
        self.csv = dataset_file
        self.edges = []
        self.nodes = []

    def read_csv(self):
        self.csv = self.csv[self.csv['Source'].notnull() & self.csv['Destination'].notnull() & self.csv['Source Port'].notnull() & \
            self.csv['Destination Port'].notnull() & (self.csv['EtherType'] == 2048) & ((self.csv['Protocol'] == 6) | (self.csv['Protocol'] == 17))]

        for index, row in tqdm(self.csv.iterrows(), total=self.csv.shape[0]):
            try:
                ip_source = row['Source']
                ip_dest = row['Destination']
                port_source = row['Source Port']
                port_dest = row['Destination Port']
                if (row['Protocol'] == 6):
                    num_bytes = row['TCP Payload Length']
                elif (row['Protocol'] == 17):
                    num_bytes = row['UDP Length']-8
                else:
                    continue
                ttl = row['TTL']
            except:
                continue

            self.edges.append((ip_source, ip_dest, float(row['Time']), port_source, \
                port_dest, ttl, num_bytes))

            # Generates a sorted array of IP addresses of the devices
            j = bisect.bisect_left(self.nodes, ip_source)
            if j == len(self.nodes) or self.nodes[j] != ip_source:
                self.nodes.insert(j, ip_source)
            j = bisect.bisect_left(self.nodes, ip_dest)
            if j == len(self.nodes) or self.nodes[j] != ip_dest:
                self.nodes.insert(j, ip_dest)
            


    '''
    Returns graph g, which contains the nodes and edges and their property
    maps
    '''
    def make_graph(self, save_graph=False, save_filename="graph_structure.gt"):
        self.read_csv()

        g = Graph()

        # Create internal property maps
        g.vertex_properties["ip_address"] = g.new_vertex_property("float")

        g.edge_properties["timestamp"] = g.new_edge_property("float")
        g.edge_properties["num_bytes"] = g.new_edge_property("float")
        g.edge_properties["ip_source"] = g.new_edge_property("float")
        g.edge_properties["ip_dest"] = g.new_edge_property("float")
        g.edge_properties["port_source"] = g.new_edge_property("float")
        g.edge_properties["port_dest"] = g.new_edge_property("float")
        g.edge_properties["ttl"] = g.new_edge_property("float")

        # Sorted list of tuples of the form (ip_address, vertex_index)
        vertex_ip_list = []
        for node in tqdm(self.nodes, total=len(self.nodes)):
            v = g.add_vertex()
            g.vp.ip_address[v] = node
            bisect.insort_left(vertex_ip_list, (node, int(v)))

        for edge in self.edges:
            # Connect vertices with the source and destination IP address
            # and add to its properties
            v1 = bisect.bisect_left(vertex_ip_list, (edge[0], 0))
            v2 = bisect.bisect_left(vertex_ip_list, (edge[1], 0))
            e = g.add_edge(v1, v2)
            g.ep.ip_source[e] = edge[0]
            g.ep.ip_dest[e] = edge[1]
            g.ep.timestamp[e] = edge[2]
            g.ep.port_source[e] = edge[3]
            g.ep.port_dest[e] = edge[4]
            g.ep.ttl[e] = edge[5]
            g.ep.num_bytes[e] = edge[6]

        if save_graph == True:
            save_type = save_filename.split(".")[1]
            if save_type in ["gt", "graphml", "xml", "dot", "gml"]:
                g.save(save_filename, fmt = save_type)
            else:
                print("Invalid save type. Graph not saved.")

        return g
