import warnings
from pandas.core.common import SettingWithCopyWarning
import pandas as pd
from tqdm import tqdm
import socket
import numpy
import sys

sys.path.append("..")
from utilities.network import *

warnings.simplefilter(action="ignore", category=SettingWithCopyWarning)


def updateFlows(Flows, Packets, row, local_ip, mode, malicious_IPs_list):
    SrcIP = row['Source'] if row['Source']<row['Destination'] else row['Destination']
    SrcPort = row['Source Port'] if row['Source Port']<row['Destination Port'] else row['Destination Port']
    DstIp = row['Destination'] if row['Source']<row['Destination'] else row['Source']
    DstPort = row['Destination Port'] if row['Source Port']<row['Destination Port'] else row['Source Port']
    Duration = Packets['Time'].max() - Packets['Time'].min()
    PX = len(Packets.index)
    NNP = Num_null_packets(Packets)
    NSP = Num_small_packets(Packets)
    PSP = NSP/PX
    if (len(Packets[Packets['Forward'] == 0]) != 0):
        IOPR = len(Packets[Packets['Forward'] == 1])/len(Packets[Packets['Forward'] == 0])
    else:
        IOPR = -1
    Reconnect = len(Packets[Packets['TCP Flags'] == 2]) - 1 
    FPS = Packets.loc[0]['Length']
    TBT = Packets['Length'].sum()
    APL = Average_payload_len(Packets)
    DPL = Num_different_packets_len(Packets)
    PV = Stdv_payload(Packets)
    if Duration != float(0):
        BPS = TBT*8/Duration # ???
        PS = PX/Duration # ???
    else:
        BPS = -1
        PS = -1
    AIT = Average_arrival_time(Packets)
    MPL = Packets['Length'].max()
    MP = len(Packets[Packets['Length'] == MPL])

    if (mode == 'dataset'):
        Label = 1 if SrcIP in malicious_IPs_list or DstIp in malicious_IPs_list else 0
        Flows.loc[len(Flows)] = [SrcIP, SrcPort, DstIp, DstPort, Duration, PX, NNP, NSP, PSP, IOPR, Reconnect, FPS, TBT, APL, DPL, PV, BPS, PS, AIT, MPL, MP, Label]
    else:
        Flows.loc[len(Flows)] = [SrcIP, SrcPort, DstIp, DstPort, Duration, PX, NNP, NSP, PSP, IOPR, Reconnect, FPS, TBT, APL, DPL, PV, BPS, PS, AIT, MPL, MP]


def Stdv_payload(packets):
    length_list = []
    for index, row in packets.iterrows():
        length_list.append(row['Length'])
    return numpy.std(length_list)


def Num_different_packets_len(packets):
    length_list = []
    for index, row in packets.iterrows():
        if row['Length'] not in length_list:
            length_list.append(row['Length'])
    return len(length_list)


def Average_payload_len(packets):
    sum = 0
    for index, row in packets.iterrows():
        if row['Protocol'] == 17:
            sum += row['UDP Length']-8
        if row['Protocol'] == 6:
            sum += row['TCP Payload Length']

    return sum/len(packets.index)


def Num_small_packets(packets):
    sum = 0
    for index, row in packets.iterrows():
        if row['Length'] >= 63 and row['Length'] <= 400:
            sum += 1

    return sum


def Num_null_packets(packets):
    sum = 0
    for index, row in packets.iterrows():
        if (row['Protocol'] == 17 and row['UDP Length']-8 == 0) or \
            (row['Protocol'] == 6 and row['TCP Payload Length'] == 0):
            sum += 1
    return sum


def Average_arrival_time(packets):
    prevT = None
    sum_int = 0
    for index, row in packets.iterrows():
        if prevT == None:
            prevT = row['Time']
            continue

        sum_int += row['Time']-prevT
        prevT = row['Time']

    if (len(packets) != 0):
        iat_mean = sum_int/len(packets)
    else:
        iat_mean = 0


    return iat_mean


def flow_id(x):
    if x['Source']<x['Destination']:
        return str(x['Source'])+'-'+str(x['Destination'])+'-'+str(x['Source Port'])+'-'+str(x['Destination Port'])+'-'+str(x['Protocol'])
    else:
        return str(x['Destination'])+'-'+str(x['Source'])+'-'+str(x['Destination Port'])+'-'+str(x['Source Port'])+'-'+str(x['Protocol'])


def convert_to_float(d, mode):
    if (mode == 'dataset'):
        d['Time'] = d['Time'].progress_apply(lambda x: float(x))
        print("\'Time\' feature converted to float")
        d['Source'] = d['Source'].progress_apply(lambda x: float(ip2int(str(x))))
        print("\'Source\' feature converted to float")
        d['Destination'] = d['Destination'].progress_apply(lambda x: float(ip2int(str(x))))
        print("\'Destination\' feature converted to float")
        d['Source Port'] = d['Source Port'].progress_apply(lambda x: float(x))
        print("\'Source Port\' feature converted to float")
        d['Destination Port'] = d['Destination Port'].progress_apply(lambda x: float(x))
        print("\'Destination Port\' feature converted to float")
        d['EtherType'] = d['EtherType'].progress_apply(lambda x: float(6) if str(x) == 'IPv4' else float(x) if str(x).isnumeric() else float('nan'))
        print("\'EtherType\' feature converted to float")
        d['Protocol'] = d['Protocol'].progress_apply(lambda x: float(6) if str(x) == 'TCP' else float(17) if str(x) == 'UDP' else float(x) if str(x).isnumeric() else float('nan'))
        print("\'Protocol\' feature converted to float")
        d['TCP Flags'] = d['TCP Flags'].progress_apply(lambda x: float(int(x, 16)) if 'x' in str(x) else float(x))
        print("\'TCP Flags\' feature converted to float")
        d['Length'] = d['Length'].progress_apply(lambda x: float(x))
        print("\'Length\' feature converted to float")
        d['TCP Payload Length'] = d['TCP Payload Length'].progress_apply(lambda x: float(x))
        print("\'TCP Payload Length\' feature converted to float")
        d['UDP Length'] = d['UDP Length'].progress_apply(lambda x: float(x))
        print("\'UDP Length\' feature converted to float")
        d['TTL'] = d['TTL'].progress_apply(lambda x: float(x) if str(x).isnumeric() else float('nan'))
        print("\'TTL\' feature converted to float")
    else:
        d['Time'] = d['Time'].apply(lambda x: float(x))
        d['Source'] = d['Source'].apply(lambda x: float(ip2int(str(x))))
        d['Destination'] = d['Destination'].apply(lambda x: float(ip2int(str(x))))
        d['Source Port'] = d['Source Port'].apply(lambda x: float(x))
        d['Destination Port'] = d['Destination Port'].apply(lambda x: float(x))
        d['EtherType'] = d['EtherType'].apply(lambda x: float(6) if str(x) == 'IPv4' else float(x) if str(x).isnumeric() else float('nan'))
        d['Protocol'] = d['Protocol'].apply(lambda x: float(6) if str(x) == 'TCP' else float(17) if str(x) == 'UDP' else float(x) if str(x).isnumeric() else float('nan'))
        d['TCP Flags'] = d['TCP Flags'].apply(lambda x: float(int(x, 16)) if 'x' in str(x) else float(x))
        d['Length'] = d['Length'].apply(lambda x: float(x))
        d['TCP Payload Length'] = d['TCP Payload Length'].apply(lambda x: float(x))
        d['UDP Length'] = d['UDP Length'].apply(lambda x: float(x))
        d['TTL'] = d['TTL'].apply(lambda x: float(x) if str(x).isnumeric() else float('nan'))

    return d



def FlowFeaturesExtractor(captured_packets, mode, malicious_IPs_list):
    local_ip = socket.gethostbyname(socket.gethostname())
    if (mode != 'dataset' and mode != 'traffic'):
        return None

    if mode == 'dataset':       
        tqdm.pandas()

    d = captured_packets
    d = convert_to_float(d, mode)
    d = d[d['Source'].notnull() & d['Destination'].notnull() & d['Source Port'].notnull() & d['Destination Port'].notnull() & d['EtherType'].notnull() & d['Protocol'].notnull()]

    if mode == 'dataset':
        d['Forward'] = d.progress_apply(lambda x: 1 if str(x['Source']) < str(x['Destination']) else 0, axis=1)
        print("\'Forward\' feature converted to float")
        d['UFid'] = d.progress_apply(lambda x: flow_id(x), axis=1)
        print("\'UFid\' feature converted to float")
    else:
        d['Forward'] = d.apply(lambda x: 1 if str(x['Source']) < str(x['Destination']) else 0, axis=1)
        d['UFid'] = d.apply(lambda x: flow_id(x), axis=1)

    if mode == 'dataset':
        print("\nSorting Dataframe...")

    d = d.sort_values(['UFid','Time'])

    if mode == 'dataset':
        print("\nExtracting Flow Features...")

    if (mode == 'dataset'):
        Flows = pd.DataFrame(columns=['SrcIP', 'SrcPort', 'DstIP', 'DstPort', 'Duration', 'PX', 'NNP', 'NSP', 'PSP', 'IOPR', 'Reconnect', 'FPS', 'TBT', 'APL', 'DPL', 'PV', 'BPS', 'PS', 'AIT', 'MPL', 'MP', 'Label'])
    else:
        Flows = pd.DataFrame(columns=['SrcIP', 'SrcPort', 'DstIP', 'DstPort', 'Duration', 'PX', 'NNP', 'NSP', 'PSP', 'IOPR', 'Reconnect', 'FPS', 'TBT', 'APL', 'DPL', 'PV', 'BPS', 'PS', 'AIT', 'MPL', 'MP'])

    prev = None
    Packets = pd.DataFrame(columns=['Time', 'Source', 'Destination', 'Source Port', 'Destination Port', 'EtherType', 'Protocol', 'TCP Flags', 'Length', 'TCP Payload Length', 'UDP Length', 'TTL', 'Forward', 'UFid'])
    
    for index, row in tqdm(d.iterrows(), total=d.shape[0]):
        if mode == 'traffic':
            if row['Source'] != ip2int(local_ip) and row['Destination'] != ip2int(local_ip):
                continue

        if prev is None:
            Packets.loc[len(Packets)] = row
        
        elif row['Protocol'] == 6 and row['UFid'] == prev['UFid']: #MOD 3
            Packets.loc[len(Packets)] = row
            
        elif row['Protocol'] == 17 and row['UFid'] == prev['UFid']:
            Packets.loc[len(Packets)] = row
            if (row['Forward'] == 0):
                updateFlows(Flows, Packets, prev, local_ip, mode, malicious_IPs_list)            
                Packets.drop(Packets.index, inplace=True)
        else:
            if not (prev['Protocol'] == 17 and prev['Forward'] == 0):
                updateFlows(Flows, Packets, prev, local_ip, mode, malicious_IPs_list)
                Packets.drop(Packets.index, inplace=True)
            Packets.loc[len(Packets)] = row
        
        prev = row

    # Fill the NaN values in the "Flows" Dataframe
    Flows.fillna(0, inplace=True)
    
    del Packets

    return Flows


if __name__ == '__main__':
    if (len(sys.argv) == 3):
        dataset = pd.read_csv(sys.argv[1])

        malicious_IPs_list = []
        with open(sys.argv[2]) as malicious_IPs:
            malicious_IPs_list = malicious_IPs.read()
        
        malicious_IPs_list = malicious_IPs_list.split('\n')
        for i in range(len(malicious_IPs_list)):
            malicious_IPs_list[i] = float(ip2int(malicious_IPs_list[i]))

        flows = FlowFeaturesExtractor(dataset, 'dataset', malicious_IPs_list)
        print(flows)
        print("\nSaving extracted Flow Features")
        flows.to_hdf('training_dataset/training.hdf5', key='flows', mode='w')
    else:
        print("\nUSAGE (Windows): python flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>")
        print("USAGE (Linux): python3 flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>\n")
        sys.exit(-1)