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


def updateFlows(Flows, Source, Source_Port, Destination, Destination_Port, Protocol, Time, TCP_Flags, Length, TCP_Payload_Length, UDP_Length, TTL, Forward, mode, malicious_IPs_list):  
    SrcIP = Source if Source<Destination else Destination
    SrcPort = Source_Port if Source_Port<Destination_Port else Destination_Port
    DstIp = Destination if Source<Destination else Source
    DstPort = Destination_Port if Source_Port<Destination_Port else Source_Port
    Duration = max(Time) - min(Time)
    PX = len(Time)
    NNP = Num_null_packets(Protocol, UDP_Length, TCP_Payload_Length)
    NSP = Num_small_packets(Length)
    PSP = NSP/PX
    if (Forward.count(0) != 0):
        IOPR = Forward.count(1)/Forward.count(0)
    else:
        IOPR = -1
    Reconnect = TCP_Flags.count(2) - 1 
    FPS = Length[0]
    TBT = sum(Length)
    APL = Average_payload_len(Protocol, UDP_Length, TCP_Payload_Length)
    DPL = Num_different_packets_len(Length)
    PV = Stdv_payload(Length)
    if Duration != float(0):
        BPS = TBT*8/Duration # ???
        PS = PX/Duration # ???
    else:
        BPS = -1
        PS = -1
    AIT = Average_arrival_time(Time)
    MPL = max(Length)
    MP = Length.count(MPL)

    if (mode == 'training'):
        Label = 1 if SrcIP in malicious_IPs_list or DstIp in malicious_IPs_list else 0
        Flows.append([SrcIP, SrcPort, DstIp, DstPort, Duration, PX, NNP, NSP, PSP, IOPR, Reconnect, FPS, TBT, APL, DPL, PV, BPS, PS, AIT, MPL, MP, Label])
    else:
        Flows.append([SrcIP, SrcPort, DstIp, DstPort, Duration, PX, NNP, NSP, PSP, IOPR, Reconnect, FPS, TBT, APL, DPL, PV, BPS, PS, AIT, MPL, MP])


def Stdv_payload(Length):
    length_list = []
    for l in Length:
        length_list.append(l)
    return numpy.std(length_list)


def Num_different_packets_len(Length):
    length_list = []
    for l in Length:
        if l not in length_list:
            length_list.append(l)
    return len(length_list)


def Average_payload_len(Protocol, UDP_Length, TCP_Payload_Length):
    s = 0

    if (Protocol == 6):
        for ul in UDP_Length:
            s += ul-8
        
        return s/len(UDP_Length)
    else:
        for tpl in TCP_Payload_Length:
            s += tpl
        
        return s/len(TCP_Payload_Length)


def Num_small_packets(Length):
    s = 0
    for l in Length:
        if l >= 63 and l <= 400:
            s += 1

    return s


def Num_null_packets(Protocol, UDP_Length, TCP_Payload_Length):
    s = 0
    if (Protocol == 6):
        for ul in UDP_Length:
            if ul-8 == 0:
                s += 1
    else:
        for tpl in TCP_Payload_Length:
            if tpl == 0:
                s += 1 

    return s


def Average_arrival_time(Time):
    prevT = None
    sum_int = 0
    for i in range(len(Time)):
        if prevT == None:
            prevT = Time[i]
            continue
        sum_int += Time[i]-prevT
        prevT = Time[i]

    if (len(Time) != 0):
        iat_mean = sum_int/len(Time)
    else:
        iat_mean = 0

    return iat_mean


def flow_id(x):
    if x['Source']<x['Destination']:
        return str(x['Source'])+'-'+str(x['Destination'])+'-'+str(x['Source Port'])+'-'+str(x['Destination Port'])+'-'+str(x['Protocol'])
    else:
        return str(x['Destination'])+'-'+str(x['Source'])+'-'+str(x['Destination Port'])+'-'+str(x['Source Port'])+'-'+str(x['Protocol'])


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



def FlowFeaturesExtractor(captured_packets, mode, malicious_IPs_list):
    local_ip = socket.gethostbyname(socket.gethostname())
    if (mode != 'training' and mode != 'predicting'):
        return None

    if mode == 'training':       
        tqdm.pandas()

    d = captured_packets

    if (mode == 'training'):
        d = convert_to_float(d)

    d = d[d['Source'].notnull() & d['Destination'].notnull() & d['Source Port'].notnull() & \
        d['Destination Port'].notnull() & (d['EtherType'] == 2048) & ((d['Protocol'] == 6) | (d['Protocol'] == 17))]

    if mode == 'training':
        d['Forward'] = d.progress_apply(lambda x: 1 if x['Source'] < x['Destination'] else 0, axis=1)
        print("\'Forward\' feature converted to float")
        d['UFid'] = d.progress_apply(lambda x: flow_id(x), axis=1)
        print("\'UFid\' feature converted to float")
    else:
        d['Forward'] = d.apply(lambda x: 1 if x['Source'] < x['Destination'] else 0, axis=1)
        d['UFid'] = d.apply(lambda x: flow_id(x), axis=1)

    if mode == 'training':
        print("\nSorting Dataframe...")

    d = d.sort_values(['UFid','Time'])

    if mode == 'training':
        print("\nExtracting Flow Features...")

    Flows = []

    prev = None
    Packets = pd.DataFrame(columns=['Time', 'Source', 'Destination', 'Source Port', 'Destination Port', 'EtherType', 'Protocol', 'TCP Flags', 'Length', 'TCP Payload Length', 'UDP Length', 'TTL', 'Forward', 'UFid'])
    Time = []
    TCP_Flags = []
    Length = []
    TCP_Payload_Length = []
    UDP_Length = []
    TTL = []
    Forward = []

    for index, row in tqdm(d.iterrows(), total=d.shape[0]):
        if mode == 'traffic':
            if row['Source'] != ip2int(local_ip) and row['Destination'] != ip2int(local_ip):
                continue

        if prev is None:
            Time.append(row['Time'])
            TCP_Flags.append(row['TCP Flags'])
            Length.append(row['Length'])
            TCP_Payload_Length.append(row['TCP Payload Length'])
            UDP_Length.append(row['UDP Length'])
            TTL.append(row['TTL'])
            Forward.append(row['Forward'])
        
        elif row['Protocol'] == 6 and row['UFid'] == prev['UFid']: #MOD 3
            Time.append(row['Time'])
            TCP_Flags.append(row['TCP Flags'])
            Length.append(row['Length'])
            TCP_Payload_Length.append(row['TCP Payload Length'])
            UDP_Length.append(row['UDP Length'])
            TTL.append(row['TTL'])
            Forward.append(row['Forward'])
            
        elif row['Protocol'] == 17 and row['UFid'] == prev['UFid']:
            Time.append(row['Time'])
            TCP_Flags.append(row['TCP Flags'])
            Length.append(row['Length'])
            TCP_Payload_Length.append(row['TCP Payload Length'])
            UDP_Length.append(row['UDP Length'])
            TTL.append(row['TTL'])
            Forward.append(row['Forward'])
            # if (row['Forward'] == 0):
            #     updateFlows(Flows, row['Source'], row['Source Port'], row['Destination'], row['Destination Port'], row['Protocol'], Time, TCP_Flags, Length, TCP_Payload_Length, UDP_Length, TTL, Forward, mode, malicious_IPs_list)       
            #     Time.clear()
            #     TCP_Flags.clear()
            #     Length.clear()
            #     TCP_Payload_Length.clear()
            #     UDP_Length.clear()
            #     TTL.clear()
            #     Forward.clear()
        else:
            # if not (prev['Protocol'] == 17 and prev['Forward'] == 0):
            #     updateFlows(Flows, prev['Source'], prev['Source Port'], prev['Destination'], prev['Destination Port'], row['Protocol'], Time, TCP_Flags, Length, TCP_Payload_Length, UDP_Length, TTL, Forward, mode, malicious_IPs_list)
            #     Time.clear()
            #     TCP_Flags.clear()
            #     Length.clear()
            #     TCP_Payload_Length.clear()
            #     UDP_Length.clear()
            #     TTL.clear()
            #     Forward.clear()

            updateFlows(Flows, prev['Source'], prev['Source Port'], prev['Destination'], prev['Destination Port'], row['Protocol'], Time, TCP_Flags, Length, TCP_Payload_Length, UDP_Length, TTL, Forward, mode, malicious_IPs_list)
            Time.clear()
            TCP_Flags.clear()
            Length.clear()
            TCP_Payload_Length.clear()
            UDP_Length.clear()
            TTL.clear()
            Forward.clear()

            Time.append(row['Time'])
            TCP_Flags.append(row['TCP Flags'])
            Length.append(row['Length'])
            TCP_Payload_Length.append(row['TCP Payload Length'])
            UDP_Length.append(row['UDP Length'])
            TTL.append(row['TTL'])
            Forward.append(row['Forward'])
        
        prev = row
    
    updateFlows(Flows, prev['Source'], prev['Source Port'], prev['Destination'], prev['Destination Port'], row['Protocol'], Time, TCP_Flags, Length, TCP_Payload_Length, UDP_Length, TTL, Forward, mode, malicious_IPs_list)

    if mode == 'training':
        df_flows = pd.DataFrame(Flows, columns=['SrcIP', 'SrcPort', 'DstIP', 'DstPort', 'Duration', 'PX', 'NNP', 'NSP', 'PSP', 'IOPR', 'Reconnect', 'FPS', 'TBT', 'APL', 'DPL', 'PV', 'BPS', 'PS', 'AIT', 'MPL', 'MP', 'Label'])
    else:
        df_flows = pd.DataFrame(Flows, columns=['SrcIP', 'SrcPort', 'DstIP', 'DstPort', 'Duration', 'PX', 'NNP', 'NSP', 'PSP', 'IOPR', 'Reconnect', 'FPS', 'TBT', 'APL', 'DPL', 'PV', 'BPS', 'PS', 'AIT', 'MPL', 'MP'])
    
    df_flows.fillna(0, inplace=True)

    del Packets

    return df_flows


if __name__ == '__main__':
    if (len(sys.argv) == 3):
        dataset = pd.read_csv(sys.argv[1])

        malicious_IPs_list = []
        with open(sys.argv[2]) as malicious_IPs:
            malicious_IPs_list = malicious_IPs.read()
        
        malicious_IPs_list = malicious_IPs_list.split('\n')
        for i in range(len(malicious_IPs_list)):
            malicious_IPs_list[i] = float(ip2int(malicious_IPs_list[i]))

        flows = FlowFeaturesExtractor(dataset, 'training', malicious_IPs_list)
        print(flows)
        print("\nSaving extracted Flow Features")
        flows.to_hdf('training_dataset/training.hdf5', key='flows', mode='w')
    else:
        print("\nUSAGE (Windows): python flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>")
        print("USAGE (Linux): python3 flow_features_extractor.py <path of the csv dataset> <path of the file containing malicious IPs>\n")
        sys.exit(-1)
