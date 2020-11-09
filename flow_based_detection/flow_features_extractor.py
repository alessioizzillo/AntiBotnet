import pandas as pd
from tqdm import tqdm
import socket


# Extract from the Dataframe 'Packets' the Flow features
def updateFlows(Flows, Packets, row, local_ip):
    IP = row['Destination'] if row['Destination'] != local_ip else row['Source']
    Src_Port = row['Source Port']
    Flow_Duration = Packets['Time'].max() - Packets['Time'].min()
    Tot_Fwd_Pkts = len(Packets[Packets['Forward'] == 1])
    Tot_Bwd_Pkts = len(Packets[Packets['Forward'] == 0])
    TotLen_Fwd_Pkts = Packets[Packets['Forward'] == 1]['Length'].sum()
    TotLen_Bwd_Pkts = Packets[Packets['Forward'] == 0]['Length'].sum()
    Fwd_Pkt_Len_Max = Packets[Packets['Forward'] == 1]['Length'].max()
    Fwd_Pkt_Len_Min = Packets[Packets['Forward'] == 1]['Length'].min()
    Fwd_Pkt_Len_Mean = Packets[Packets['Forward'] == 1]['Length'].mean()
    Fwd_Pkt_Len_Std = Packets[Packets['Forward'] == 1]['Length'].std()
    Bwd_Pkt_Len_Max = Packets[Packets['Forward'] == 0]['Length'].max()
    Bwd_Pkt_Len_Min = Packets[Packets['Forward'] == 0]['Length'].min()
    Bwd_Pkt_Len_Mean = Packets[Packets['Forward'] == 0]['Length'].mean()
    Bwd_Pkt_Len_Std = Packets[Packets['Forward'] == 0]['Length'].std()
    Flow_IAT_Mean = IAT_Mean(Packets)
    Flow_IAT_Std = IAT_Std(Packets)
    Flow_IAT_Max = IAT_Max(Packets)
    Flow_IAT_Min = IAT_Min(Packets)
    Fwd_IAT_Tot = IAT_Sum(Packets[Packets['Forward'] == 1])
    Fwd_IAT_Mean = IAT_Mean(Packets[Packets['Forward'] == 1])
    Bwd_IAT_Mean = IAT_Mean(Packets[Packets['Forward'] == 0])
    Fwd_IAT_Max = IAT_Max(Packets[Packets['Forward'] == 1])
    Fwd_IAT_Min = IAT_Min(Packets[Packets['Forward'] == 1])
    Bwd_IAT_Tot = IAT_Sum(Packets[Packets['Forward'] == 0])
    Bwd_IAT_Mean = IAT_Mean(Packets[Packets['Forward'] == 0])
    Bwd_IAT_Std = IAT_Std(Packets[Packets['Forward'] == 0])
    Bwd_IAT_Max = IAT_Max(Packets[Packets['Forward'] == 0])
    Bwd_IAT_Min = IAT_Min(Packets[Packets['Forward'] == 0])
    Fwd_PSH_Flags = Count_Flags(Packets[Packets['Forward'] == 1], 8)
    Bwd_PSH_Flags = Count_Flags(Packets[Packets['Forward'] == 0], 8)
    Fwd_URG_Flags = Count_Flags(Packets[Packets['Forward'] == 1], 32)
    Bwd_URG_Flags = Count_Flags(Packets[Packets['Forward'] == 0], 32)
    Pkt_Len_Min = Packets['Length'].min()
    Pkt_Len_Max = Packets['Length'].max()
    Pkt_Len_Mean = Packets['Length'].mean()
    Pkt_Len_Std = Packets['Length'].std()
    Pkt_Len_Var = Packets['Length'].var()
    FIN_Flag_Cnt = Count_Flags(Packets, 1)
    SYN_Flag_Cnt = Count_Flags(Packets, 2)
    RST_Flag_Cnt = Count_Flags(Packets, 4)
    PSH_Flag_Cnt = Count_Flags(Packets, 8)
    ACK_Flag_Cnt = Count_Flags(Packets, 16)
    URG_Flag_Cnt = Count_Flags(Packets, 32)
    CWE_Flag_Count = Count_Flags(Packets, 128)
    ECE_Flag_Cnt = Count_Flags(Packets, 64)

    Flows.loc[len(Flows)] = [IP, Src_Port, Flow_Duration, Tot_Fwd_Pkts, Tot_Bwd_Pkts, TotLen_Fwd_Pkts, TotLen_Bwd_Pkts, Fwd_Pkt_Len_Max, Fwd_Pkt_Len_Min, Fwd_Pkt_Len_Mean, Fwd_Pkt_Len_Std, Bwd_Pkt_Len_Max, Bwd_Pkt_Len_Min, Bwd_Pkt_Len_Mean, Bwd_Pkt_Len_Std, Flow_IAT_Mean, Flow_IAT_Std, Flow_IAT_Max, Flow_IAT_Min, Fwd_IAT_Tot, Fwd_IAT_Mean, Bwd_IAT_Mean, Fwd_IAT_Max, Fwd_IAT_Min, Bwd_IAT_Tot, Bwd_IAT_Mean, Bwd_IAT_Std, Bwd_IAT_Max, Bwd_IAT_Min, Fwd_PSH_Flags, Bwd_PSH_Flags, Fwd_URG_Flags, Bwd_URG_Flags, Pkt_Len_Min, Pkt_Len_Max, Pkt_Len_Mean, Pkt_Len_Std, Pkt_Len_Var, FIN_Flag_Cnt, SYN_Flag_Cnt, RST_Flag_Cnt, PSH_Flag_Cnt, ACK_Flag_Cnt, URG_Flag_Cnt, CWE_Flag_Count, ECE_Flag_Cnt]

# MOD 1
def flow_id(x):
    if x['Source']<x['Destination']:
        return str(x['Source'])+'-'+str(x['Destination'])+'-'+str(x['Source Port'])+'-'+str(x['Destination Port'])+'-'+str(x['Protocol'])
    else:
        return str(x['Destination'])+'-'+str(x['Source'])+'-'+str(x['Destination Port'])+'-'+str(x['Source Port'])+'-'+str(x['Protocol'])


def Count_Flags(packets, flag):
    sum = 0
    for index, row in packets.iterrows():
        sum += 1 if int(row['tcp_Flags'])&flag else 0   #MOD 2 (giusta)
    return sum


def IAT_Min(packets):
    prevT = None
    min_int = None
    for index, row in packets.iterrows():
        if prevT == None:
            prevT = row['Time']
            continue

        interval = row['Time']-prevT
        if min_int == None or interval < min_int:
            min_int = interval
        prevT = row['Time']

    return min_int


def IAT_Max(packets):
    prevT = None
    max_int = 0
    for index, row in packets.iterrows():
        if prevT == None:
            prevT = row['Time']
            continue

        interval = row['Time']-prevT
        if interval > max_int:
            max_int = interval
        prevT = row['Time']

    return max_int


def IAT_Mean(packets):
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


def IAT_Sum(packets):
    prevT = None
    sum_int = 0
    for index, row in packets.iterrows():
        if prevT == None:
            prevT = row['Time']
            continue

        sum_int += row['Time']-prevT
        prevT = row['Time']

    return sum_int


def IAT_Std(packets):
    prevT = None
    Interval = pd.DataFrame(columns=['Interval'])
    for index, row in packets.iterrows():
        if prevT == None:
            prevT = row['Time']
            continue

        Interval[len(Interval)] = row['Time']-prevT
        prevT = row['Time']

    return Interval['Interval'].std()


def FlowFeaturesExtractor(captured_packets):
    local_ip = socket.gethostbyname(socket.gethostname())

    prev = None
    Packets = pd.DataFrame(columns=['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Source Port', 'tcp_Flags', 'Destination Port', 'UFid', 'Forward'])
    Flows = pd.DataFrame(columns=['IP', 'Src_Port', 'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts', 'TotLen_Fwd_Pkts', 'TotLen_Bwd_Pkts', 'Fwd_Pkt_Len_Max', 'Fwd_Pkt_Len_Min', 'Fwd_Pkt_Len_Mean', 'Fwd_Pkt_Len_Std', 'Bwd_Pkt_Len_Max', 'Bwd_Pkt_Len_Min', 'Bwd_Pkt_Len_Mean', 'Bwd_Pkt_Len_Std', 'Flow_IAT_Mean', 'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Tot', 'Fwd_IAT_Mean', 'Bwd_IAT_Mean.1', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Tot', 'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Fwd_PSH_Flags', 'Bwd_PSH_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags', 'Pkt_Len_Min', 'Pkt_Len_Max', 'Pkt_Len_Mean', 'Pkt_Len_Std', 'Pkt_Len_Var', 'FIN_Flag_Cnt', 'SYN_Flag_Cnt', 'RST_Flag_Cnt', 'PSH_Flag_Cnt', 'ACK_Flag_Cnt', 'URG_Flag_Cnt', 'CWE_Flag_Count', 'ECE_Flag_Cnt'])

    d = captured_packets
    d = d[d['Source Port'].notnull() & d['Destination Port'].notnull()]
    d['Forward'] = d.apply(lambda x: 1 if x['Source']<x['Destination'] else 0, axis=1)
    d['UFid'] = d.apply(lambda x:flow_id(x), axis=1)
    d.fillna(0, inplace=True)

    d = d.sort_values(['UFid','Time'])

    for index, row in tqdm(d.iterrows(), total=d.shape[0]):
        if row['Source'] != local_ip and row['Destination'] != local_ip:
            continue

        if prev is None:
            Packets.loc[len(Packets)] = row
        
        elif row['Protocol'] == 6 and row['UFid'] == prev['UFid'] and not row['tcp_Flags']==2: #MOD 3
            Packets.loc[len(Packets)] = row
           
        elif row['Protocol'] == 17 and row['UFid'] == prev['UFid']:
            Packets.loc[len(Packets)] = row
            if (row['Forward'] == 0):
                updateFlows(Flows, Packets, prev, local_ip)            
                Packets.drop(Packets.index, inplace=True)
        else:
            updateFlows(Flows, Packets, prev, local_ip)            
            Packets.drop(Packets.index, inplace=True)
            Packets.loc[len(Packets)] = row
        
        prev = row

    # Fill the NaN values in the "Flows" Dataframe
    Flows.fillna(0, inplace=True)
    
    del Packets

    return Flows