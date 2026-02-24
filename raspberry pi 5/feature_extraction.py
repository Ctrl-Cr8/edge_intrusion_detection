import numpy as np
from scapy.all import sniff, IP, TCP
import threading
import time
from collections import defaultdict

flows = {}
completed_flows = []
lock = threading.Lock()

PACKET_THRESHOLD = 10  # extract features every 10 packets
INTERFACE = "eth0"

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    
    
    protocol = ip.proto  #PROTOCOL

    #PACKET SIZE
    length = len(pkt)

    
    timestamp = time.time()



    syn = ack = rst = 0
    if pkt.haslayer(TCP):

        flags = pkt[TCP].flags
        syn = 1 if flags & 0x02 else 0
        ack = 1 if flags & 0x10 else 0
        rst = 1 if flags & 0x04 else 0

    
    packet_info = {
        "timestamp": timestamp,
        "length": length,
        "syn": syn,
        "ack": ack,
        "rst": rst,
    }

    flow_key = (src_ip, dst_ip, protocol)

    with lock:
        
        if flow_key not in flows:
            flows[flow_key] = []
        flows[flow_key].append(packet_info)

        #CHECK IF 10 PACKETS HAVE ARRIVED
        if len(flows[flow_key]) >= PACKET_THRESHOLD:

            flow_packets = flows.pop(flow_key)
            features, meta = compute_features(flow_packets, flow_key)

            completed_flows.append((meta, features))

def compute_features(packets, flow_key):
    src_ip, dst_ip, protocol = flow_key
    
    lengths = [p["length"] for p in packets]

    
    timestamps = [p["timestamp"] for p in packets]

    #FLOW DURATION
    flow_duration = timestamps[-1] - timestamps[0]
    if flow_duration == 0:
        flow_duration = 1e-6  
    


    #FLOW BYTES /S
    total_bytes = sum(lengths)
    flow_bytes_per_s = total_bytes / flow_duration


    #FLOW PACKETS/S
    flow_packets_per_s = len(packets) / flow_duration
    
    
    #PACKET LENGTH MEAN
    packet_length_mean = np.mean(lengths)

    #INTERVAL BETWEEN PACKETS
    iats = []

    for i in range(len(timestamps)-1):
        iats.append( timestamps[i+1] - timestamps[i])

    flow_iat_mean = np.mean(iats) if iats else 0
    
    #INTERVAL DEVIATION
    flow_iat_std = np.std(iats) if iats else 0

    #SYN, ACK AND RST COUNT
    syn_count = sum(p["syn"] for p in packets)
    ack_count = sum(p["ack"] for p in packets)
    rst_count = sum(p["rst"] for p in packets)


    
    features = np.array([
        protocol,
        flow_duration,
        flow_bytes_per_s,
        flow_packets_per_s,
        packet_length_mean,
        flow_iat_mean,
        flow_iat_std,
        syn_count,
        ack_count,
        rst_count
    ], dtype=np.float32)


    #SOURCE IP, DESTINATION IP AND PROTOCOL
    meta = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol
    }

    return features, meta



def extract_features():
    with lock:
        ready = completed_flows[:]
        completed_flows.clear()
    
    return ready


def start_sniffing():
    sniff(iface= INTERFACE, prn=process_packet, store=False)

sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()