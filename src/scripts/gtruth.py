# Precompute ground truth and then start testing
import sys
import json
from scapy.all import rdpcap
from scapy.all import IP, IPv6, TCP, UDP

def compute_gtruth(pcap_file, threshold):
    pkt_dict = {}
    hh_list = []
    packets = rdpcap(pcap_file)

    for pkt in packets:
        id_tuple = None

        if TCP in pkt and IPv6 in pkt:
            id_tuple = handle_tcp_6_traffic(pkt)
        elif UDP in pkt and IPv6 in pkt:
            id_tuple = handle_udp_6_traffic(pkt)
        elif TCP in pkt and IP in pkt:
            id_tuple = handle_tcp_4_traffic(pkt)
        elif UDP in pkt and IP in pkt:
            id_tuple = handle_udp_4_traffic(pkt)
        
        if id_tuple is None:
            continue

        if id_tuple not in pkt_dict:
            pkt_dict[id_tuple] = 1
        else:
            pkt_dict[id_tuple] += 1
        
        if pkt_dict[id_tuple] > threshold and id_tuple not in hh_list:
            hh_list.append(id_tuple)

    return hh_list


def handle_tcp_4_traffic(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    return (src_ip, dst_ip, proto, sport, dport)

def handle_udp_4_traffic(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    return (src_ip, dst_ip, proto, sport, dport)

def handle_tcp_6_traffic(packet):
    src_ip = packet[IPv6].src
    dst_ip = packet[IPv6].dst
    proto = packet[IPv6].nh
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    return (src_ip, dst_ip, proto, sport, dport)

def handle_udp_6_traffic(packet):
    src_ip = packet[IPv6].src
    dst_ip = packet[IPv6].dst
    proto = packet[IPv6].nh
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    return (src_ip, dst_ip, proto, sport, dport)



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: start.py <dataset.pcap> <threshold>")
        exit(1)

    dataset_path = sys.argv[1]
    threshold = int(sys.argv[2])
    gtruth_output_path = "run/gtruth.json"
    gtruth = compute_gtruth(dataset_path, threshold)
    with open(gtruth_output_path, 'w') as f:
        json.dump(gtruth, f)

