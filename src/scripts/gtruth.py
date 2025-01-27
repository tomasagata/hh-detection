# Precompute ground truth and then start testing
import json
import argparse
from scapy.all import rdpcap
from scapy.all import IP, IPv6, TCP, UDP

def separate_flows(pcap_file, no_ipv6: bool, identifier_items: int):
    flow_dict = {}
    packets = rdpcap(pcap_file)

    for pkt in packets:
        flow_id = None

        if TCP in pkt and IPv6 in pkt and not no_ipv6:
            flow_id = handle_tcp_6_traffic(pkt, identifier_items)
        elif UDP in pkt and IPv6 in pkt and not no_ipv6:
            flow_id = handle_udp_6_traffic(pkt, identifier_items)
        elif TCP in pkt and IP in pkt:
            flow_id = handle_tcp_4_traffic(pkt, identifier_items)
        elif UDP in pkt and IP in pkt:
            flow_id = handle_udp_4_traffic(pkt, identifier_items)
        
        if flow_id is None:
            continue

        if flow_id not in flow_dict:
            flow_dict[flow_id] = 1
        else:
            flow_dict[flow_id] += 1

    return flow_dict

def compute_threshold(flow_dict, pkt_threshold):
    hh_list = []
    for flow_id, pkt_count in flow_dict.items():
        if pkt_count > pkt_threshold and flow_id not in hh_list:
            hh_list.append(flow_id)
    return hh_list

def compute_topk(flow_dict, top_k):
    sorted_items = sorted(flow_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_flow_ids = [flow_id for flow_id, _ in sorted_items]
    return sorted_flow_ids[:top_k]

def handle_tcp_4_traffic(packet, identifier_items):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if identifier_items == 5:
        proto = packet[IP].proto
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        return (src_ip, dst_ip, proto, sport, dport)
    return (src_ip, dst_ip)

def handle_udp_4_traffic(packet, identifier_items):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if identifier_items == 5:
        proto = packet[IP].proto
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        return (src_ip, dst_ip, proto, sport, dport)
    return (src_ip, dst_ip)

def handle_tcp_6_traffic(packet, identifier_items):
    src_ip = packet[IPv6].src
    dst_ip = packet[IPv6].dst
    if identifier_items == 5:
        proto = packet[IPv6].nh
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        return (src_ip, dst_ip, proto, sport, dport)
    return (src_ip, dst_ip)

def handle_udp_6_traffic(packet, identifier_items):
    src_ip = packet[IPv6].src
    dst_ip = packet[IPv6].dst
    if identifier_items == 5:
        proto = packet[IPv6].nh
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        return (src_ip, dst_ip, proto, sport, dport)
    return (src_ip, dst_ip)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate ground truth file from packet capture")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--threshold", type=int, help="Specify the packet threshold to start considering a flow as a heavy hitter.")
    group.add_argument("-k", "--top-k", type=int, help="Specify the amount of flows to consider as heavy hitters.")
    parser.add_argument("--no-ipv6", action='store_true', help="Avoid using IPv6 traffic for ground truth generation.")
    parser.add_argument("-I", "--identifier", type=int, default=5, help="Specify the identifying tuple for each flow.")
    parser.add_argument("pcap_file", type=str, help="Specify the packet capture file to read from.") 
    args = parser.parse_args()
    
    gtruth_output_path = "run/gtruth.json"
    flows = separate_flows(args.pcap_file, no_ipv6=args.no_ipv6, identifier_items=args.identifier)

    if args.threshold is not None:
        hh_list = compute_threshold(flows, args.threshold)
    elif args.top_k is not None:
        hh_list = compute_topk(flows, args.top_k)
    with open(gtruth_output_path, 'w+') as f:
        json.dump(hh_list, f)

