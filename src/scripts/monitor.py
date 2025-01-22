from scapy.all import sniff, get_if_list, bind_layers, AsyncSniffer
from scapy.all import Packet
from scapy.all import Ether
from scapy.fields import *
import logging
import atexit
import json
import sys

def get_if():
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

logger = logging.getLogger(__name__)
iface = get_if()
detected_hh_list = []

class Elephant4(Packet):
    name = "Elephant4"
    fields_desc = [
        IPField("src", 0),
        IPField("dst", 0),
        BitField("proto", 0, 8),
        BitField("sport", 0, 16),
        BitField("dport", 0, 16),
    ]

class Elephant6(Packet):
    name = "Elephant6"
    fields_desc = [
        IP6Field("src", 0),
        IP6Field("dst", 0),
        BitField("proto", 0, 8),
        BitField("sport", 0, 16),
        BitField("dport", 0, 16),
    ]

def handle_pkt(pkt: Packet):
    if Elephant4 in pkt:
        src_ip = pkt[Elephant4].src
        dst_ip = pkt[Elephant4].dst
        ip_proto = pkt[Elephant4].proto
        src_port = pkt[Elephant4].sport
        dst_port = pkt[Elephant4].dport
    elif Elephant6 in pkt:
        src_ip = pkt[Elephant6].src
        dst_ip = pkt[Elephant6].dst
        ip_proto = pkt[Elephant6].proto
        src_port = pkt[Elephant6].sport
        dst_port = pkt[Elephant6].dport
    else:
        return
    
    packet_info = (src_ip, dst_ip, ip_proto, src_port, dst_port)

    if packet_info not in detected_hh_list:
        detected_hh_list.append(packet_info)
        logger.info(f"New heavy hitter flow: {packet_info}")

def read_ground_truth(path: str):
    with open(path, "r") as f:
        real_hh_list = json.load(f)
    return [tuple(i) for i in real_hh_list]

def report_accuracy(real_hh_list):
    logger.info("Starting accuracy report...")
    fp = 0.0; fn = 0.0; tp = 0.0
    
    for detected_hh in detected_hh_list:
        if detected_hh in real_hh_list:
            tp += 1
        if detected_hh not in real_hh_list:
            fp += 1

    for real_hh in real_hh_list:
        if real_hh not in detected_hh_list:
            fn += 1

    try:
        precision = tp/(tp+fp)
        recall = tp/(tp+fn)
        f1 = 2 * (precision * recall) / (precision + recall)
        logger.info("Accuracy details: \n" +
            f"tp = {tp}, \n" +
            f"fp = {fp}, \n" +
            f"fn = {fn}, \n" +
            f"precision = {precision}, \n" +
            f"recall = {recall}, \n" +
            f"f1 = {f1}")
    except:
        logger.info("Accuracy measurements incomplete (zero true positives found): \n" +
            f"tp = {tp}, \n" +
            f"fp = {fp}, \n" +
            f"fn = {fn}, \n" +
            "precision = unknown, \n" +
            "recall = unknown, \n" +
            "f1 = unknown")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ground_truth_path>")
        exit(1)

    logging.basicConfig(filename="log/monitor.log", level=logging.INFO)
    logger.info(f"Started monitor on interface {iface}")

    bind_layers(Ether, Elephant4, type=0x8822)
    bind_layers(Ether, Elephant6, type=0x8823)
    t = AsyncSniffer(iface=iface, prn=handle_pkt)
    t.start()
    real_hh_list = read_ground_truth(sys.argv[1])
    atexit.register(lambda: report_accuracy(real_hh_list))
    t.join()
