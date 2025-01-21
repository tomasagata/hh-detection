from scapy.all import sniff, get_if_list, bind_layers
from scapy.all import Packet
from scapy.all import Ether
from scapy.fields import *
import logging

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
hh_list = []

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

    if packet_info not in hh_list:
        hh_list.append(packet_info)
        logger.info("New heavy hitter flow: %s", packet_info)
    
    pkt.show2()


if __name__ == '__main__':
    logging.basicConfig(filename="log/monitor.log", level=logging.INFO)
    logger.info("Started monitor on interface %s", iface)

    bind_layers(Ether, Elephant4, type=0x8822)
    bind_layers(Ether, Elephant6, type=0x8823)
    sniff(iface=iface, prn=handle_pkt)