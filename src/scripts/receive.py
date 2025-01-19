from scapy.all import sniff, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, TCP, UDP
import logging
import atexit
import sys
logger = logging.getLogger(__name__)


def get_if():
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


totals = {}
iface = get_if()


def handle_pkt(pkt):
    logger.debug("Received packet!")
    if not is_valid(pkt):
        return

    logger.debug("pkt: %s", pkt)

    if TCP in pkt:
        handle_tcp_traffic(pkt)
    elif UDP in pkt:
        handle_udp_traffic(pkt)
    elif IP in pkt:
        handle_ip_traffic(pkt)
    elif Ether in pkt:
        handle_raw_traffic(pkt)

#    print("Received from %s total: %s" % (id_tup, totals[id_tup]))
 
def handle_tcp_traffic(packet):
    logger.debug("Packet has TCP header")
    eth_t = packet[Ether].type
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    id_tup = (eth_t, src_ip, dst_ip, proto, sport, dport)
    add_tuple(id_tup)

def handle_udp_traffic(packet):
    logger.debug("Packet has UDP header")
    eth_t = packet[Ether].type
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    id_tup = (eth_t, src_ip, dst_ip, proto, sport, dport)
    add_tuple(id_tup)

def handle_ip_traffic(packet):
    logger.debug("Packet has IP header")
    eth_t = packet[Ether].type
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    id_tup = (eth_t, src_ip, dst_ip, proto, None, None)
    add_tuple(id_tup)

def handle_raw_traffic(packet):
    logger.debug("Packet has Raw header")
    eth_t = packet[Ether].type
    id_tup = (eth_t, None, None, None, None, None)
    add_tuple(id_tup)

def add_tuple(id_tup):
    if id_tup not in totals:
        totals[id_tup] = 0
        logger.info("New tuple found: %s", id_tup)
        
    totals[id_tup] += 1

def is_valid(pkt):
    # filter packets that are sent from this interface. 
    # This is done to just focus on the receiving ones.
    # 
    # Some people had problems with this line since they 
    # set the src mac address to be the same than the destination, thus
    # all packets got filtered here.
    if get_if_hwaddr(iface) == pkt[Ether].src:
        logger.debug("Packet is not valid")
        return False
    logger.debug("Packet is valid")
    return True

def exit_handler():
    sorted_totals = {}
    for key in sorted(totals, key=totals.get, reverse=True):
        sorted_totals[key] = totals[key]

    summary_str = "Flows summaries: \n"
    for tuple, hits in sorted_totals.items():
        summary_str += '    {} {}\n'.format(tuple, hits)
    logger.info(summary_str)

def error_handler(type, value, tb):
    logger.exception("Uncaught exception: {0}".format(str(value)))

if __name__ == '__main__':
    logging.basicConfig(filename='log/receive.log', level=logging.INFO)
    atexit.register(exit_handler)
    sys.excepthook = error_handler

    logger.info("Starting receive.py on interface {0}".format(iface))
    sniff(iface = iface,
        prn = handle_pkt)