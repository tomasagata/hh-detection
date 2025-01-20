from scapy.all import sendp, get_if_list, rdpcap, Ether
import logging
import sys
logger = logging.getLogger(__name__)
totals = 0

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

def read_capture(capture_file):
    pkts =  rdpcap(capture_file)
    for p in pkts:
        logger.info(p)
    return pkts

def send_traffic(packets):
    iface = get_if()
    for p in packets:
        sendp(p, iface=iface)
    # logger.info("Sent %s packets in total", len(sent_pkts))

def error_handler(type, value, tb):
    logger.exception("Uncaught exception: {0}".format(str(value)))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python send.py <pcap_file>")
        exit(1)

    logging.basicConfig(filename='log/send.log', level=logging.INFO)
    sys.excepthook = error_handler

    logger.info("Starting send.py")
    pkts = read_capture(sys.argv[1])
    send_traffic(pkts)