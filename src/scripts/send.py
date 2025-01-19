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

def read_capture():
    return rdpcap("../data/dataset.pcap")

def send_traffic(packets):
    iface = get_if()
    count = 0

    for pkt in packets:
        pkt = Ether() / pkt
        sendp(pkt, iface=iface)
        logger.info("Packet sent: \n%s", pkt)
        count+=1
    logger.info("Sent %s packets in total", count)

def error_handler(type, value, tb):
    logger.exception("Uncaught exception: {0}".format(str(value)))

if __name__ == '__main__':
    logging.basicConfig(filename='log/send.log', level=logging.INFO)
    sys.excepthook = error_handler

    logger.info("Starting send.py")
    pkts = read_capture()
    send_traffic(pkts)