from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw
import sys, socket, random, os, subprocess, re

def get_hostname():
    ifconfig_output=(subprocess.check_output('ifconfig')).decode()
    hostname=re.search(r"-eth0", ifconfig_output)
    return((str(hostname))[47:-2])

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


# Most important function
def send_random_traffic(dst_host, num_packets):
    if dst_host != "h3" and dst_host != "h4":
        print("host must be h3 or h4")
        sys.exit(1)
    elif dst_host == "h3":
        dst_ip = '10.0.0.3'
        dst_mac = '00:10:0a:00:00:33'
    elif dst_host == "h4":
        dst_ip = '10.0.0.4'
        dst_mac = '00:10:0a:00:00:44'
    

    dst_addr = socket.gethostbyname(dst_ip)
    total_pkts = 0
    random_port = random.randint(1024,65000)
    iface = get_if()
    

    # For this exercise the destination mac address is not important. Just ignore the value we use.
    p = Ether(dst=dst_mac, src=get_if_hwaddr(iface)) / IP(dst=dst_addr)
    p = p / TCP(dport=random_port)
    for i in range(num_packets):
        sendp(p, iface = iface)
        total_pkts += 1
    with open("log/file.txt", "w") as f:
        f.write("Created using write mode.")
    print("Sent %s packets in total" % total_pkts)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python send.py <h3 or h4> <num_packets>")
        sys.exit(1)
    else:
        dst_name = sys.argv[1]
        num_packets = int(sys.argv[2])
        send_random_traffic(dst_name, num_packets)