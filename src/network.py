from p4utils.mininetlib.network_API import NetworkAPI
import sys

if len(sys.argv) < 2:
  print("Usage: sudo python network.py <pcap_file>")
  exit(1)

net = NetworkAPI()

# Network general options
net.setLogLevel('debug')


# Network definition
net.addP4Switch('s1', cli_input='s1-commands.txt')
net.setP4Source('s1','p4/l2_basic_forwarding.p4')
# net.addSwitch('s1', failMode='standalone')

net.addHost('h1')
net.addHost('h2')

net.addLink('s1', 'h1', port1=0, port2=0)
net.addLink('s1', 'h2', port1=1, port2=0)

net.setIntfMac('h1', 's1', '00:10:0a:00:00:11')
net.setIntfMac('h2', 's1', '00:10:0a:00:00:22')

# net.setIntfIp('h1', 's1', '10.0.0.1/24')
# net.setIntfIp('h2', 's1', '10.0.0.2/24')

##################
#
# h1 -- s1 -- h2
#
##################
# ** IPs **
#
# h1: 10.0.0.1/24
# h2: 10.0.0.2/24
##################
# ** MACs **
#
# h1: 00:10:0a:00:00:11
# h2: 00:10:0a:00:00:22
##################


# Start tests
net.addTask('h1', 'tcpdump -i h1-eth0 -w pcap/h1-eth0.pcap')
net.addTask('h2', 'tcpdump -i h2-eth0 -w pcap/h2-eth0.pcap')
net.addTask('h2', f"python scripts/receive.py")
net.addTask('h1', f"python scripts/send.py {sys.argv[1]}", start=1)


# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()
net.startNetwork()
