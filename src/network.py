from p4utils.mininetlib.network_API import NetworkAPI
import sys

if len(sys.argv) < 2:
  print("Usage: sudo python network.py <type of test> <pcap_file>")
  exit(1)

net = NetworkAPI()

# Network general options
net.setLogLevel('debug')


# Network definition
net.addP4Switch('s1', cli_input='src/s1-commands.txt')
# net.setP4Source('s1','p4/l2_basic_forwarding.p4')
net.setP4Source('s1','src/p4/modified_precision.p4')
# net.addSwitch('s1', failMode='standalone')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')

net.addLink('s1', 'h1', port1=0, port2=0)
net.addLink('s1', 'h2', port1=1, port2=0)
net.addLink('s1', 'h3', port1=2, port2=0)

net.setIntfMac('h1', 's1', '00:10:0a:00:00:11')
net.setIntfMac('h2', 's1', '00:10:0a:00:00:22')
net.setIntfMac('h3', 's1', '00:10:0a:00:00:33')

if (sys.argv[1] != 'detection'):
  net.setIntfIp('h1', 's1', '10.0.0.1/24')
  net.setIntfIp('h2', 's1', '10.0.0.2/24')

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
if sys.argv[1] == 'detection':
  net.addTask('h3', f"python src/scripts/monitor.py run/gtruth.json")
  net.addTask('h2', f"python src/scripts/receive.py")
  net.addTask('h1', f"python src/scripts/send.py {sys.argv[2]}", start=1)
elif sys.argv[1] == 'throughput':
  net.addTask('h2', f"iperf3 -s")
  net.addTask('h1', f"iperf3 -c 10.0.0.2 --logfile log/throughput.log", start=1)
elif sys.argv[1] == 'jitter':
  net.addTask('h2', f"iperf3 -s")
  net.addTask('h1', f"iperf3 -c 10.0.0.2 -u --logfile log/jitter.log", start=1)
# elif sys.argv[1] == 'delay':
#   net.addTask('h2', f"owampd -a O -f -R run")
#   net.addTask('h1', f"owping 10.0.0.2 >>log/delay.log 2>&1", start=1)
else:
  print(f"ERROR: Unknown subcommand {sys.argv[1]}")
  exit(1)

net.addTask('h1', 'tcpdump -i h1-eth0 -w pcap/h1-eth0.pcap')
net.addTask('h2', 'tcpdump -i h2-eth0 -w pcap/h2-eth0.pcap')
net.addTask('h3', 'tcpdump -i h3-eth0 -w pcap/h3-eth0.pcap')

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()
net.startNetwork()
