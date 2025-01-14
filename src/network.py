from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('debug')


# Network definition
net.addP4Switch('s1', cli_input='s1-commands.txt')
net.setP4Source('s1','p4/l2_basic_forwarding.p4')
# net.addSwitch('s1', failMode='standalone')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')
net.addHost('h4')

net.addLink('s1', 'h1', port1=0, port2=0)
net.addLink('s1', 'h2', port1=1, port2=0)
net.addLink('s1', 'h3', port1=2, port2=0)
net.addLink('s1', 'h4', port1=3, port2=0)

net.setIntfMac('h1', 's1', '00:10:0a:00:00:11')
net.setIntfMac('h2', 's1', '00:10:0a:00:00:22')
net.setIntfMac('h3', 's1', '00:10:0a:00:00:33')
net.setIntfMac('h4', 's1', '00:10:0a:00:00:44')

net.setIntfIp('h1', 's1', '10.0.0.1/24')
net.setIntfIp('h2', 's1', '10.0.0.2/24')
net.setIntfIp('h3', 's1', '10.0.0.3/24')
net.setIntfIp('h4', 's1', '10.0.0.4/24')

# h1          h3
#     \    /
#       s1
#     /    \
# h2          h4

# Traffic flows
# (h1 -> h3) UDP.  1st heaviest
# (h1 -> h4) HTTP. 2nd heaviest
# (h2 -> h3) HTTP. 3rd heaviest
# (h2 -> h4) UDP.  4rd heaviest
# (For now this works)
# (Analyze the possibility of using a dataset of traffic)

# IPs
# h1: 10.0.0.1/24
# h2: 10.0.0.2/24
# h3: 10.0.0.3/24
# h4: 10.0.0.4/24
# net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:11')


# Assignment strategy
# net.l2()


# Adding receiving tasks
net.addTask('h3', 'python scripts/receive.py')
net.addTask('h4', 'python scripts/receive.py')
net.addTask('h1', 'python scripts/send.py h3 10', start=2)
net.addTask('h2', 'python scripts/send.py h4 10', start=2)

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()
net.startNetwork()
