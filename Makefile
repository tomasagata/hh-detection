test:
	cd src && sudo python network.py ../data/test.pcap

real:
	cd src && sudo python network.py ../data/dataset.pcap	

clean:
	rm -rf src/log src/pcap src/topology.json src/p4/*.json src/p4/*.p4i