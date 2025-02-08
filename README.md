# hh-detection

## Overview

This project focuses on heavy hitter detection in network traffic using P4 programmable switches. The goal is to identify and analyze heavy hitter flows, which are responsible for a significant portion of the traffic in a network.

## Features

- **Topology Configuration**: Setup and configure network topology including host IPs.
- **Traffic Generation**: Generate real network traffic using datasets like CAIDA.
- **P4 Switch Implementation**: Create and configure P4 switches for heavy hitter detection.
- **Control Plane Configuration**: Manage and configure the control plane for the network.
- **Measurement Implementation**: Measure precision, recall, F1 score, false positive rate, and false negative rate.
- **Algorithm Analysis**: Analyze and implement various heavy hitter detection algorithms such as HashPipe, PRECISION, and Count-Min Sketch.
- **IPv6 Traffic Support**: Enable and analyze IPv6 traffic in the model.
- **Performance Analysis**: Conduct bandwidth, throughput, and latency/delay analysis.


## Limitations

- **Scalability**: The current implementation may not scale well with extremely large datasets or very high-speed networks.
- **Accuracy**: The accuracy of heavy hitter detection can vary depending on the algorithm and parameters used.
- **Resource Intensive**: Running the P4 switches and generating traffic can be resource-intensive and may require powerful hardware.
- **Dataset Dependency**: The performance and accuracy of the detection algorithms are highly dependent on the quality and characteristics of the dataset used.
- **IPv6 Support**: While IPv6 traffic is supported, the implementation and analysis are primarily focused on IPv4 traffic.
- **Control Plane Overhead**: Managing and configuring the control plane can introduce additional overhead and complexity.
- **Limited Algorithm Implementation**: Only a few heavy hitter detection algorithms are implemented; other algorithms may provide better performance or accuracy.

## Getting Started

### Prerequisites

- P4 development environment
- Mininet
- Python 3.x
- Any traffic dataset in pcap/pcapng format (We used CAIDA dataset)

### Installation

1. Clone the repository:
```sh
git clone https://github.com/tomasagata/hh-detection.git
cd hh-detection
```

2. Install dependencies:
```sh
sudo apt-get install mininet
sudo apt-get install python3
```

3. Download the CAIDA dataset and place it in the `data` directory.

### Usage

1. Change the P4 file that will be used in the BMv2 switch:
```sh
nano src/network.py
```

2. Start the network and run tests:
```sh
./start.sh <test_type> -t <threshold> <pcap_file>
```

### Test Types

- `detection`: Detect heavy hitter flows and measure accuracy.
- `throughput`: Test network throughput using iperf3.
- `jitter`: Test network jitter using iperf3.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any questions or inquiries, please contact Tomas Agata and Muhammad Mansour.
