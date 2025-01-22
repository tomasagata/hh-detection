#!/usr/bin/env bash

if [ $# -lt 3 ]; then
  echo "Usage: ${$0} PCAP_FILE THRESHOLD";
  exit 1;
fi

PCAP_FILE=$1
THRESHOLD=$2

echo "Generating ground truth..."
python3 src/scripts/gtruth.py $PCAP_FILE $THRESHOLD
echo "Done."

echo "Starting network..."
sudo python src/network.py $PCAP_FILE
echo "Done."