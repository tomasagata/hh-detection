__usage="
Usage: $0 top_k_flows pcap_file"

TOP_K=$1
PCAP_FILE=$2

if [ -z $TOP_K ] || [ -z $PCAP_FILE ]; then
  echo "ERROR: Missing arguments."
  echo "$__usage"
  exit 1
fi

echo "Generating ground truth..."
python3 src/scripts/gtruth.py $PCAP_FILE --top-k $TOP_K --no-ipv6 --identifier 2
ret=$?
echo "Done."

if [ $ret -ne 0 ]; then
  echo "ERROR: Failed generating ground truth."
  exit 1
fi

echo "Starting network..."
sudo python src/network.py detection $PCAP_FILE
echo "Done."

