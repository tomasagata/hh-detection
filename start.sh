#!/usr/bin/env bash

__usage="
Usage: $0 [-t pkts | -k flows] -p file

Options:
  -p, --pcap <file>            Specify the packet capture file for the test.
  -t, --threshold <packets>    Specify the packet threshold to start considering as a heavy hitter.
  -k, --top-k <flows>          Specify the amount of flows to consider as heavy hitters.
  -h, --help                   Print this usage and exit.

"

while [[ $# -gt 0 ]]; do
  case $1 in
    -p|--pcap-file)
      PCAP_FILE="$2"
      shift # past argument
      shift # past value
      ;;
    -t|--threshold)
      THRESHOLD="$2"
      shift # past argument
      shift # past value
      ;;
    -k|--top-k)
      TOP_K="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      HELP=YES
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      echo "Unknown argument $1"
      exit 1
      ;;
  esac
done

if [ -n "$HELP" ]; then
  echo "$__usage"
  exit 0
fi

if [ -z "$PCAP_FILE" ]; then
  echo "ERROR: Missing packet capture file."
  exit 1
fi

if [ -z "$TOP_K" ] && [ -z "$THRESHOLD" ]; then
  echo "ERROR: Missing --top-k or --threshold flag."
  exit 1
fi

if [ -n "$TOP_K" ] && [ -n "$THRESHOLD" ]; then
  echo "ERROR: --top-k and --threshold flags are mutually exclusive."
  exit 1
fi

echo "Generating ground truth..."
python3 src/scripts/gtruth.py $PCAP_FILE $THRESHOLD
echo "Done."

echo "Starting network..."
sudo python src/network.py $PCAP_FILE
echo "Done."