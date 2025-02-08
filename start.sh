#!/usr/bin/env bash

__usage="
Usage: $0 [-h] test_type [(-t THRESHOLD | -k TOP_K) pcap_file]

Test types:
  detection                 : Reads <pcap_file> and sends out the packets 
                                  to the other host. Measures true 
                                  positives, false positives, false 
                                  negatives, recall, precision and 
                                  f1 score.
  throughput                : Uses iperf3 to test the throughput of the 
                                  network.
  jitter                    : Uses iperf3 to test the jitter of the network.

Positional arguments:
  test_type                 : Specify the type of test to perform. See \"Test types\" section for all possibilities.
  pcap_file                 : Specify the packet capture file for the test.

Options:
  -t, --threshold <packets> : Specify the packet threshold to start considering a flow as a heavy hitter.
  -k, --top-k <flows>       : Specify the amount of flows to consider as heavy hitters.
  -h, --help                : Print this usage and exit.

"

POSITIONAL_ARGS=()

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
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # Restore positional args

if [ -n "$HELP" ]; then
  echo "$__usage"
  exit 0
fi

case $1 in
  "detection")
    PCAP_FILE=$2

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

    if [ -n "$TOP_K" ]; then
      echo "Generating ground truth..."
      python3 src/scripts/gtruth.py $PCAP_FILE --top-k $TOP_K
      echo "Done."
    fi

    if [ -n "$THRESHOLD" ]; then
      echo "Generating ground truth..."
      python3 src/scripts/gtruth.py $PCAP_FILE --threshold $THRESHOLD
      ret=$?
      echo "Done."
    fi

    if [ $ret -ne 0 ]; then
      echo "ERROR: Failed generating ground truth."
      exit 1
    fi

    echo "Starting network..."
    sudo python src/network.py detection $PCAP_FILE
    echo "Done."
  ;;

  "throughput")
    echo "Starting network..."
    sudo python src/network.py throughput
    echo "Done."
  ;;

  "jitter")
    echo "Starting network..."
    sudo python src/network.py jitter
    echo "Done."
  ;;

  # "delay")
  #   echo "Starting network..."
  #   sudo python src/network.py delay
  #   echo "Done."
  # ;;

esac