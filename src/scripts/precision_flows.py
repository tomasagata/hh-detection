from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import json
import sys

def decode_ipv4(ip_32):
    """
    32-bit integer to 
    dotted-decimal string
    """
    return f"{(ip_32 >> 24) & 0xFF}.{(ip_32 >> 16) & 0xFF}.{(ip_32 >> 8) & 0xFF}.{ip_32 & 0xFF}"

def parse_flow_ids(flow_id_src, flow_id_dst):
    src_str = decode_ipv4(flow_id_src)
    dst_str = decode_ipv4(flow_id_dst)

    return (src_str, dst_str)

def read_precision_flows(thrift_port=9090,
                         thrift_ip="localhost",
                         table_size=64):

    api = SimpleSwitchThriftAPI(
        thrift_port=thrift_port,
        thrift_ip=thrift_ip
    )
    detected_heavy_flows = {}

    for table_idx in [1, 2, 3]:
        flow_id_reg_src = f"MyEgress.flow_table_ids_{table_idx}_src"
        flow_id_reg_dst = f"MyEgress.flow_table_ids_{table_idx}_dst"
        flow_ctr_reg = f"MyEgress.flow_table_ctrs_{table_idx}"


        for i in range(table_size):
            flow_id_val_src = api.register_read(flow_id_reg_src, i)
            flow_id_val_dst = api.register_read(flow_id_reg_dst, i)
            flow_ctr_val = api.register_read(flow_ctr_reg, i)

            if flow_ctr_val == 0:
                continue
            
            id_tuple = parse_flow_ids(flow_id_val_src, flow_id_val_dst)

            if id_tuple not in detected_heavy_flows:
                detected_heavy_flows[id_tuple] = flow_ctr_val
            else:
                detected_heavy_flows[id_tuple] += flow_ctr_val

    return detected_heavy_flows

def report_accuracy(real_hh_list, detected_hh_list):
    print("Starting accuracy report...")
    fp = 0.0; fn = 0.0; tp = 0.0
    
    for detected_hh in detected_hh_list:
        if detected_hh in real_hh_list:
            tp += 1
        if detected_hh not in real_hh_list:
            fp += 1

    for real_hh in real_hh_list:
        if real_hh not in detected_hh_list:
            fn += 1
            print(f"Missing flow: {real_hh}")

    try:
        precision = tp/(tp+fp)
        recall = tp/(tp+fn)
        f1 = 2 * (precision * recall) / (precision + recall)
        print("Accuracy details: \n" +
            f"tp = {tp}, \n" +
            f"fp = {fp}, \n" +
            f"fn = {fn}, \n" +
            f"precision = {precision}, \n" +
            f"recall = {recall}, \n" +
            f"f1 = {f1}")
    except:
        print("Accuracy measurements incomplete (zero true positives found): \n" +
            f"tp = {tp}, \n" +
            f"fp = {fp}, \n" +
            f"fn = {fn}, \n" +
            "precision = unknown, \n" +
            "recall = unknown, \n" +
            "f1 = unknown")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 precision_flows.py <threshold> <k-flows>")
        exit(1)

    flows = read_precision_flows(
        thrift_port=9090,
        thrift_ip="localhost",
        table_size=int(sys.argv[2])
    )

    filter_flows = [k for k, v in flows.items() if v > int(sys.argv[1])]

    with open("run/gtruth.json", "r") as f:
        real_hh_list = json.load(f)
    
    real_hh_list = [tuple(i) for i in real_hh_list]
    report_accuracy(real_hh_list, filter_flows)
