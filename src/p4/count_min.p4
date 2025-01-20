/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 28
#define SKETCH_CELL_BIT_WIDTH 64
// 28 * 64 = 1792 bits

#define SKETCH_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch##num

#define SKETCH_COUNT(num, algorithm) \
    hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, \
        {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)SKETCH_BUCKET_LENGTH); \
    sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
    meta.value_sketch##num = meta.value_sketch##num +1; \
    sketch##num.write(meta.index_sketch##num, meta.value_sketch##num);

const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8>  IPPROTO_ICMP  = 0x01;
const bit<8>  IPPROTO_IPv4  = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

struct metadata {
    bit<32> index_sketch0;
    bit<32> index_sketch1;
    bit<32> index_sketch2;
    bit<32> index_sketch3;
    bit<32> index_sketch4;
    bit<32> index_sketch5;
    bit<32> index_sketch6;
    bit<32> index_sketch7;

    bit<64> value_sketch0;
    bit<64> value_sketch1;
    bit<64> value_sketch2;
    bit<64> value_sketch3;
    bit<64> value_sketch4;
    bit<64> value_sketch5;
    bit<64> value_sketch6;
    bit<64> value_sketch7;
}


struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    tcp_t        tcp;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP  : parse_udp;
            IPPROTO_TCP  : parse_tcp;
            default      : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
     
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept; 
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    SKETCH_REGISTER(0);
    SKETCH_REGISTER(1);
    SKETCH_REGISTER(2);
    //SKETCH_REGISTER(3);
    //SKETCH_REGISTER(4);

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action sketch_count(){
        SKETCH_COUNT(0, crc32_custom);
        SKETCH_COUNT(1, crc32_custom);
        SKETCH_COUNT(2, crc32_custom);
        //SKETCH_COUNT(3, crc32_custom);
        //SKETCH_COUNT(4, crc32_custom);
    }

    action forward(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    table port {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }

    apply {

        //apply sketch
        if (hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid())){
            sketch_count();
        }

        port.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;