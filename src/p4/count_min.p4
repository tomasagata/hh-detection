/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 64
#define SKETCH_CELL_BIT_WIDTH 32
// 28 * 64 = 1792 bits
#define HH_THRESHOLD 10
#define CLONE_SESS_ID 500

#define SKETCH_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch##num

#define SKETCH_COUNT_4_TCP(num, algorithm) \
    hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<32>)0, \
        {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)SKETCH_BUCKET_LENGTH); \
    sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
    meta.value_sketch##num = meta.value_sketch##num +1; \
    log_msg("register = {}", {meta.value_sketch##num}); \
    sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

#define SKETCH_COUNT_4_UDP(num, algorithm) \
    hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<32>)0, \
        {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol}, (bit<32>)SKETCH_BUCKET_LENGTH); \
    sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
    meta.value_sketch##num = meta.value_sketch##num +1; \
    log_msg("register = {}", {meta.value_sketch##num}); \
    sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

#define SKETCH_COUNT_6_TCP(num, algorithm) \
    hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<32>)0, \
        {hdr.ipv6.srcAddr, hdr.ipv6.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv6.nextHeader}, (bit<32>)SKETCH_BUCKET_LENGTH); \
    sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
    meta.value_sketch##num = meta.value_sketch##num +1; \
    log_msg("register = {}", {meta.value_sketch##num}); \
    sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

#define SKETCH_COUNT_6_UDP(num, algorithm) \
    hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<32>)0, \
        {hdr.ipv6.srcAddr, hdr.ipv6.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv6.nextHeader}, (bit<32>)SKETCH_BUCKET_LENGTH); \
    sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
    meta.value_sketch##num = meta.value_sketch##num +1; \
    log_msg("register = {}", {meta.value_sketch##num}); \
    sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

#define isClone() standard_metadata.instance_type == 1

const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_ELEPHANTV4 = 0x8822;
const bit<16> ETHERTYPE_ELEPHANTV6 = 0x8823;

const bit<8>  IPPROTO_ICMP  = 0x01;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header elephantv4_t {
    bit<1>    flow_addition;  // +
    bit<1>    flow_eviction;  // +
    bit<6>    reserved;       // = 1
    ip4Addr_t srcAddr;        // 4
    ip4Addr_t dstAddr;        // 4
    bit<8>    protocol;       // 1
    bit<16>   srcPort;        // 2
    bit<16>   dstPort;        // 2
}

header elephantv6_t {
    bit<1>    flow_addition;
    bit<1>    flow_eviction;
    bit<6>    reserved;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
    bit<8>    protocol;
    bit<16>   srcPort;
    bit<16>   dstPort;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLength;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
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
// Probably accomodate the variable OPTIONS header for a complete implementation
// otherwise it will appear as part of the payload of the program

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

    bit<SKETCH_CELL_BIT_WIDTH> value_sketch0;
    bit<SKETCH_CELL_BIT_WIDTH> value_sketch1;
    bit<SKETCH_CELL_BIT_WIDTH> value_sketch2;
    bit<SKETCH_CELL_BIT_WIDTH> value_sketch3;
    bit<SKETCH_CELL_BIT_WIDTH> value_sketch4;
    bit<SKETCH_CELL_BIT_WIDTH> value_sketch5;
    bit<SKETCH_CELL_BIT_WIDTH> value_sketch6;
    bit<SKETCH_CELL_BIT_WIDTH> value_sketch7;
}


struct headers {
    ethernet_t     ethernet;
    elephantv4_t   elephantv4;
    elephantv6_t   elephantv6;
    ipv4_t         ipv4;
    ipv6_t         ipv6;
    udp_t          udp;
    tcp_t          tcp;
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
            ETHERTYPE_IPV6: parse_ipv6;
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

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader) {
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

    action sketch_count_4_tcp(){
        SKETCH_COUNT_4_TCP(0, crc32);
        SKETCH_COUNT_4_TCP(1, crc16);
        SKETCH_COUNT_4_TCP(2, xor16);
        //SKETCH_COUNT_4_TCP(3, crc32_custom);
        //SKETCH_COUNT_4_TCP(4, crc32_custom);
    }

    action sketch_count_4_udp(){
        SKETCH_COUNT_4_UDP(0, crc32);
        SKETCH_COUNT_4_UDP(1, crc16);
        SKETCH_COUNT_4_UDP(2, xor16);
        //SKETCH_COUNT_4_UDP(3, crc32_custom);
        //SKETCH_COUNT_4_UDP(4, crc32_custom);
    }

    action sketch_count_6_tcp(){
        SKETCH_COUNT_6_TCP(0, crc32);
        SKETCH_COUNT_6_TCP(1, crc16);
        SKETCH_COUNT_6_TCP(2, xor16);
        //SKETCH_COUNT_6_TCP(3, crc32_custom);
        //SKETCH_COUNT_6_TCP(4, crc32_custom);
    }

    action sketch_count_6_udp(){
        SKETCH_COUNT_6_UDP(0, crc32);
        SKETCH_COUNT_6_UDP(1, crc16);
        SKETCH_COUNT_6_UDP(2, xor16);
        //SKETCH_COUNT_6_UDP(3, crc32_custom);
        //SKETCH_COUNT_6_UDP(4, crc32_custom);
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
        port.apply();

        if ((hdr.ipv4.isValid()) && 
            (hdr.tcp.isValid() || hdr.udp.isValid())){

            log_msg("srcAddr = {}", {hdr.ipv4.srcAddr});
            log_msg("dstAddr = {}", {hdr.ipv4.dstAddr});
            log_msg("proto = {}", {hdr.ipv4.protocol});
            if (hdr.tcp.isValid()){
                sketch_count_4_tcp();
                log_msg("srcPort = {}", {hdr.tcp.srcPort});
                log_msg("dstPort = {}", {hdr.tcp.dstPort});
            } else {
                sketch_count_4_udp();
                log_msg("srcPort = {}", {hdr.udp.srcPort});
                log_msg("dstPort = {}", {hdr.udp.dstPort});
            }


            if (meta.value_sketch0 > HH_THRESHOLD && 
                meta.value_sketch1 > HH_THRESHOLD && 
                meta.value_sketch2 > HH_THRESHOLD) {

                // Heavy hitter detected. Clone the packet 
                // and send it to the egress pipeline
                clone(CloneType.I2E, CLONE_SESS_ID);
            }
        } else if ((hdr.ipv6.isValid()) && 
            (hdr.tcp.isValid() || hdr.udp.isValid())){
            
            log_msg("srcAddr = {}", {hdr.ipv6.srcAddr});
            log_msg("dstAddr = {}", {hdr.ipv6.dstAddr});
            log_msg("proto = {}", {hdr.ipv6.nextHeader});

            if (hdr.tcp.isValid()){
                sketch_count_6_tcp();
                log_msg("srcPort = {}", {hdr.tcp.srcPort});
                log_msg("dstPort = {}", {hdr.tcp.dstPort});
            } else {
                sketch_count_6_udp();
                log_msg("srcPort = {}", {hdr.udp.srcPort});
                log_msg("dstPort = {}", {hdr.udp.dstPort});
            }

            if (meta.value_sketch0 > HH_THRESHOLD && 
                meta.value_sketch1 > HH_THRESHOLD && 
                meta.value_sketch2 > HH_THRESHOLD) {

                // Heavy hitter detected. Clone the packet 
                // and send it to the egress pipeline
                clone(CloneType.I2E, CLONE_SESS_ID);
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (isClone()) {
            if (hdr.ipv4.isValid()) {
                hdr.elephantv4.setValid();
                hdr.elephantv4.flow_addition = (bit<1>)1;
                hdr.elephantv4.flow_eviction = (bit<1>)0;
                hdr.elephantv4.reserved = (bit<6>)0;
                hdr.elephantv4.srcAddr = hdr.ipv4.srcAddr;
                hdr.elephantv4.dstAddr = hdr.ipv4.dstAddr;
                hdr.elephantv4.protocol = hdr.ipv4.protocol;
                hdr.ipv4.setInvalid();
                if (hdr.udp.isValid()) {
                    hdr.elephantv4.srcPort = hdr.udp.srcPort;
                    hdr.elephantv4.dstPort = hdr.udp.dstPort;
                    hdr.udp.setInvalid();
                } else {
                    hdr.elephantv4.srcPort = hdr.tcp.srcPort;
                    hdr.elephantv4.dstPort = hdr.tcp.dstPort;
                    hdr.tcp.setInvalid();
                }
                hdr.ethernet.etherType = ETHERTYPE_ELEPHANTV4;
            } else if (hdr.ipv6.isValid()) {
                hdr.elephantv6.setValid();
                hdr.elephantv6.flow_addition = (bit<1>)1;
                hdr.elephantv6.flow_eviction = (bit<1>)0;
                hdr.elephantv6.reserved = (bit<6>)0;
                hdr.elephantv6.srcAddr = hdr.ipv6.srcAddr;
                hdr.elephantv6.dstAddr = hdr.ipv6.dstAddr;
                hdr.elephantv6.protocol = hdr.ipv6.nextHeader;
                hdr.ipv6.setInvalid();
                if (hdr.udp.isValid()) {
                    hdr.elephantv6.srcPort = hdr.udp.srcPort;
                    hdr.elephantv6.dstPort = hdr.udp.dstPort;
                    hdr.udp.setInvalid();
                } else {
                    hdr.elephantv6.srcPort = hdr.tcp.srcPort;
                    hdr.elephantv6.dstPort = hdr.tcp.dstPort;
                    hdr.tcp.setInvalid();
                }
                hdr.ethernet.etherType = ETHERTYPE_ELEPHANTV6;
            }
        }
    }
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
        packet.emit(hdr.elephantv4);
        packet.emit(hdr.elephantv6);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
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