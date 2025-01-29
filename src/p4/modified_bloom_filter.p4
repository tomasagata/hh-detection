/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define BLOOM_FILTER_ENTRIES 192
#define BLOOM_FILTER_BIT_WIDTH 32
#define PACKET_THRESHOLD 10

#define HASH_IPV4_TCP(num, algorithm) \
    hash(meta.output_hash_##num, HashAlgorithm.algorithm, (bit<16>)0, \
        {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol, (bit<16>)num}, (bit<32>)BLOOM_FILTER_ENTRIES-1); \

#define HASH_IPV4_UDP(num, algorithm) \
    hash(meta.output_hash_##num, HashAlgorithm.algorithm, (bit<16>)0, \
        {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol, (bit<16>)num}, (bit<32>)BLOOM_FILTER_ENTRIES-1); \

#define HASH_IPV6_TCP(num, algorithm) \
    hash(meta.output_hash_##num, HashAlgorithm.algorithm, (bit<16>)0, \
        {hdr.ipv6.srcAddr, hdr.ipv6.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv6.nextHeader, (bit<16>)num}, (bit<32>)BLOOM_FILTER_ENTRIES-1); \

#define HASH_IPV6_UDP(num, algorithm) \
    hash(meta.output_hash_##num, HashAlgorithm.algorithm, (bit<16>)0, \
        {hdr.ipv6.srcAddr, hdr.ipv6.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv6.nextHeader, (bit<16>)num}, (bit<32>)BLOOM_FILTER_ENTRIES-1); \


/*changes*/
#define isClone() standard_metadata.instance_type == 1
#define CLONE_SESS_ID 500

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_ELEPHANTV4 = 0x8822;
const bit<16> ETHERTYPE_ELEPHANTV6 = 0x8823;

const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*changes*/
typedef bit<128> ip6Addr_t;

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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/*changes*/
header elephantv4_t {
    bit<1>    flow_addition;  // +
    bit<1>    flow_eviction;  // +
    bit<6>    reserved;       // = 1
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<8>    protocol;
    bit<16>   srcPort;
    bit<16>   dstPort;
}

header elephantv6_t {
    bit<1>    flow_addition;  // +
    bit<1>    flow_eviction;  // +
    bit<6>    reserved;       // = 1
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
    bit<8>    protocol;
    bit<16>   srcPort;
    bit<16>   dstPort;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

/*done*/

struct metadata {
    bit<32> output_hash_1;
    bit<32> output_hash_2;
    bit<32> output_hash_3;
    bit<32> counter_one;
    bit<32> counter_two;
    bit<32> counter_three;
}


/*changes in part of headers*/
struct headers {
    ethernet_t   ethernet;
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

/******changes in parser, changing the names of states to be unified,
adding the IPv6, changing the constant names to be unifed, add UDP******/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){

            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol){
            IPPROTO_UDP  : parse_udp;
            IPPROTO_TCP  : parse_tcp;
            default: accept;
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

/******* changes to ingress, delete the ipv4 forward action, ipv4_lpm table
and adding forward action, port table to be suitable for s1 commands
in apply, adding udp condition, changing the action from drop to clone and
changing the name of the table used, adding ipv6 action inside apply and
 ipv6 hash algorithm *******/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action hash_4_tcp(){
        HASH_IPV4_TCP(1, crc32);
        HASH_IPV4_TCP(2, crc32);
        HASH_IPV4_TCP(3, crc32);
    }

    action hash_4_udp(){
        HASH_IPV4_UDP(1, crc32);
        HASH_IPV4_UDP(2, crc32);
        HASH_IPV4_UDP(3, crc32);
    }

    action hash_6_tcp(){
       HASH_IPV6_TCP(1, crc32);
       HASH_IPV6_TCP(2, crc32);
       HASH_IPV6_TCP(3, crc32);        
    }

    action hash_6_udp(){
        HASH_IPV6_UDP(1, crc32);
        HASH_IPV6_UDP(2, crc32);
        HASH_IPV6_UDP(3, crc32);
    }

    action update_bloom_filter(){
        // Read counters
        bloom_filter.read(meta.counter_one, meta.output_hash_1);
        bloom_filter.read(meta.counter_two, meta.output_hash_2);
        bloom_filter.read(meta.counter_three, meta.output_hash_3);

        // Update them
        meta.counter_one = meta.counter_one + 1;
        meta.counter_two = meta.counter_two + 1;
        meta.counter_three = meta.counter_three + 1;

        // Write them back
        bloom_filter.write(meta.output_hash_1, meta.counter_one);
        bloom_filter.write(meta.output_hash_2, meta.counter_two);
        bloom_filter.write(meta.output_hash_3, meta.counter_three);
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

        if (hdr.tcp.isValid()){
            hash_4_tcp();
        } else {
            hash_4_udp();
        }
        update_bloom_filter();

        // Only if IPv4, the rule is applied. Other packets will not be forwarded.
        if (meta.counter_one > PACKET_THRESHOLD &&
            meta.counter_two > PACKET_THRESHOLD && 
            meta.counter_three > PACKET_THRESHOLD) {
            // Heavy hitter detected. Clone the packet and send it to the egress pipeline.
            clone(CloneType.I2E, CLONE_SESS_ID);
        }
        
    } else if ((hdr.ipv6.isValid()) && 
        (hdr.tcp.isValid() || hdr.udp.isValid())){

        if (hdr.tcp.isValid()){
            hash_6_tcp();
        } else {
            hash_6_udp();
        }
        update_bloom_filter();

        // Only if IPv6, the rule is applied. Other packets will not be forwarded.
        if (meta.counter_one > PACKET_THRESHOLD &&
            meta.counter_two > PACKET_THRESHOLD && 
            meta.counter_three > PACKET_THRESHOLD) {
            // Heavy hitter detected. Clone the packet and send it to the egress pipeline.
            clone(CloneType.I2E, CLONE_SESS_ID);
        }
    }
}

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

/******* adding the elephant flow header to the cloned packet
copying*******/


control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (isClone()) {
            if (hdr.ipv4.isValid()) {
                hdr.elephantv4.setValid();
                hdr.elephantv4.flow_addition = (bit<1>)1;
                hdr.elephantv4.flow_eviction = (bit<1>)0;
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
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

/******* adding all headers, copying *******/

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