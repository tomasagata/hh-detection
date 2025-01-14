/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* MACROS */
#define ENTRIES_PER_TABLE 2040
#define ENTRY_WIDTH 136

#define HP_INIT(num) register<bit<ENTRY_WIDTH>>(ENTRIES_PER_TABLE) hp##num

#define GET_ENTRY(num, seed) \
hash(meta.currentIndex, HashAlgorithm.crc32, (bit<32>)0, {meta.flowId, seed}, (bit<32>)ENTRIES_PER_TABLE);\
hp##num.read(meta.currentEntry, meta.currentIndex);

#define WRITE_ENTRY(num, entry) hp##num.write(meta.currentIndex, entry)

#define STAGE_N(num, seed) {\
meta.flowId = meta.carriedKey;\
GET_ENTRY(num, seed);\
meta.currentKey = meta.currentEntry[135:32];\
meta.currentCount = meta.currentEntry[31:0];\
if (meta.currentKey - meta.carriedKey == 0) {\
    meta.toWriteKey = meta.currentKey;\
    meta.toWriteCount = meta.currentCount + meta.carriedCount;\
    meta.carriedKey = 0;\
    meta.carriedCount = 0;\
} else {\
    if (meta.carriedCount > meta.currentCount) {\
        meta.toWriteKey = meta.carriedKey;\
        meta.toWriteCount = meta.carriedCount;\
\
        meta.carriedKey = meta.currentKey;\
        meta.carriedCount = meta.currentCount;\
    } else {\
        meta.toWriteKey = meta.currentKey;\
        meta.toWriteCount = meta.currentCount;\
    }\
}\
bit<136> temp = meta.toWriteKey ++ meta.toWriteCount;\
WRITE_ENTRY(num, temp);\
}

/* Initialize HP*/
HP_INIT(0);
HP_INIT(1);
HP_INIT(2);
HP_INIT(3);
HP_INIT(4);
HP_INIT(5);

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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<104>    flowId;

    bit<32>     currentIndex;
    bit<136>    currentEntry;

    bit<104>    currentKey;
    bit<32>     currentCount;

    bit<104>    carriedKey;
    bit<32>     carriedCount;

    bit<104>    toWriteKey;
    bit<32>     toWriteCount;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
    udp_t       udp; 
}

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_TCP = 8w6;
const bit<8> PROTO_UDP = 8w17;


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
	    transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4   : parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP   : parse_tcp;
            PROTO_UDP   : parse_udp;
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
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    
    table ip_forward {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            drop;
            forward;
        }
        default_action = drop;
        const entries = {
            1 : forward(2);
            2 : forward(1);
        }
    }
    
    apply {
        if (hdr.ipv4.isValid()) {    
            ip_forward.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action extract_flow_id () {
        meta.flowId[103:72] = hdr.ipv4.srcAddr;
        meta.flowId[71:40] = hdr.ipv4.dstAddr;
        meta.flowId[39:32] = hdr.ipv4.protocol;
        
        if(hdr.tcp.isValid()) {
            meta.flowId[31:16] = hdr.tcp.srcPort;
            meta.flowId[15:0] = hdr.tcp.dstPort;
        } else if(hdr.udp.isValid()) {
            meta.flowId[31:16] = hdr.udp.srcPort;
            meta.flowId[15:0] = hdr.udp.dstPort;
        } else {
            meta.flowId[31:16] = 0;
            meta.flowId[15:0] = 0;
        }
    }

    action stage1 () {
        meta.carriedKey = meta.flowId;
        meta.carriedCount = 0;

        GET_ENTRY(0, 104w00000000000000000000);

        meta.currentKey = meta.currentEntry[135:32];
        meta.currentCount = meta.currentEntry[31:0];

        // If the flowIds are the same
        if (meta.currentKey - meta.carriedKey == 0) {
            meta.toWriteKey = meta.currentKey;
            meta.toWriteCount = meta.currentCount + 1;

            meta.carriedKey = 0;
            meta.carriedCount = 0;
        } else {
            meta.toWriteKey = meta.carriedKey;
            meta.toWriteCount = 1;

            meta.carriedKey = meta.currentKey;
            meta.carriedCount = meta.currentCount;
        }

        bit<136> temp = meta.toWriteKey ++ meta.toWriteCount;
        WRITE_ENTRY(0, temp);
    }

    action hashpipe() {
        extract_flow_id();
        stage1();
        STAGE_N(1, 104w11111111111111111111);
        STAGE_N(2, 104w22222222222222222222);
        STAGE_N(3, 104w33333333333333333333);
        STAGE_N(4, 104w44444444444444444444);
        STAGE_N(5, 104w55555555555555555555);
    }

    apply {
        hashpipe();
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;