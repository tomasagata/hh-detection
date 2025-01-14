/*********************************************************************
* Copyright 2022 INTRIG
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
**********************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

const bit<16> GTP_UDP_PORT     = 2152;
const bit<16> UDP_PORT_VXLAN   = 4789;

const bit<32> MAC_LEARN_RECEIVER = 1;
const bit<32> ARP_LEARN_RECEIVER = 1025;

/**** pre-defined parameters for HH detection ***/
const bit<16>  IPG_INIT  = 1600;  // for 5 Mbps HH threhsold
const bit<16>  CONST     = 20;    // contant rate linear increase of weighted IPG 
const bit<16>  TAU_TH    = 300;   // tau threshold to decide HHs 
const bit<16>  WRAPTIME  = 4096;  // in microseconds
const  bit<5>  QID_LP    = 7;   
const  bit<5>  QID_HP    = 1; 
typedef bit<11>rSize;             // size of register 

typedef bit<9> port_t;
//const port_t port = 136;
//const port_t port = 129;
const port_t CPU_PORT = 255;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
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

header resubmit_h {
    PortId_t port_id; // 9 bits - uses 16 bit container
    bit<48>  _pad2;
}

/* Local metadata */
struct hash_metadata_t {
    bit<32>  flowId;
    bit<1>   IPGflag;
    bit<48>  TS;
    bit<16>  tauFlag;
    bit<8>   FlowIdFlag;
    bit<8>   IPGw_flag;
    bit<16>  TSlastComp;
    bit<16>  TSlast;
    bit<16>  Diff;
    bit<16>  IPGw;
    bit<16>  tau;
    bit<16>  IPGc;
    bit<16>  TSc;
    bit<16>  IPGcComp;
    bit<11>  mIndex;
    bit<16>  l4_sport;
    bit<16>  l4_dport;
    bit<8>   resubmit_type;
}

struct header_t {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    tcp_t        tcp;
}


struct ingress_metadata_t {
    hash_metadata_t hash_meta;
    resubmit_h resubmit_data;
}

struct egress_metadata_t {

}




/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
#if __TARGET_TOFINO__ == 2
       //pkt.advance(192);
       pkt.advance(PORT_METADATA_SIZE);
#else
       //pkt.advance(64);
       pkt.advance(PORT_METADATA_SIZE);
#endif
       transition accept;
     }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser SwitchIngressParser(
        packet_in packet,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

   state start {
        packet.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        packet.extract(ig_md.resubmit_data);
        transition parse_ethernet;
    }

    state parse_port_metadata {
        packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

   state parse_ethernet {
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
        ig_md.hash_meta.l4_sport = hdr.tcp.srcPort;
        ig_md.hash_meta.l4_dport = hdr.tcp.dstPort;
        transition accept;
    }
     
   state parse_udp {
        packet.extract(hdr.udp);
        ig_md.hash_meta.l4_sport = hdr.udp.srcPort;
        ig_md.hash_meta.l4_dport = hdr.udp.dstPort;
        transition accept; 
       }
  }


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

control SwitchIngressDeparser(
        packet_out packet,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Resubmit() resubmit;

    apply {

        if (ig_dprsr_md.resubmit_type == 1) {
            resubmit.emit();
        } else if (ig_dprsr_md.resubmit_type == 2) {
            resubmit.emit(ig_md.resubmit_data);
        }

        /*packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);*/

        packet.emit(hdr);
  }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------

parser SwitchEgressParser(
        packet_in packet,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

 	TofinoEgressParser() tofino_parser;

	state start {
        tofino_parser.apply(packet, eg_intr_md);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out packet,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
       //Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;

    apply {

    }

}


/*************************************************************************
*********************** I N G R E S S ***********************************
*************************************************************************/


control SwitchIngress(
                        inout header_t hdr,
                        inout ingress_metadata_t meta,
                        in ingress_intrinsic_metadata_t ig_intr_md,
                        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    /*********** Math Unit Functions ******************************/
    MathUnit<bit<16>>(MathOp_t.MUL, 1, 16) right_shift;

    /****** Register definition ***********************************/
    Register <bit<32>, _> (32w2048)  rFlowId      ;
    Register <bit<16>, _> (32w2048)  rIPGw        ;
    Register <bit<16>, _> (32w2048)  rTSlast      ;
    Register <bit<16>, _> (32w2048)  rTau         ;
    Register <bit<1>,  _> (32w2048)  rIPGflag     ;

    /**********  Calculate Table Index and Set IPG flag for first pkt of a flow ****************/
    Hash<rSize>(HashAlgorithm_t.CRC32) hTableIndex;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hFlowId;

    action computeFlowId() {
        { /* 5 Tuple */
            meta.hash_meta.flowId = hFlowId.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                                    hdr.ipv4.protocol, meta.hash_meta.l4_sport, meta.hash_meta.l4_dport });
        }
    }
    /***** Check whether the slot is vacant or not  *****/
    RegisterAction<bit<1>, rSize, bit<1>>(rIPGflag) rIPGflag_action = {
        void apply(inout bit<1> value, out bit<1> readvalue){
            readvalue = value;
            value = 1;
        }
    };
    action computeFIndex() {
        {
            meta.hash_meta.mIndex = hTableIndex.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,hdr.ipv4.protocol,
                                    meta.hash_meta.l4_sport, meta.hash_meta.l4_dport});
        }
    }

    /******************************************************************************************/
    /******* Case I : Insert new entry when the slot is vacant ********************************/
    /******************************************************************************************/

    /**********  Insert new Flow in the hash table ****************/
    RegisterAction<bit<32>, rSize, bit<32>>(rFlowId) rFlowId_action1 = {
        void apply(inout bit<32> value){
            value = meta.hash_meta.flowId;
        }
    };
    /***************** Set Ingress Timestamp  *********************/
    RegisterAction<bit<16>, rSize, bit<16>>(rTSlast) rTSlast_action1 = {
        void apply(inout bit<16> value){
            value =  (bit<16>) (meta.hash_meta.TS[21:10]);
        }
    };
    /***************  Initialize weighted IPG *********************/
    RegisterAction<bit<16>, rSize, bit<8>>(rIPGw) rIPGw_action1 = {
        void apply(inout bit<16> value){
            value = IPG_INIT;
        }
    };
    /***** Initilize Tau metric for keeping throughput state ******/
    RegisterAction<bit<16>, rSize, bit<16>>(rTau) rTau_action1 = {
        void apply(inout bit<16> value){
            value = 0;
        }
    };

    /******************************************************************************************/
    /*********************** Case II : Update the existing entry ******************************/
    /******************************************************************************************/

    /****** Update the last noted Timestamp **********************/
    RegisterAction<bit<16>, rSize, bit<16>>(rTSlast) rTSlast_action2 = {
        void apply(inout bit<16> value, out bit<16> readvalue){
            bit<16> tmp;
            if (value > (bit<16>) (meta.hash_meta.TS[21:10])) {
                tmp = value + 0x8000;
                readvalue = tmp;
            } else { tmp = value; readvalue = tmp;}
            value = (bit<16>) (meta.hash_meta.TS[21:10]);
        }
    };

    /**** Update IPG weighted (approximate calclution) **************/
    RegisterAction<bit<16>, rSize, bit<16>>(rIPGw) rIPGw_action2 = {
        void apply(inout bit<16> value, out bit<16> readvalue){
            readvalue = value;
            if (value > meta.hash_meta.IPGc) {
                value = value - right_shift.execute(value);
            } 
            else {
                value = value + meta.hash_meta.IPGcComp;
            }
        }
    };
    /**** Update Tau to keep flow throughput state  ********************/
    RegisterAction<bit<16>, rSize, bit<16>>(rTau) rTau_action2_1 = {
        void apply(inout bit<16> value, out bit<16> readvalue){
            if (value > TAU_TH) {
                value = 0;
                readvalue = 1;
            }
            else {
                value = value + meta.hash_meta.tau;
                readvalue = 2;
            }
        }
    };
    RegisterAction<bit<16>, rSize, bit<16>>(rTau) rTau_action2_2 = {
        void apply(inout bit<16> value, out bit<16> readvalue){
            if (value > TAU_TH) {
                value = 0;
                readvalue = 1;
            }
            else {
                readvalue = 2;
            }
        }
    };

    /*******************************************************************************************/
    /*************************** Case III ******************************************************/
    /*******************************************************************************************/

    /**** Update IPG weighted (approximated calclution) *******************/
    RegisterAction<bit<16>, rSize, bit<8>>(rIPGw) rIPGw_action3 = {
        void apply(inout bit<16> value, out bit<8> readvalue) {
            if (value > IPG_INIT){
            readvalue = 1;}
            else {readvalue = 2;}
            value = value + CONST;
        }
    };

    /** Check incoming flowId already exist in the register **************/
    RegisterAction<bit<32>, rSize, bit<8>>(rFlowId) rFlowId_action = {
        void apply(inout bit<32> value, out bit<8> readvalue){
            if ( value == meta.hash_meta.flowId ) {
                readvalue = 1;}
            else {readvalue = 0;}
        }
    };

    /**********************  Required Actions  *****************************************/
    action checkFlowId_flag() {
        meta.hash_meta.FlowIdFlag = rFlowId_action.execute(meta.hash_meta.mIndex);
    }
    action computeTSlast() {
        meta.hash_meta.TSlastComp  =  rTSlast_action2.execute(meta.hash_meta.mIndex);
    }
    action computeTSc() {
        /*********** Set wraptime 4096 microseconds ***********************/ 
        meta.hash_meta.TSc     =  (bit<16>)(meta.hash_meta.TS[21:10]);
        meta.hash_meta.TSlast  =  (bit<16>)(meta.hash_meta.TSlastComp[11:0]);
    }
    action computeIPGc_wt() {
        meta.hash_meta.IPGc = meta.hash_meta.Diff + meta.hash_meta.TSc;
    }
    action computeIPGc() {
        meta.hash_meta.IPGc = meta.hash_meta.TSc - meta.hash_meta.TSlast;
    }


    /********* match-action table for keeping flow throughput *********************/
    action setTau(bit<16> tau) {
        meta.hash_meta.tau =  tau;
    }
    action setTauNull() {
        meta.hash_meta.tau =  0;
    }
    table storeFlowTPState {
        key = {
            meta.hash_meta.IPGw :  exact;
        }
        actions = {setTau; setTauNull; }
        size = IPG_INIT;
        default_action = setTauNull;
    }

    /********** forwarding packets to output port ***********************************/
    action setOutputPort(port_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    table tblForwarding {
        key = {
            hdr.ipv4.srcAddr :  exact;
        }
        actions = {setOutputPort; NoAction; }
        size = 512;
        default_action = NoAction;
    }


    /**************************** Apply *********************************************/
    apply {

        /******** Preproecssing for HH detection ********************************/
        computeFlowId()                                                         ;
        computeFIndex()                                                         ;
        meta.hash_meta.IPGflag  = rIPGflag_action.execute(meta.hash_meta.mIndex);
        meta.hash_meta.TS = ig_intr_md.ingress_mac_tstamp                       ;
        meta.hash_meta.tauFlag = 2                                              ;
        meta.hash_meta.resubmit_type = 0                                        ;

        /************************* Case I *******************************/
        if ( meta.hash_meta.IPGflag == 0 || ig_intr_md.resubmit_flag == 1 ) {
            rFlowId_action1.execute(meta.hash_meta.mIndex)  ;
            rTSlast_action1.execute(meta.hash_meta.mIndex)  ;
            rIPGw_action1.execute(meta.hash_meta.mIndex)    ;
            rTau_action1.execute(meta.hash_meta.mIndex)     ;
        }
        else {
            checkFlowId_flag();
            /****************** Case II  ******************************/
            if (meta.hash_meta.FlowIdFlag == 1) {
                computeTSlast();
                computeTSc();
                if (meta.hash_meta.TSlastComp[15:15] == 0x1) {
                    meta.hash_meta.Diff = WRAPTIME - meta.hash_meta.TSlast;
                    computeIPGc_wt();
                    meta.hash_meta.IPGcComp = (bit<16>) (meta.hash_meta.IPGc[15:4]); 
                    meta.hash_meta.IPGw = rIPGw_action2.execute(meta.hash_meta.mIndex);
                    storeFlowTPState.apply();
                    meta.hash_meta.tauFlag = rTau_action2_1.execute(meta.hash_meta.mIndex);
                } else {
                    computeIPGc();
                    meta.hash_meta.IPGcComp = (bit<16>) (meta.hash_meta.IPGc[15:4]);
                    meta.hash_meta.IPGw = rIPGw_action2.execute(meta.hash_meta.mIndex);
                    meta.hash_meta.tauFlag = rTau_action2_2.execute(meta.hash_meta.mIndex);
                }
            }
            /******************** Case III *******************************************/
            else {
                /****** IPGw Calculation and Resubmission pkt ********************/
                if (rIPGw_action3.execute(meta.hash_meta.mIndex) == 1) {
                    ig_intr_dprsr_md.resubmit_type = 1;
                    meta.hash_meta.resubmit_type   = 1;
                }
            }
        }

        /******* Detected HHs can be dropped or put in lower priority queue or route to ******/
        /********** other path or report to the controller for further actions ***************/
        if (meta.hash_meta.resubmit_type == 0) {
                if (meta.hash_meta.tauFlag == 1) {
                    // inform to the controller
                }
                tblForwarding.apply();
                //ig_tm_md.bypass_egress = 1w1;
        }
    }
}

/*********************  E G R E S S   P R O C E S S I N G  ********************************************/
control SwitchEgress(
    inout header_t hdr,
    inout egress_metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    apply{ }
}

/********************************  S W I T C H  ********************************************************/
Pipeline(SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;
