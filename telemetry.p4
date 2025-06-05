// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

const bit<16> S1 = 0x7331;
const bit<16> S2 = 0x7332;
const bit<16> S3 = 0x7333;
const bit<16> S4 = 0x7334;
const bit<16> S5 = 0x7335;
const bit<16> EMPTY = 0x0000;

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

// This function will output the path the package went through
header path_t {
    // each ascii character uses 8bits, the names have 2 ascii
    bit<16> first;
    bit<16> second;
    bit<16> third;
}

struct metadata {
    bit<16> current_switch_id; // Will hold the ID of the switch processing the packet
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    path_t       path;
}

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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_path;
    }

    state parse_path {
        packet.extract(hdr.path);
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

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action set_this_switch_id(bit<16> switch_id_val){
        meta.current_switch_id = switch_id_val;
    }

    table current_switch_id {
        key = {} // can be empty
        actions = {
            set_this_switch_id;
            NoAction;
        }
        size = 1;
        default_action = NoAction;
    }

    // Init all paths as empty, then changes it according to the path the packet is 
    // going thorugh.
    action record_switch_in_path(){
        if(!hdr.path.isValid()){
            hdr.path.setValid();
            hdr.path.first = EMPTY;
            hdr.path.second = EMPTY; 
            hdr.path.third = EMPTY;  
        }
        if(hdr.path.first == EMPTY){
            hdr.path.first = meta.current_switch_id;
        }else if(hdr.path.second == EMPTY){
            hdr.path.second = meta.current_switch_id;
        }else if(hdr.path.third == EMPTY){
            hdr.path.third = meta.current_switch_id;
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // 1. Get the ID of the current switch
            current_switch_id.apply(); // This populates meta.current_switch_id
            
            if (meta.current_switch_id != EMPTY) {
                record_switch_in_path();
            }
            ipv4_lpm.apply();
        }
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.path);
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