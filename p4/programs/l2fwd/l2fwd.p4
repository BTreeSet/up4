// l2fwd - a static-forwarding-database L2 switch.
//
// Artifact of record for up4's `l2fwd` pipeline (spec P1). Written in the
// SoftNPU dialect that x4c compiles: 16-bit egress ports, and the egress
// metadata booleans that spec S7.2 maps onto up4 verdicts
// (drop -> Drop, broadcast -> Broadcast, port 65535 -> Punt, else Forward).
//
// The corresponding Rust rendering is crates/up4-engine/src/programs/l2fwd.rs.
// Where the two disagree, this file wins and the conformance corpus in
// p4/corpus/l2fwd says so.

#include <core.p4>
#include <softnpu.p4>

SoftNPU(parse(), ingress()) main;

header ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

struct headers_t {
    ethernet_h ethernet;
}

parser parse(packet_in pkt, out headers_t hdr, inout IngressMetadata ingress) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control ingress(
    inout headers_t hdr,
    inout IngressMetadata ingress,
    inout EgressMetadata egress
) {
    action forward(bit<16> port) {
        egress.port = port;
    }

    action broadcast() {
        egress.broadcast = true;
    }

    action drop() {
        egress.drop = true;
    }

    // A frame whose destination is not in the database floods, which is what
    // an L2 switch with no learning can honestly do.
    table mac_dst {
        key = {
            hdr.ethernet.dst: exact;
        }
        actions = {
            forward;
            broadcast;
            drop;
        }
        default_action = broadcast();
        size = 1024;
    }

    apply {
        mac_dst.apply();
    }
}
