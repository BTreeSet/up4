// l2fwd, bound to the SoftNPU architecture.
//
// Artifact of record for up4's `l2fwd` program on the `native` and `x4c`
// backends (spec P1). `x4c --check` runs over this file in CI, so the claim
// that it is the dialect x4c compiles is tested rather than asserted.
//
// The same program bound to the uBPF architecture is l2fwd.ubpf.p4. Nothing
// textual ties the two together on purpose: what ties them is the conformance
// corpus in p4/corpus/l2fwd, which every backend must satisfy identically.
//
// Verdict mapping (spec S7.2): egress.drop -> Drop, egress.broadcast ->
// Broadcast, egress.port == 65535 -> Punt, any other egress.port -> Forward.

#include <core.p4>
#include <softnpu.p4>

SoftNPU(parse(), ingress(), egress()) main;

header ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

struct headers_t {
    ethernet_h ethernet;
}

parser parse(packet_in pkt, out headers_t hdr, inout ingress_metadata_t ingress) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control ingress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress
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
        default_action = broadcast;
        size = 1024;
    }

    apply {
        mac_dst.apply();
    }
}

// SoftNPU is a three-stage package. up4 makes every forwarding decision in
// ingress, so egress exists to satisfy the architecture and does nothing.
control egress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress
) {
    apply { }
}
