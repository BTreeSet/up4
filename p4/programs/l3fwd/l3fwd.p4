// l3fwd - an IPv4 router with a longest-prefix-match route table.
//
// Artifact of record for up4's `l3fwd` pipeline (spec P1). SoftNPU dialect;
// see p4/programs/l2fwd/l2fwd.p4 for the verdict mapping.
//
// Two up4 rules are visible in the source:
//
//   * The header checksum is zero-filled rather than recomputed. up4 never
//     computes or verifies an inner checksum (spec S1.5); the outer UDP
//     checksum covers integrity on the fabric, and the conformance corpus
//     masks exactly these fields (spec S10).
//   * The source MAC is left alone. up4 vports have no addresses of their own,
//     so rewriting it would be a forwarding decision made outside the table.
//
// The corresponding Rust rendering is crates/up4-engine/src/programs/l3fwd.rs.

#include <core.p4>
#include <softnpu.p4>

SoftNPU(parse(), ingress()) main;

const bit<16> ETHERTYPE_IPV4 = 16w0x0800;

// The reserved egress port that up4 delivers to the control channel (spec S5).
const bit<16> PUNT_PORT = 16w65535;

header ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src;
    bit<32> dst;
}

struct headers_t {
    ethernet_h ethernet;
    ipv4_h     ipv4;
}

parser parse(packet_in pkt, out headers_t hdr, inout IngressMetadata ingress) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: ipv4;
            default: reject;
        }
    }

    state ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control ingress(
    inout headers_t hdr,
    inout IngressMetadata ingress,
    inout EgressMetadata egress
) {
    action drop() {
        egress.drop = true;
    }

    action punt() {
        egress.port = PUNT_PORT;
    }

    action forward(bit<16> port, bit<48> dmac) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
        hdr.ethernet.dst = dmac;
        hdr.ipv4.hdr_checksum = 16w0;
        egress.port = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst: lpm;
        }
        actions = {
            forward;
            punt;
            drop;
        }
        default_action = drop();
        size = 4096;
    }

    apply {
        // An arriving TTL of zero is already expired; the table is not consulted.
        if (hdr.ipv4.ttl == 8w0) {
            drop();
        } else {
            ipv4_lpm.apply();
        }
    }
}
