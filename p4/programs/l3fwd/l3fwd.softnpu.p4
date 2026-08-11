// l3fwd, bound to the SoftNPU architecture.
//
// Artifact of record for up4's `l3fwd` program on the `native` and `x4c`
// backends (spec P1). `x4c --check` runs over this file in CI.
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
// The ethertype demux is in the control, not the parser. x4c's Rust backend
// does not implement `transition select` (`codegen/rust/src/statement.rs`
// reaches `todo!()` on it), so expressing the demux as a parser transition
// would make this program uncompilable by one of the two compilers that must
// read it. Moving it into `apply` is verdict-equivalent: a frame too short to
// carry an IPv4 header fails extraction and is rejected either way, and a
// long non-IPv4 frame is dropped here before any header is written, so the
// misparsed bytes are never observable. The corpus covers both cases.
//
// Constants are written as literals for the same reason: x4c does not resolve
// a `const` referenced from an expression or an action body, so 16w0x0800 is
// IPv4's ethertype and 16w65535 is up4's reserved punt port (spec S5).

#include <core.p4>
#include <softnpu.p4>

SoftNPU(parse(), ingress(), egress()) main;

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

parser parse(packet_in pkt, out headers_t hdr, inout ingress_metadata_t ingress) {
    state start {
        pkt.extract(hdr.ethernet);
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control ingress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress
) {
    action drop() {
        egress.drop = true;
    }

    // The reserved egress port up4 delivers to the control channel (spec S5).
    action punt() {
        egress.port = 16w65535;
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
        default_action = drop;
        size = 4096;
    }

    apply {
        if (hdr.ethernet.ether_type != 16w0x0800) {
            // Not IPv4: this router has nothing to say about it.
            egress.drop = true;
        } else if (hdr.ipv4.ttl == 8w0) {
            // An arriving TTL of zero is already expired; the table is not
            // consulted.
            egress.drop = true;
        } else {
            ipv4_lpm.apply();
        }
    }
}

control egress(
    inout headers_t hdr,
    inout ingress_metadata_t ingress,
    inout egress_metadata_t egress
) {
    apply { }
}
