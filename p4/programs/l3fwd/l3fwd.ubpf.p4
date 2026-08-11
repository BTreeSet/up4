// l3fwd, bound to the uBPF architecture (`ubpf_model.p4`).
//
// Artifact of record for up4's `l3fwd` program on the `ubpf` backend (spec
// P1). See l3fwd.softnpu.p4 for the two up4 rules the source makes visible
// (checksum zero-filled, source MAC untouched) and l2fwd.ubpf.p4 for the
// verdict mapping and the two reserved port ids.
//
// Unlike the SoftNPU binding, this one keeps the ethertype demux in the
// parser where P4 puts it: p4c implements `transition select`, so there is no
// reason to move it. The two bindings must still agree verdict for verdict on
// the corpus, which is what proves the relocation in the other file is sound.

#include <core.p4>
#include <ubpf_model.p4>

const bit<16> ETHERTYPE_IPV4 = 16w0x0800;
const bit<32> PUNT_PORT = 32w65535;

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

struct metadata_t { }

parser prs(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata std_meta
) {
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

control pipe(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata std_meta
) {
    action drop() {
        mark_to_drop();
    }

    action punt() {
        std_meta.output_port = PUNT_PORT;
        mark_to_pass();
    }

    action forward(bit<16> port, bit<48> dmac) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
        hdr.ethernet.dst = dmac;
        hdr.ipv4.hdr_checksum = 16w0;
        std_meta.output_port = (bit<32>)port;
        mark_to_pass();
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
        // An arriving TTL of zero is already expired; the table is not
        // consulted.
        if (hdr.ipv4.ttl == 8w0) {
            mark_to_drop();
        } else {
            ipv4_lpm.apply();
        }
    }
}

control dprs(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

ubpf(prs(), pipe(), dprs()) main;
