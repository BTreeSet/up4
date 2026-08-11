// l2fwd, bound to the uBPF architecture (`ubpf_model.p4`).
//
// Artifact of record for up4's `l2fwd` program on the `ubpf` backend (spec
// P1). Compiled by `p4c --target ubpf` to C, then by `clang -target bpf` to
// bytecode that up4 executes in process.
//
// The same program bound to SoftNPU is l2fwd.softnpu.p4. The two files share
// no text: what makes them the same program is the conformance corpus in
// p4/corpus/l2fwd, which every backend must satisfy identically.
//
// Verdict mapping. `ubpf_model.p4` gives a pipeline `mark_to_drop()`,
// `mark_to_pass()`, and a 32-bit `output_port` -- and no way to say
// "replicate". up4 therefore reserves two port ids for the verdicts the
// architecture cannot express directly (spec S5): 65535 punts to the control
// channel and 65534 broadcasts. Both are reserved across every backend, not
// just this one, so the vport space means the same thing everywhere.
//
// Ports are carried as bit<16> and widened on assignment so that a table entry
// installed through `up4ctl` has the same encoding on all three backends.

#include <core.p4>
#include <ubpf_model.p4>

header ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

struct headers_t {
    ethernet_h ethernet;
}

struct metadata_t { }

parser prs(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata std
) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control pipe(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata std
) {
    action forward(bit<16> port) {
        std.output_port = (bit<32>)port;
        mark_to_pass();
    }

    action broadcast() {
        std.output_port = 32w65534;
        mark_to_pass();
    }

    action drop() {
        mark_to_drop();
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

control dprs(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
    }
}

ubpf(prs(), pipe(), dprs()) main;
