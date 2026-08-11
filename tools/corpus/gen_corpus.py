#!/usr/bin/env python3
"""Generate up4's conformance corpora (spec S10).

This script is an *independent model* of the two P4 programs: it builds each
frame and works out what `p4/programs/<name>/<name>.softnpu.p4` says should happen to
it, without consulting the Rust implementation. `crates/up4-engine/tests/
conformance.rs` then replays the corpus through the real engine and diffs.

Two models written from one P4 source is the whole point: a bug that exists in
only one of them shows up as a diff. When the BMv2 differential runner of spec
S10 lands (`tools/bmv2-diff/`), it replaces this script as the source of the
expectations and the Rust side does not change.

Usage: python3 tools/corpus/gen_corpus.py [--check]
       --check verifies the checked-in corpora match what this script produces.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORPUS = ROOT / "p4" / "corpus"

ETH_HDR_LEN = 14
IPV4_MIN_HDR_LEN = 20
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
IP_PROTO_UDP = 17

# Fields masked on both sides before diffing (spec S10). Nothing else is
# masked, and this list is duplicated (deliberately, in one place each) in
# conformance.rs. Keep them adjacent: p4/corpus/README.md documents the pair.
MASK_IPV4_CHECKSUM = True
MASK_L4_CHECKSUM = True


def mac(text: str) -> bytes:
    return bytes(int(b, 16) for b in text.split(":"))


def ipv4(text: str) -> bytes:
    return bytes(int(b) for b in text.split("."))


def frame(
    *,
    dst_mac: str = "02:00:00:00:00:02",
    src_mac: str = "02:00:00:00:00:01",
    ethertype: int = ETHERTYPE_IPV4,
    src_ip: str = "10.0.1.1",
    dst_ip: str = "10.0.2.1",
    ttl: int = 64,
    total: int = 128,
    version: int = 4,
    ihl: int = 5,
    hdr_checksum: int = 0xDEAD,
    l4_checksum: int = 0xBEEF,
) -> bytes:
    """An Ethernet frame, with IPv4/UDP when the ethertype says so."""
    out = bytearray(mac(dst_mac) + mac(src_mac) + ethertype.to_bytes(2, "big"))
    if ethertype == ETHERTYPE_IPV4:
        ip = bytearray(IPV4_MIN_HDR_LEN)
        ip[0] = (version << 4) | ihl
        ip[2:4] = max(0, total - ETH_HDR_LEN).to_bytes(2, "big")
        ip[8] = ttl
        ip[9] = IP_PROTO_UDP
        ip[10:12] = hdr_checksum.to_bytes(2, "big")
        ip[12:16] = ipv4(src_ip)
        ip[16:20] = ipv4(dst_ip)
        out += ip
        udp = bytearray(8)
        udp[0:2] = (4000).to_bytes(2, "big")
        udp[2:4] = (4001).to_bytes(2, "big")
        udp[4:6] = max(0, total - ETH_HDR_LEN - IPV4_MIN_HDR_LEN).to_bytes(2, "big")
        udp[6:8] = l4_checksum.to_bytes(2, "big")
        out += udp
    # A recognizable payload, so a diff points at an offset rather than a blur.
    out += bytes((i % 251) for i in range(max(0, total - len(out))))
    return bytes(out[:total]) if total >= len(out) else bytes(out)


def routed(f: bytes, *, dmac: str, decrement_ttl: bool = True) -> bytes:
    """What `l3fwd`'s forward action leaves behind.

    The action itself rewrites the destination MAC, decrements the TTL, and
    zeroes the IPv4 header checksum. Zeroing the transport checksum is the
    harness's one inner-packet touch (spec S1.5), and it finds the transport
    header the only way an IPv4 header offers: through IHL. A header length
    below the legal minimum, or one running past the captured bytes, locates
    no transport header, so nothing is zeroed -- which is exactly what
    `Ipv4::payload_offset` returning `None` means on the Rust side.
    """
    out = bytearray(f)
    out[0:6] = mac(dmac)
    if decrement_ttl:
        out[ETH_HDR_LEN + 8] -= 1
    out[ETH_HDR_LEN + 10 : ETH_HDR_LEN + 12] = b"\x00\x00"  # never recomputed
    hdr_len = (f[ETH_HDR_LEN] & 0x0F) * 4
    l4 = ETH_HDR_LEN + hdr_len
    if hdr_len >= IPV4_MIN_HDR_LEN and l4 + 8 <= len(out):
        out[l4 + 6 : l4 + 8] = b"\x00\x00"
    return bytes(out)


def case(name, port, f, verdict, egress=None, out=None):
    expect = {"verdict": verdict}
    if egress is not None:
        expect["egress_port"] = egress
    if out is not None:
        expect["frame_hex"] = out.hex()
    return {"name": name, "ingress_port": port, "frame_hex": f.hex(), "expect": expect}


def l2fwd():
    tables = [
        {"table": "mac_dst", "key": "02:00:00:00:00:02", "action": "forward", "params": {"port": "1"}},
        {"table": "mac_dst", "key": "02:00:00:00:00:03", "action": "drop", "params": {}},
    ]
    hit = frame(dst_mac="02:00:00:00:00:02")
    cases = [
        case("hit-forwards", 0, hit, "forward", 1, hit),
        case("miss-broadcasts", 0, frame(dst_mac="02:00:00:00:00:09"), "broadcast"),
        case("entry-may-drop", 0, frame(dst_mac="02:00:00:00:00:03"), "drop"),
        # The parser extracts only ethernet, so a non-IP frame still matches.
        case("non-ip-still-matches", 1, frame(dst_mac="02:00:00:00:00:02", ethertype=ETHERTYPE_ARP, total=60),
             "forward", 1, frame(dst_mac="02:00:00:00:00:02", ethertype=ETHERTYPE_ARP, total=60)),
        # Truncated ethernet: the one extracted header, one byte short.
        case("truncated-ethernet", 0, frame()[: ETH_HDR_LEN - 1], "drop"),
        case("empty-frame", 0, b"", "drop"),
        case("min-size-frame", 0, frame(dst_mac="02:00:00:00:00:02", total=60), "forward", 1,
             frame(dst_mac="02:00:00:00:00:02", total=60)),
        case("max-size-frame", 0, frame(dst_mac="02:00:00:00:00:02", total=1460), "forward", 1,
             frame(dst_mac="02:00:00:00:00:02", total=1460)),
        # Broadcast fan-out is the harness's job; the pipeline just says so.
        case("broadcast-address-misses", 0, frame(dst_mac="ff:ff:ff:ff:ff:ff"), "broadcast"),
    ]
    return tables, cases


def l3fwd():
    dmac_24, dmac_32 = "bb:bb:bb:bb:bb:01", "bb:bb:bb:bb:bb:02"
    tables = [
        {"table": "ipv4_lpm", "key": "10.0.2.0/24", "action": "forward", "params": {"port": "1", "dmac": dmac_24}},
        {"table": "ipv4_lpm", "key": "10.0.2.7/32", "action": "forward", "params": {"port": "2", "dmac": dmac_32}},
        {"table": "ipv4_lpm", "key": "10.7.0.0/16", "action": "punt", "params": {}},
        {"table": "ipv4_lpm", "key": "10.8.0.0/16", "action": "drop", "params": {}},
    ]
    f24 = frame(dst_ip="10.0.2.9")
    f32 = frame(dst_ip="10.0.2.7")
    ttl1 = frame(dst_ip="10.0.2.9", ttl=1)
    small = frame(dst_ip="10.0.2.9", total=60)
    large = frame(dst_ip="10.0.2.9", total=1460)
    cases = [
        case("lpm-hit-24", 0, f24, "forward", 1, routed(f24, dmac=dmac_24)),
        case("lpm-longest-prefix-wins", 0, f32, "forward", 2, routed(f32, dmac=dmac_32)),
        case("lpm-miss-takes-default-action", 0, frame(dst_ip="192.168.0.1"), "drop"),
        case("entry-may-punt", 0, frame(dst_ip="10.7.1.1"), "punt"),
        case("entry-may-drop", 0, frame(dst_ip="10.8.1.1"), "drop"),
        # TTL: 1 forwards and leaves 0 behind; 0 never reaches the table.
        case("ttl-one-forwards-with-ttl-zero", 0, ttl1, "forward", 1, routed(ttl1, dmac=dmac_24)),
        case("ttl-zero-is-dropped", 0, frame(dst_ip="10.0.2.9", ttl=0), "drop"),
        # Parser branches: the select on ethertype, both ways.
        case("non-ipv4-is-rejected-by-the-parser", 0, frame(ethertype=ETHERTYPE_ARP, total=60), "drop"),
        case("truncated-ethernet", 0, frame()[: ETH_HDR_LEN - 1], "drop"),
        case("truncated-ipv4", 0, frame()[: ETH_HDR_LEN + IPV4_MIN_HDR_LEN - 1], "drop"),
        case("min-size-frame", 0, small, "forward", 1, routed(small, dmac=dmac_24)),
        case("max-size-frame", 0, large, "forward", 1, routed(large, dmac=dmac_24)),
        # Ingress port is metadata, not a key: the same frame routes the same way.
        case("ingress-port-does-not-change-the-decision", 3, f24, "forward", 1, routed(f24, dmac=dmac_24)),
    ]
    # Ingress admission (`Admission::CoherentIpv4`), not the P4 parser. A P4
    # parser rejects when `extract` runs out of bytes and for no other reason,
    # so neither l3fwd binding refuses these on its own -- up4 refuses them
    # before the program runs, identically on every backend, because a router
    # declines to route a header that contradicts itself. See
    # crates/up4-engine/src/admission.rs and docs/deviations.md D10.
    cases += [
        case("ihl-past-the-end-of-the-frame", 0,
             frame(dst_ip="10.0.2.9", total=30, ihl=15), "drop"),
        case("ihl-below-the-legal-minimum", 0,
             frame(dst_ip="10.0.2.9", ihl=3), "drop"),
        case("version-is-not-four", 0,
             frame(dst_ip="10.0.2.9", version=6), "drop"),
    ]
    return tables, cases


PROGRAMS = {"l2fwd": l2fwd, "l3fwd": l3fwd}


def render(name):
    tables, cases = PROGRAMS[name]()
    return {
        "tables.json": json.dumps({"entries": tables}, indent=2) + "\n",
        "cases.json": json.dumps(cases, indent=2) + "\n",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify instead of writing")
    args = parser.parse_args()

    failures = 0
    for name in PROGRAMS:
        directory = CORPUS / name
        directory.mkdir(parents=True, exist_ok=True)
        for filename, contents in render(name).items():
            path = directory / filename
            if args.check:
                current = path.read_text() if path.exists() else ""
                if current != contents:
                    print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
                    failures += 1
            else:
                path.write_text(contents)
                print(f"wrote {path.relative_to(ROOT)}")
    if args.check and failures:
        print("run tools/corpus/gen_corpus.py to regenerate", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
