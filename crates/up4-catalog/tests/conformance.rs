//! Conformance: every compiled-in pipeline against its corpus (spec S10).
//!
//! The corpus in `p4/corpus/<program>/` is produced by an independent model of
//! the P4 source (`tools/corpus/gen_corpus.py`, and in due course the BMv2
//! differential runner of spec S10). This test replays it through the real
//! `Engine` — no sockets, no harness — and diffs verdict and frame bytes.
//!
//! Masking: before diffing frames, the IPv4 header checksum and the TCP/UDP
//! checksums are zeroed on **both** sides, and nothing else is. up4 never
//! computes an inner checksum (spec S1.5), so those fields carry no
//! information; every other byte must match exactly.

use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};
use up4_engine::admission::Admission;
use up4_engine::catalog::{Backend, Program, Selection};
use up4_engine::{
    Engine, FrameCtx, Pipeline, PipelineParams, TypedKey, TypedVal, Verdict,
    headers::{ETH_HDR_LEN, ETHERTYPE_IPV4, IP_PROTO_TCP, IP_PROTO_UDP, IPV4_MIN_HDR_LEN},
};

/// Headroom the harness promises a pipeline (spec S7.1).
const HEADROOM: usize = 64;

#[derive(Debug, Deserialize)]
struct Batch {
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    table: String,
    key: String,
    action: String,
    #[serde(default)]
    params: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    ingress_port: u16,
    frame_hex: String,
    expect: Expect,
}

#[derive(Debug, Deserialize)]
struct Expect {
    verdict: String,
    egress_port: Option<u16>,
    frame_hex: Option<String>,
}

fn corpus_dir(program: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../p4/corpus")
        .join(program)
}

fn read<T: serde::de::DeserializeOwned>(path: &PathBuf) -> T {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (corpus missing is a build failure, spec S10)",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex string");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digits"))
        .collect()
}

/// Install the corpus's control-plane state, refining each value against the
/// table's own schema — the same gate the control channel uses.
fn load_tables(pipeline: &dyn Pipeline, entries: &[Entry]) {
    for entry in entries {
        let schema = pipeline
            .tables()
            .schema(&entry.table)
            .unwrap_or_else(|e| panic!("{}: {e}", entry.table));
        let key = TypedKey::parse(schema.key, &entry.key)
            .unwrap_or_else(|e| panic!("{} key {:?}: {e}", entry.table, entry.key));
        let action = schema
            .action(&entry.action)
            .unwrap_or_else(|| panic!("{} has no action {:?}", entry.table, entry.action));
        let params: Vec<TypedVal> = action
            .params
            .iter()
            .map(|p| {
                let text = entry
                    .params
                    .get(p.name)
                    .unwrap_or_else(|| panic!("{} missing parameter {}", entry.action, p.name));
                TypedVal::parse(p.kind, text).unwrap_or_else(|e| panic!("{}: {e}", p.name))
            })
            .collect();
        pipeline
            .tables()
            .table_add(schema.name, key, action.name, &params)
            .unwrap_or_else(|e| panic!("installing {} {}: {e}", entry.table, entry.key));
    }
}

/// Zero the fields spec S10 masks, and only those.
fn mask(frame: &mut [u8]) {
    let Some(ethertype) = frame.get(12..14) else {
        return;
    };
    if u16::from_be_bytes([ethertype[0], ethertype[1]]) != ETHERTYPE_IPV4 {
        return;
    }
    let Some(ip) = frame.get(ETH_HDR_LEN..) else {
        return;
    };
    if ip.len() < IPV4_MIN_HDR_LEN {
        return;
    }
    let hdr_len = usize::from(ip[0] & 0x0f) * 4;
    let protocol = ip[9];
    if let Some(field) = frame.get_mut(ETH_HDR_LEN + 10..ETH_HDR_LEN + 12) {
        field.fill(0);
    }
    let l4 = ETH_HDR_LEN + hdr_len;
    let offset = match protocol {
        IP_PROTO_TCP => l4 + 16,
        IP_PROTO_UDP => l4 + 6,
        _ => return,
    };
    if let Some(field) = frame.get_mut(offset..offset + 2) {
        field.fill(0);
    }
}

fn masked(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    mask(&mut out);
    out
}

/// Run one case through the engine exactly as the harness would.
fn run(engine: &mut dyn Engine, case: &Case) -> (Verdict, Vec<u8>) {
    let frame = hex_to_bytes(&case.frame_hex);
    let mut buf = vec![0u8; HEADROOM + frame.len()];
    buf[HEADROOM..].copy_from_slice(&frame);
    let mut ctx = FrameCtx::new(&mut buf, HEADROOM, frame.len(), case.ingress_port, 0)
        .expect("the window fits by construction");
    let verdict = engine.process(&mut ctx);
    (verdict, ctx.frame().to_vec())
}

fn describe(verdict: Verdict) -> (String, Option<u16>) {
    match verdict {
        Verdict::Forward(port) => ("forward".to_owned(), Some(port)),
        Verdict::Broadcast => ("broadcast".to_owned(), None),
        Verdict::Punt => ("punt".to_owned(), None),
        Verdict::Drop => ("drop".to_owned(), None),
    }
}

/// Replay a whole corpus.
fn conform(program: &str) {
    let dir = corpus_dir(program);
    let batch: Batch = read(&dir.join("tables.json"));
    let cases: Vec<Case> = read(&dir.join("cases.json"));
    assert!(
        !cases.is_empty(),
        "{program}: an empty corpus proves nothing"
    );

    // Every backend, on the same corpus. That all three produce identical
    // output on identical input is what makes "the same program" a checkable
    // claim rather than a naming convention — the three share no code and, in
    // the uBPF case, not even a language.
    for backend in Backend::ALL {
        check_backend(program, backend, &batch, &cases);
    }
}

fn check_backend(program: &str, backend: Backend, batch: &Batch, cases: &[Case]) {
    let sel = Selection::P4 {
        program: Program::parse(program).expect("known program"),
        backend,
    };
    let pipeline = up4_catalog::build(sel, &PipelineParams::new([0, 1, 2, 3]));
    load_tables(&*pipeline, &batch.entries);
    let mut engine = pipeline.engine();

    for case in cases {
        let (verdict, frame) = run(&mut *engine, case);
        let (got_verdict, got_port) = describe(verdict);
        assert_eq!(
            got_verdict,
            case.expect.verdict,
            "{program}/{}: {} verdict",
            case.name,
            backend.name()
        );
        if let Some(want_port) = case.expect.egress_port {
            assert_eq!(
                got_port,
                Some(want_port),
                "{program}/{}: egress port",
                case.name
            );
        }
        if let Some(want_hex) = &case.expect.frame_hex {
            let want = masked(&hex_to_bytes(want_hex));
            let got = masked(&frame);
            assert_eq!(
                got.len(),
                want.len(),
                "{program}/{}: frame length {} != {}",
                case.name,
                got.len(),
                want.len()
            );
            if got != want {
                let at = got.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(0);
                panic!(
                    "{program}/{}: frames differ at byte {at}: got {:02x?}, want {:02x?}",
                    case.name,
                    &got[at..(at + 8).min(got.len())],
                    &want[at..(at + 8).min(want.len())]
                );
            }
        }
    }
    println!("{program}: {} cases pass", cases.len());
}

#[test]
fn l2fwd_matches_its_corpus() {
    conform("l2fwd");
}

#[test]
fn l3fwd_matches_its_corpus() {
    conform("l3fwd");
}

/// The composition law, checked independently of the corpus: whatever a
/// program's [`Admission`] refuses, *every* backend of that program refuses.
///
/// The corpus already covers three such frames, but only the ones someone
/// thought to write down. This walks the whole domain the check inspects —
/// all 256 values of the IPv4 version/IHL byte — against all three backends,
/// so a backend that quietly stopped applying admission (or a `build` that
/// forgot to wrap one) fails here rather than waiting for a corpus case to be
/// added. It is the pointwise statement of `up4(p) = admit(p) ; p4(p)`.
#[test]
fn admission_binds_every_backend_of_a_program() {
    let params = PipelineParams::new([0, 1, 2, 3]);
    for program in Program::ALL {
        let admission = program.admission();
        if admission == Admission::Everything {
            continue;
        }
        let batch: Batch = read(&corpus_dir(program.name()).join("tables.json"));
        for backend in Backend::ALL {
            let pipeline = up4_catalog::build(Selection::P4 { program, backend }, &params);
            load_tables(&*pipeline, &batch.entries);
            let mut engine = pipeline.engine();
            for byte in 0..=u8::MAX {
                let mut frame = ipv4_frame(byte);
                if admission.admits(&frame) {
                    continue;
                }
                let mut buf = vec![0u8; HEADROOM + frame.len()];
                buf[HEADROOM..].copy_from_slice(&frame);
                let mut ctx = FrameCtx::new(&mut buf, HEADROOM, frame.len(), 0, 0).expect("fits");
                assert_eq!(
                    engine.process(&mut ctx),
                    Verdict::Drop,
                    "{}/{}: admission refused version/ihl byte {byte:#04x}, the backend did not",
                    program.name(),
                    backend.name()
                );
                frame.clear();
            }
        }
    }
}

/// A routable frame whose IPv4 version/IHL byte is `byte`. The destination is
/// one the corpus routes, so anything but a `Drop` is a real disagreement
/// rather than a table miss.
fn ipv4_frame(byte: u8) -> Vec<u8> {
    let mut f = vec![0u8; ETH_HDR_LEN + IPV4_MIN_HDR_LEN + 8];
    f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    f[ETH_HDR_LEN] = byte;
    f[ETH_HDR_LEN + 8] = 64; // ttl
    f[ETH_HDR_LEN + 9] = IP_PROTO_UDP;
    f[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20].copy_from_slice(&[10, 0, 2, 9]);
    f
}

/// Spec S10's CI gate: a program without a corpus fails the build. Stated as a
/// test so that adding a pipeline without adding a corpus is a red test rather
/// than a silent gap.
#[test]
fn every_registered_program_has_a_corpus() {
    for program in Program::ALL {
        let dir = corpus_dir(program.name());
        assert!(
            dir.join("cases.json").exists(),
            "{} has no corpus",
            program.name()
        );
        assert!(
            dir.join("tables.json").exists(),
            "{} has no corpus tables",
            program.name()
        );
    }
}

/// The mask must be narrow: it may not hide a TTL, an address, or a payload.
#[test]
fn masking_touches_only_the_checksums() {
    let original = hex_to_bytes(
        &serde_json::from_str::<Vec<Case>>(
            &std::fs::read_to_string(corpus_dir("l3fwd").join("cases.json")).expect("corpus"),
        )
        .expect("valid corpus")[0]
            .frame_hex,
    );
    let after = masked(&original);
    let differences: Vec<usize> = (0..original.len())
        .filter(|i| original[*i] != after[*i])
        .collect();
    assert_eq!(
        differences,
        vec![24, 25, 40, 41],
        "only the IPv4 header checksum and the L4 checksum may be masked"
    );
}
