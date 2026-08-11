//! One test per validation rule (spec S13.1), plus the multi-error case that
//! is the point of the accumulator.

use super::*;

const REGISTRY: &[&str] = &["l2fwd", "l3fwd"];

fn cfg(extra_node: &str, vports: &str) -> Result<Config, ConfigErrors> {
    let src = format!(
        r#"
[node]
id = "a"
bind = "10.0.0.11:7400"
pipeline = "l2fwd"
ctl_socket = "/tmp/up4-a.sock"
{extra_node}
{vports}
"#
    );
    Config::from_toml(&src, REGISTRY)
}

fn one_vport() -> &'static str {
    "[[vport]]\nid = 0\npeer = \"10.0.0.12:7400\"\n"
}

fn errors(r: Result<Config, ConfigErrors>) -> Vec<ConfigError> {
    r.expect_err("expected the configuration to be rejected")
        .iter()
        .cloned()
        .collect()
}

#[test]
fn minimal_config_has_documented_defaults() {
    let c = cfg("", one_vport()).expect("valid");
    assert_eq!(c.node.fabric, Fabric::V4);
    assert_eq!(c.node.threads, Threads::new(1).expect("1 is in range"));
    assert_eq!(c.node.metrics_interval, Some(Duration::from_secs(5)));
    assert!(c.node.pin_cores.is_empty());
    assert!(c.punt.is_none());
    assert_eq!(c.inner_mtu(), up4_wire::INNER_MTU_V4);
}

#[test]
fn full_config_round_trips_into_the_domain_model() {
    let c = cfg(
        r#"fabric = "ipv6"
threads = 2
pin_cores = [2, 3]
metrics_interval_s = 0
"#,
        "[[vport]]\nid = 0\npeer = \"10.0.0.12:7400\"\n\
         [[vport]]\nid = 7\npeer = \"10.0.0.13:7400\"\n\
         [punt]\nvport = 65535\n",
    )
    .expect("valid");
    assert_eq!(c.node.fabric, Fabric::V6);
    assert_eq!(c.inner_mtu(), up4_wire::INNER_MTU_V6);
    assert_eq!(c.node.threads.get(), 2);
    assert_eq!(&*c.node.pin_cores, &[2, 3]);
    assert_eq!(c.node.metrics_interval, None, "0 disables snapshots");
    assert_eq!(c.vports.len(), 2);
    assert!(c.punt.is_some());

    let idx = c.vports.idx_of_id(7).expect("vport 7 exists");
    assert_eq!(
        c.vports.get(idx).peer,
        "10.0.0.13:7400".parse().expect("literal")
    );
    assert_eq!(
        c.vports
            .idx_of_peer(&"10.0.0.12:7400".parse().expect("literal")),
        c.vports.idx_of_id(0)
    );
    assert_eq!(c.vports.idx_of_id(1), None, "unconfigured id has no slot");
    assert_eq!(c.vports.idx_of_id(65535), None, "punt id is never a vport");
}

#[test]
fn rejects_bad_scalars_and_lists_all_of_them() {
    let src = r#"
[node]
id = ""
bind = "nope"
fabric = "ipv5"
pipeline = "missing"
threads = 99
ctl_socket = ""

[[vport]]
id = 65535
peer = "also-nope"
"#;
    let found = errors(Config::from_toml(src, REGISTRY));
    assert!(found.contains(&ConfigError::EmptyNodeId), "{found:?}");
    assert!(
        found.contains(&ConfigError::Bind {
            value: "nope".into()
        }),
        "{found:?}"
    );
    assert!(
        found.contains(&ConfigError::Fabric {
            value: "ipv5".into()
        }),
        "{found:?}"
    );
    assert!(
        found.contains(&ConfigError::Threads { value: 99 }),
        "{found:?}"
    );
    assert!(found.contains(&ConfigError::EmptyCtlSocket), "{found:?}");
    assert!(
        found.contains(&ConfigError::VportId { value: 65535 }),
        "{found:?}"
    );
    assert!(
        found.contains(&ConfigError::Peer {
            vport: 65535,
            value: "also-nope".into()
        }),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|e| matches!(e, ConfigError::UnknownPipeline { value, .. } if value == "missing")),
        "{found:?}"
    );
    assert_eq!(
        found.len(),
        8,
        "every violation is reported, not just the first: {found:?}"
    );
}

#[test]
fn rejects_duplicate_vport_id() {
    let found = errors(cfg(
        "",
        "[[vport]]\nid = 3\npeer = \"10.0.0.12:7400\"\n\
         [[vport]]\nid = 3\npeer = \"10.0.0.13:7400\"\n",
    ));
    assert_eq!(found, vec![ConfigError::DuplicateVportId { value: 3 }]);
}

#[test]
fn rejects_duplicate_peer_tuple() {
    let found = errors(cfg(
        "",
        "[[vport]]\nid = 0\npeer = \"10.0.0.12:7400\"\n\
         [[vport]]\nid = 1\npeer = \"10.0.0.12:7400\"\n",
    ));
    assert_eq!(
        found,
        vec![ConfigError::DuplicatePeer {
            value: "10.0.0.12:7400".into(),
            first: 0,
            second: 1
        }]
    );
}

#[test]
fn rejects_peer_pointing_at_self() {
    let found = errors(cfg("", "[[vport]]\nid = 0\npeer = \"10.0.0.11:7400\"\n"));
    assert_eq!(
        found,
        vec![ConfigError::PeerIsSelf {
            vport: 0,
            value: "10.0.0.11:7400".into()
        }]
    );
}

#[test]
fn rejects_topology_with_no_vports() {
    assert_eq!(errors(cfg("", "")), vec![ConfigError::NoVports]);
}

#[test]
fn rejects_punt_vport_other_than_the_reserved_id() {
    let found = errors(cfg("", &format!("{}[punt]\nvport = 4\n", one_vport())));
    assert_eq!(
        found,
        vec![ConfigError::PuntVport {
            value: 4,
            reserved: up4_wire::PUNT_VPORT
        }]
    );
}

#[test]
fn rejects_pin_cores_that_do_not_match_thread_count() {
    let found = errors(cfg("threads = 2\npin_cores = [1]\n", one_vport()));
    assert_eq!(
        found,
        vec![ConfigError::PinCoresArity {
            given: 1,
            threads: 2
        }]
    );
}

#[test]
fn rejects_negative_core_id() {
    let found = errors(cfg("pin_cores = [-1]\n", one_vport()));
    assert_eq!(found, vec![ConfigError::NegativeCore { value: -1 }]);
}

#[test]
fn rejects_unknown_field_rather_than_ignoring_it() {
    let found = errors(cfg("thread = 2\n", one_vport()));
    assert!(
        matches!(found.as_slice(), [ConfigError::Toml(m)] if m.contains("thread")),
        "{found:?}"
    );
}

#[test]
fn rejects_malformed_toml_without_pretending_to_check_more() {
    let found = errors(Config::from_toml("[node", REGISTRY));
    assert!(
        matches!(found.as_slice(), [ConfigError::Toml(_)]),
        "{found:?}"
    );
}

#[test]
fn error_display_lists_every_violation() {
    let e = cfg("threads = 0\n", "").expect_err("invalid");
    let text = e.to_string();
    assert!(text.contains("2 configuration error(s)"), "{text}");
    assert!(text.contains("node.threads 0"), "{text}");
    assert!(text.contains("[[vport]]"), "{text}");
}

#[test]
fn refined_types_have_no_illegal_inhabitants() {
    assert_eq!(VportId::new(up4_wire::PUNT_VPORT), None);
    assert!(VportId::new(65534).is_some());
    assert_eq!(Threads::new(0), None);
    assert_eq!(Threads::new(17), None);
    assert!(Threads::new(16).is_some());
    assert_eq!(Fabric::from_config_str("IPv4"), None, "spelling is exact");
}
