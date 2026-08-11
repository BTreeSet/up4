//! Command handling, exercised through the real socket and through [`handle`]
//! directly where a socket would only add noise.

use crate::{
    Client, Context, EntrySpec, Params, Request, Response, Server, protocol::Info, server::handle,
};
use std::{collections::BTreeMap, sync::Arc};
use up4_config::Config;
use up4_engine::{Pipeline, PipelineParams};
use up4_io::{PuntQueue, Stop, clock};
use up4_metrics::Metrics;

const CONFIG: &str = r#"
[node]
id = "a"
bind = "127.0.0.1:7400"
pipeline = "l3fwd"
ctl_socket = "/tmp/up4-ctl-test.sock"
[[vport]]
id = 0
peer = "127.0.0.1:7401"
[[vport]]
id = 1
peer = "127.0.0.1:7402"
[punt]
vport = 65535
"#;

fn context(punt: bool) -> Arc<Context> {
    let cfg = Config::from_toml(CONFIG, &up4_engine::names()).expect("fixture config");
    let pipeline: Arc<dyn Pipeline> =
        Arc::from(up4_engine::build("l3fwd", &PipelineParams::new([0, 1])).expect("registered"));
    let metrics = Arc::new(Metrics::new(&cfg.node.id, &cfg.vports));
    Arc::new(Context {
        info: Info {
            node: cfg.node.id.clone(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            pipeline: "l3fwd".to_owned(),
            pipeline_summary: "test".to_owned(),
            uptime_s: 0,
            threads: 1,
            fabric: "ipv4".to_owned(),
            inner_mtu: 1460,
            bind: cfg.node.bind.to_string(),
            punt_enabled: punt,
            vports: Vec::new(),
            probe: serde_json::Value::Null,
        },
        started_us: clock::monotonic_us(),
        metrics,
        pipeline,
        punt: punt.then(|| Arc::new(PuntQueue::with_depth(4, 1460))),
        stop: Stop::new(),
    })
}

fn add(table: &str, key: &str, action: &str, params: &[&str]) -> Request {
    Request::TableAdd {
        entries: vec![EntrySpec {
            table: table.to_owned(),
            key: key.to_owned(),
            action: action.to_owned(),
            params: Params::from_args(&params.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()),
        }],
    }
}

#[test]
fn ping_and_info_answer_without_touching_the_pipeline() {
    let ctx = context(true);
    assert_eq!(handle(&ctx, Request::Ping), Response::Pong);
    let Response::Info(info) = handle(&ctx, Request::Info) else {
        panic!("info replies with info");
    };
    assert_eq!(info.node, "a");
    assert_eq!(info.pipeline, "l3fwd");
    assert!(info.punt_enabled);
}

#[test]
fn tables_describes_what_to_type() {
    let ctx = context(true);
    let Response::Tables { tables: schemas } = handle(&ctx, Request::Tables) else {
        panic!("tables replies with schemas");
    };
    assert_eq!(schemas.len(), 1);
    assert_eq!(schemas[0].name, "ipv4_lpm");
    assert_eq!(schemas[0].key_field, "ipv4.dst");
    let forward = schemas[0]
        .actions
        .iter()
        .find(|a| a.name == "forward")
        .expect("declared");
    assert_eq!(
        forward
            .params
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["port", "dmac"]
    );
}

#[test]
fn a_route_can_be_added_dumped_and_removed_by_name_or_position() {
    let ctx = context(true);
    assert_eq!(
        handle(
            &ctx,
            add(
                "ipv4_lpm",
                "10.0.0.0/24",
                "forward",
                &["port=1", "dmac=aa:bb:cc:dd:ee:01"]
            )
        ),
        Response::Applied { count: 1 }
    );
    assert_eq!(
        handle(
            &ctx,
            add(
                "ipv4_lpm",
                "10.0.1.0/24",
                "forward",
                &["0", "aa:bb:cc:dd:ee:02"]
            )
        ),
        Response::Applied { count: 1 },
        "positional parameters mean the same thing"
    );

    let Response::Entries { entries, default } = handle(
        &ctx,
        Request::TableDump {
            table: "ipv4_lpm".into(),
        },
    ) else {
        panic!("dump replies with entries");
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].params["port"], "1");
    assert_eq!(default.action, "drop");

    assert_eq!(
        handle(
            &ctx,
            Request::TableDel {
                table: "ipv4_lpm".into(),
                key: "10.0.0.0/24".into()
            }
        ),
        Response::Applied { count: 1 }
    );
    assert_eq!(
        handle(
            &ctx,
            Request::TableClear {
                table: "ipv4_lpm".into()
            }
        ),
        Response::Applied { count: 1 }
    );
}

#[test]
fn a_batch_reports_which_entry_failed_and_how_far_it_got() {
    let ctx = context(true);
    let entries = vec![
        EntrySpec {
            table: "ipv4_lpm".into(),
            key: "10.0.0.0/24".into(),
            action: "drop".into(),
            params: Params::default(),
        },
        EntrySpec {
            table: "ipv4_lpm".into(),
            key: "not-an-address".into(),
            action: "drop".into(),
            params: Params::default(),
        },
    ];
    let Response::Error { message } = handle(&ctx, Request::TableAdd { entries }) else {
        panic!("a malformed key is refused");
    };
    assert!(message.contains("entry 1"), "{message}");
    assert!(message.contains("1 of 2 applied"), "{message}");
}

#[test]
fn refusals_name_the_alternatives() {
    let ctx = context(true);
    let cases = [
        (add("nope", "10.0.0.0/24", "drop", &[]), "ipv4_lpm"),
        (add("ipv4_lpm", "10.0.0.0/24", "teleport", &[]), "forward"),
        (
            add("ipv4_lpm", "10.0.0.0/24", "forward", &["port=1"]),
            "2 parameter",
        ),
        (
            add(
                "ipv4_lpm",
                "10.0.0.0/24",
                "forward",
                &["port=1", "mac=aa:bb:cc:dd:ee:01"],
            ),
            "dmac",
        ),
        (add("ipv4_lpm", "10.0.0.0/99", "drop", &[]), "10.0.0.0/99"),
    ];
    for (request, expected) in cases {
        let Response::Error { message } = handle(&ctx, request.clone()) else {
            panic!("{request:?} must be refused");
        };
        assert!(
            message.contains(expected),
            "{message:?} should mention {expected:?}"
        );
    }
}

#[test]
fn the_default_action_is_settable() {
    let ctx = context(true);
    assert_eq!(
        handle(
            &ctx,
            Request::TableSetDefault {
                table: "ipv4_lpm".into(),
                action: "punt".into(),
                params: Params::default(),
            }
        ),
        Response::Applied { count: 1 }
    );
    let Response::Entries { default, .. } = handle(
        &ctx,
        Request::TableDump {
            table: "ipv4_lpm".into(),
        },
    ) else {
        panic!("dump replies with entries");
    };
    assert_eq!(default.action, "punt");
}

#[test]
fn punt_drain_returns_frames_and_says_what_is_left() {
    let ctx = context(true);
    let queue = ctx.punt.as_ref().expect("punt configured");
    for i in 0..3u8 {
        assert!(queue.push(&[i, i, i], 1, 42));
    }
    let Response::Punted { frames, remaining } = handle(&ctx, Request::PuntDrain { max: 2 }) else {
        panic!("drain replies with frames");
    };
    assert_eq!(frames.len(), 2);
    assert_eq!(remaining, 1);
    assert_eq!(frames[0].ingress_vport, 1);
    assert_eq!(frames[0].rx_ts_us, 42);
    assert_eq!(
        crate::b64::decode(&frames[0].frame_b64),
        Some(vec![0, 0, 0])
    );
}

#[test]
fn punt_drain_on_a_node_without_punt_says_so() {
    let ctx = context(false);
    let Response::Error { message } = handle(&ctx, Request::PuntDrain { max: 8 }) else {
        panic!("without a queue there is nothing to drain");
    };
    assert!(message.contains("[punt]"), "{message}");
}

#[test]
fn a_pipeline_without_tables_refuses_table_commands_by_name() {
    let cfg = Config::from_toml(
        &CONFIG.replace("pipeline = \"l3fwd\"", "pipeline = \"l2fwd\""),
        &up4_engine::names(),
    )
    .expect("fixture config");
    assert_eq!(cfg.node.pipeline, "l2fwd");
    let ctx = context(true);
    let Response::Error { message } = handle(
        &ctx,
        Request::TableDump {
            table: "mac_dst".into(),
        },
    ) else {
        panic!("l3fwd has no mac_dst table");
    };
    assert!(message.contains("ipv4_lpm"), "{message}");
}

#[test]
fn shutdown_sets_the_stop_flag_and_answers_first() {
    let ctx = context(true);
    assert!(!ctx.stop.requested());
    assert_eq!(handle(&ctx, Request::Shutdown), Response::ShuttingDown);
    assert!(ctx.stop.requested());
}

#[test]
fn the_socket_carries_the_same_commands_and_is_private() {
    let dir = std::env::temp_dir().join(format!("up4-ctl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let path = dir.join("ctl.sock");
    let ctx = context(true);
    let server = Server::bind(&path, Arc::clone(&ctx)).expect("bind");
    let stop = Stop::new();

    let serving = {
        let stop = stop.clone();
        std::thread::spawn(move || server.serve(&stop).expect("serve"))
    };

    // Mode 0600: the filesystem is the authorization boundary (spec S8.1).
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path)
        .expect("socket exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode was {mode:o}");

    let mut client = Client::connect(&path).expect("connect");
    assert_eq!(client.call(&Request::Ping).expect("ping"), Response::Pong);
    assert_eq!(
        client
            .call(&add(
                "ipv4_lpm",
                "10.0.0.0/24",
                "forward",
                &["port=1", "dmac=aa:bb:cc:dd:ee:01"]
            ))
            .expect("add"),
        Response::Applied { count: 1 }
    );
    let Response::Entries { entries, .. } = client
        .call(&Request::TableDump {
            table: "ipv4_lpm".into(),
        })
        .expect("dump")
    else {
        panic!("dump replies with entries");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, "10.0.0.0/24");

    let Response::Counters(snapshot) = client.call(&Request::Counters).expect("counters") else {
        panic!("counters replies with a snapshot");
    };
    assert_eq!(snapshot.node, "a");
    assert_eq!(snapshot.harness_drops, 0);

    drop(client);
    stop.request();
    serving.join().expect("server thread");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_thousand_routes_load_in_one_batch() {
    let ctx = context(true);
    let entries: Vec<EntrySpec> = (0..1000u32)
        .map(|i| EntrySpec {
            table: "ipv4_lpm".into(),
            key: format!("{}/24", std::net::Ipv4Addr::from(0x0a00_0000 | (i << 8))),
            action: "forward".into(),
            params: Params::Named(BTreeMap::from([
                ("port".into(), (i % 2).to_string()),
                ("dmac".into(), "aa:bb:cc:dd:ee:01".into()),
            ])),
        })
        .collect();
    assert_eq!(
        handle(&ctx, Request::TableAdd { entries }),
        Response::Applied { count: 1000 }
    );
    let Response::Entries { entries, .. } = handle(
        &ctx,
        Request::TableDump {
            table: "ipv4_lpm".into(),
        },
    ) else {
        panic!("dump replies with entries");
    };
    assert_eq!(entries.len(), 1000);
}
