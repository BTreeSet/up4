#!/usr/bin/env bash
# Two up4 routers and two traffic generators on loopback, as an ordinary user.
#
#   pktgen w <--> node a <--> node b <--> pktgen e
#    :7501   vp0  :7401  vp1   vp1 :7402  vp0  :7502
#
# Generator w sources 10.0.1.1 -> 10.0.2.1 and generator e the reverse, so
# every frame crosses both routers and arrives at the far generator, which
# checks it. Brings the topology up, runs both directions at once, prints the
# counters, and shuts down cleanly. Used by CI as a smoke test and by hand as
# the shortest path to a running switch.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${UP4_BIN:-$root/target/release}"
run="$(mktemp -d)"
trap 'set +e; [[ -n "${a_pid:-}" ]] && kill "$a_pid" 2>/dev/null; [[ -n "${b_pid:-}" ]] && kill "$b_pid" 2>/dev/null; wait 2>/dev/null; rm -rf "$run"' EXIT


na=127.0.0.1:7401   # node a fabric address
nb=127.0.0.1:7402   # node b fabric address
pa=127.0.0.1:7501   # generator, a peer of node a
pb=127.0.0.1:7502   # node b's far side, a peer of node b

node_config() {
  local id=$1 bind=$2 peer0=$3 peer1=$4
  cat >"$run/$id.toml" <<EOF
[node]
id       = "$id"
bind     = "$bind"
fabric   = "ipv4"
pipeline = "l3fwd"
threads  = 1
ctl_socket = "$run/$id.sock"
metrics_interval_s = 0

[[vport]]
id   = 0
peer = "$peer0"

[[vport]]
id   = 1
peer = "$peer1"

[punt]
vport = 65535
EOF
}

routes() {
  local to_b=$1 to_a=$2
  cat <<EOF
{"entries": [
  {"table":"ipv4_lpm","key":"10.0.2.0/24","action":"forward",
   "params":{"port":"$to_b","dmac":"02:00:00:00:00:02"}},
  {"table":"ipv4_lpm","key":"10.0.1.0/24","action":"forward",
   "params":{"port":"$to_a","dmac":"02:00:00:00:00:01"}}
]}
EOF
}

node_config a "$na" "$pa" "$nb"
node_config b "$nb" "$pb" "$na"
routes 1 0 >"$run/a-routes.json"
routes 0 1 >"$run/b-routes.json"

echo "== starting two routers =="
"$bin/up4d" --config "$run/a.toml" --tables "$run/a-routes.json" --metrics-dir "$run" &
a_pid=$!
"$bin/up4d" --config "$run/b.toml" --tables "$run/b-routes.json" --metrics-dir "$run" &
b_pid=$!

for id in a b; do
  for _ in $(seq 100); do
    "$bin/up4ctl" --socket "$run/$id.sock" ping >/dev/null 2>&1 && break
    sleep 0.1
  done
  "$bin/up4ctl" --socket "$run/$id.sock" ping >/dev/null
done
echo "both nodes up"

echo
echo "== node a: what it is running =="
"$bin/up4ctl" --socket "$run/a.sock" info
echo
echo "== node a: what its tables accept =="
"$bin/up4ctl" --socket "$run/a.sock" tables
echo
echo "== node a: installed routes =="
"$bin/up4ctl" --socket "$run/a.sock" table dump ipv4_lpm

echo
echo "== traffic: both directions at once, each frame across both routers =="
"$bin/pktgen" \
  --bind "$pb" --target "$nb" \
  --frame-size 1460 --rate-pps 20000 --flows 4 --duration 3 \
  --src-ip 10.0.2.1 --dst-ip 10.0.1.1 >"$run/east.txt" &
east_pid=$!
echo "-- west to east --"
"$bin/pktgen" \
  --bind "$pa" --target "$na" \
  --frame-size 1460 --rate-pps 20000 --flows 4 --duration 3 \
  --src-ip 10.0.1.1 --dst-ip 10.0.2.1
wait "$east_pid"
echo "-- east to west --"
cat "$run/east.txt"

echo
for id in a b; do
  echo "== node $id counters =="
  "$bin/up4ctl" --socket "$run/$id.sock" counters
  drops=$("$bin/up4ctl" --socket "$run/$id.sock" counters --json \
    | tr -d ' ' | grep -o '"harness_drops":[0-9]*' | cut -d: -f2)
  if [[ "$drops" != "0" ]]; then
    echo "FAIL: node $id reported $drops harness drops"
    exit 1
  fi
  echo
done

echo "== shutting down =="
for id in a b; do
  "$bin/up4ctl" --socket "$run/$id.sock" shutdown
done
wait "$a_pid"; a_status=$?
wait "$b_pid"; b_status=$?
a_pid= b_pid=
[[ $a_status -eq 0 && $b_status -eq 0 ]] || { echo "FAIL: exit codes $a_status/$b_status"; exit 1; }
echo "both nodes exited 0: zero harness drops on either"
