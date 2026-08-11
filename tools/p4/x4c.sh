#!/usr/bin/env bash
#
# Run Oxide's x4c over up4's SoftNPU-bound P4 sources.
#
#   tools/p4/x4c.sh check          type-check only; the CI gate
#   tools/p4/x4c.sh generate DIR   emit Rust into DIR
#
# x4c resolves `#include <...>` relative to the source file's own directory and
# offers no include path, so each program is staged into a scratch directory
# beside the vendored architecture model before it is compiled. That staging is
# the only reason this is a script and not a one-line invocation.
#
# x4c is not on crates.io and is not vendored here; it is cloned and built on
# demand. UP4_X4C may point at an existing binary to skip that.
set -euo pipefail

cd "$(dirname "$0")/../.."
readonly ROOT=$PWD
readonly PROGRAMS=(l2fwd l3fwd)
readonly X4C_REPO=${UP4_X4C_REPO:-https://github.com/oxidecomputer/p4}

mode=${1:-check}
outdir=${2:-}

# --- obtain x4c -------------------------------------------------------------
if [[ -n ${UP4_X4C:-} && -x ${UP4_X4C} ]]; then
    x4c=$UP4_X4C
else
    work=${UP4_X4C_WORK:-${TMPDIR:-/tmp}/up4-x4c}
    x4c=$work/target/release/x4c
    if [[ ! -x $x4c ]]; then
        echo "==> building x4c (set UP4_X4C to reuse a binary)" >&2
        rm -rf "$work"
        git clone -q --depth 1 "$X4C_REPO" "$work"
        # x4c pins an older toolchain than up4 does; it builds fine on ours,
        # and pinning two toolchains in one CI job is not worth the minutes.
        rm -f "$work/rust-toolchain.toml"
        (cd "$work" && cargo build --release -p x4c)
    fi
fi
echo "==> x4c: $x4c" >&2

# --- stage and compile ------------------------------------------------------
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$ROOT"/p4/include/softnpu/*.p4 "$stage"/

status=0
for prog in "${PROGRAMS[@]}"; do
    src=$prog.softnpu.p4
    cp "$ROOT/p4/programs/$prog/$src" "$stage/"
    case $mode in
    check)
        printf '%-6s ' "$prog"
        if (cd "$stage" && "$x4c" --check "$src"); then
            echo "ok"
        else
            echo "::error file=p4/programs/$prog/$src::x4c rejected this source"
            status=1
        fi
        ;;
    generate)
        [[ -n $outdir ]] || { echo "generate needs an output directory" >&2; exit 2; }
        mkdir -p "$outdir"
        (cd "$stage" && "$x4c" "$src" -o "$prog.rs")
        # Drop x4c's `_main_pipeline_create` shim. It exists so SoftNPU can
        # dlopen a pipeline as a shared object, and it is `#[no_mangle]`, so
        # two programs in one crate collide on the symbol. up4 links the
        # generated code statically and constructs `main_pipeline::new()`
        # directly, so the shim is unreachable here as well as unbuildable.
        awk '/^#\[unsafe\(no_mangle\)\]$/ {skip = 1} skip && /^}$/ {skip = 0; next} !skip' \
            "$stage/$prog.rs" >"$outdir/$prog.rs"
        rm -f "$stage/$prog.rs"
        # Format on generation, not after. `cargo fmt --check` covers the whole
        # workspace, and hand-formatting generated code would make it differ
        # from what the generator emits, which is exactly what the
        # regenerate-and-diff check exists to detect. x4c and rustfmt are both
        # pinned, so this stays deterministic.
        rustfmt --edition 2024 "$outdir/$prog.rs"
        echo "$outdir/$prog.rs: $(wc -l <"$outdir/$prog.rs") lines"
        ;;
    *)
        echo "usage: $0 {check|generate DIR}" >&2
        exit 2
        ;;
    esac
done
exit $status
