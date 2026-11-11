#!/usr/bin/env bash
# Differential accuracy check between two CopperHound builds on the same input.
#
#   scripts/accuracy-diff.sh OLD_BIN NEW_BIN INPUT [WORKDIR]
#
# OLD_BIN / NEW_BIN: copperhound executables (e.g. a build of main and of your
# branch, built with separate CARGO_TARGET_DIRs). INPUT: a collector dump
# (directory, zip, LDIF ...) both versions can read; generate one with
# `OLD_BIN synth -o DIR --users 500000 --seed 11` so new synth features do not
# leak into the input.
#
# Steps:
#   1. ingest INPUT with both binaries;
#   2. compare node and edge sets per kind (order-independent hashes, via
#      `cargo run --example ch_dump`, which reads both graph formats);
#   3. run tier0 / plan / findings with each binary on its own graph, and with
#      NEW_BIN on a copy of OLD_BIN's graph. The last comparison isolates
#      analysis changes from ingest changes and must be exactly equal
#      (timings stripped).
# Exit status 1 when anything differs; differing edge kinds are dumped as
# sorted TSV under WORKDIR for inspection.
set -u
OLD=$1 NEW=$2 IN=$3 W=${4:-$(mktemp -d)}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$W"
rm -rf "$W/old" "$W/new" "$W/iso"
"$OLD" ingest "$IN" -o "$W/old" >/dev/null 2>&1 || { echo "old ingest failed"; exit 2; }
"$NEW" ingest "$IN" -o "$W/new" >/dev/null 2>&1 || { echo "new ingest failed"; exit 2; }
cp -r "$W/old" "$W/iso"

dump() { cargo run -q --release --manifest-path "$ROOT/Cargo.toml" -p ch-store --example ch_dump -- "$@"; }
status=0
dump "$W/old" summary >"$W/old.summary"
dump "$W/new" summary >"$W/new.summary"
if ! diff "$W/old.summary" "$W/new.summary" >"$W/summary.diff"; then
  status=1
  echo "== graph differs (count / set hash per kind):"
  cat "$W/summary.diff"
  kinds=$(grep -h '^[<>] edge' "$W/summary.diff" | cut -f2 | sort -u | paste -sd, -)
  if [ -n "$kinds" ]; then
    dump "$W/old" edges "$W/old.edges" "$kinds"
    dump "$W/new" edges "$W/new.edges" "$kinds"
    echo "== edge differences (< old, > new), first 40:"
    diff "$W/old.edges" "$W/new.edges" | head -40
  fi
else
  echo "== graph: identical node and edge sets"
fi

strip() { sed -E -e 's/ in [0-9.]+ ?m?s//' -e 's/\([0-9.]+m?s\)//' -e '/"seconds"/d'; }
for cmd in "tier0 --json --top 50" "plan --steps 10" "findings --json"; do
  name=${cmd%% *}
  $OLD $cmd "$W/old" 2>/dev/null | strip >"$W/$name.old"
  $NEW $cmd "$W/new" 2>/dev/null | strip >"$W/$name.new"
  $NEW $cmd "$W/iso" 2>/dev/null | strip >"$W/$name.iso"
  if cmp -s "$W/$name.old" "$W/$name.iso"; then
    echo "== $name: new code on the old graph is identical"
  else
    status=1
    echo "== $name: new code on the OLD graph differs (analysis change):"
    diff "$W/$name.old" "$W/$name.iso" | head -40
  fi
  cmp -s "$W/$name.old" "$W/$name.new" || echo "   ($name differs on the new graph: expected only if the graph differs)"
done
echo "workdir: $W"
exit $status
