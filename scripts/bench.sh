#!/usr/bin/env bash
# Loopback benchmark: a release `mjolnir recv` and `mjolnir send` as two
# processes on 127.0.0.1, one random file, several connection counts, chunk
# sizes, and both ciphers. Every run's output is checked with SHA-256.
#
# usage: scripts/bench.sh [WORKDIR]
#   SIZE_MIB  file size in MiB (default 2048)
#   REPEAT    runs per configuration; the table shows the median (default 3)
#   PORT      listen port (default 7799)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="${1:-$root/target/bench}"
size_mib="${SIZE_MIB:-2048}"
repeat="${REPEAT:-3}"
port="${PORT:-7799}"

cargo build --release --quiet --manifest-path "$root/Cargo.toml"
bin="$root/target/release/mjolnir"
[ -x "$bin" ] || bin="$bin.exe"

mkdir -p "$work"
src="$work/random-${size_mib}MiB.bin"
if [ ! -f "$src" ] || [ "$(wc -c < "$src")" -ne $((size_mib << 20)) ]; then
  echo "writing $size_mib MiB of random data to $src" >&2
  head -c $((size_mib << 20)) /dev/urandom > "$src"
fi
want="$(sha256sum "$src" | cut -d' ' -f1)"

rm -f "$work/s.key" "$work/r.key"
spub="$("$bin" keygen --out "$work/s.key" 2>/dev/null)"
rpub="$("$bin" keygen --out "$work/r.key" 2>/dev/null)"

# One transfer; prints the sender's MiB/s.
run_once() {
  local n="$1" chunk="$2" cipher="$3"
  local out="$work/out"
  rm -rf "$out" && mkdir -p "$out"
  "$bin" recv --key "$work/r.key" --allow "$spub" --listen "127.0.0.1:$port" \
    --out "$out" 2> "$work/recv.log" &
  local rpid=$!
  for _ in $(seq 100); do
    grep -q "listening on" "$work/recv.log" 2>/dev/null && break
    sleep 0.05
  done
  "$bin" send "127.0.0.1:$port" --key "$work/s.key" --peer "$rpub" \
    -n "$n" -c "$chunk" --cipher "$cipher" "$src" 2> "$work/send.log"
  wait "$rpid"
  local got
  got="$(sha256sum "$out/$(basename "$src")" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    echo "SHA-256 mismatch for -n $n -c $chunk --cipher $cipher" >&2
    exit 1
  fi
  sed -n 's/^sent .* s, \([0-9.]*\) MiB\/s.*/\1/p' "$work/send.log"
}

median() { sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }

echo "| connections | chunk | cipher | MiB/s (median of $repeat) |"
echo "|---|---|---|---|"
bench() {
  local rates
  rates="$(for _ in $(seq "$repeat"); do run_once "$@"; done)"
  echo "| $1 | $2 | $3 | $(echo "$rates" | median) |"
}
for n in 1 4 8 16; do bench "$n" 1MiB aes256gcm; done
for chunk in 4K 16K 256K 4MiB; do bench 8 "$chunk" aes256gcm; done
bench 8 1MiB chacha20poly1305
rm -rf "$work/out"
echo "all outputs matched SHA-256 $want" >&2
