#!/usr/bin/env bash
# Loopback benchmark: a release `mjolnir recv` and `mjolnir send` as two
# processes on 127.0.0.1, one random file, several connection counts, worker
# counts, chunk sizes, and both ciphers. Every run's output is checked with
# SHA-256. On Windows the CPU column is the machine-wide average of
# `\Processor(_Total)\% Processor Time` sampled by typeperf during the send.
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
have_typeperf=false
command -v typeperf > /dev/null 2>&1 && have_typeperf=true

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

# One transfer; prints "<sender MiB/s> <average CPU %>".
run_once() {
  local n="$1" threads="$2" chunk="$3" cipher="$4" verify="$5"
  local out="$work/out" recv_flags=()
  [ "$verify" = off ] && recv_flags+=(--no-verify)
  rm -rf "$out" && mkdir -p "$out"
  "$bin" recv --key "$work/r.key" --allow "$spub" --listen "127.0.0.1:$port" \
    --out "$out" --threads "$threads" "${recv_flags[@]}" 2> "$work/recv.log" &
  local rpid=$!
  for _ in $(seq 100); do
    grep -q "listening on" "$work/recv.log" 2>/dev/null && break
    sleep 0.05
  done
  if $have_typeperf; then
    typeperf '\Processor(_Total)\% Processor Time' -si 1 > "$work/cpu.txt" 2>&1 &
  fi
  "$bin" send "127.0.0.1:$port" --key "$work/s.key" --peer "$rpub" \
    -n "$n" --threads "$threads" -c "$chunk" --cipher "$cipher" "$src" 2> "$work/send.log"
  wait "$rpid"
  local cpu="-"
  if $have_typeperf; then
    taskkill //F //IM typeperf.exe > /dev/null 2>&1 || true
    wait 2> /dev/null || true
    cpu="$(tr -d '\r' < "$work/cpu.txt" | grep '^"[0-9]' | cut -d, -f2 | tr -d '"' |
      awk 'NF { s += $1; c++ } END { if (c) printf "%.0f", s / c; else print "-" }')"
  fi
  local got
  got="$(sha256sum "$out/$(basename "$src")" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    echo "SHA-256 mismatch for -n $n --threads $threads -c $chunk --cipher $cipher" >&2
    exit 1
  fi
  echo "$(sed -n 's/^sent .* s, \([0-9.]*\) MiB\/s.*/\1/p' "$work/send.log") $cpu"
}

median() { sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }

echo "| connections | threads | chunk | cipher | verify | MiB/s (median of $repeat) | CPU % |"
echo "|---|---|---|---|---|---|---|"
bench() {
  local runs
  runs="$(for _ in $(seq "$repeat"); do run_once "$@"; done)"
  local rate cpu
  rate="$(echo "$runs" | cut -d' ' -f1 | median)"
  cpu="$(echo "$runs" | cut -d' ' -f2 | median)"
  local threads="$2"
  [ "$threads" = 0 ] && threads=auto
  echo "| $1 | $threads | $3 | $4 | $5 | $rate | $cpu |"
}
for n in 1 4 8 16; do bench "$n" 0 1MiB aes256gcm on; done
for chunk in 4K 16K 256K 4MiB; do bench 8 0 "$chunk" aes256gcm on; done
bench 8 0 1MiB chacha20poly1305 on
bench 8 0 1MiB aes256gcm off
for cipher in aes256gcm chacha20poly1305; do
  for n in 1 2; do
    for threads in 1 4 16 32; do bench "$n" "$threads" 1MiB "$cipher" on; done
  done
done
rm -rf "$work/out"
echo "all outputs matched SHA-256 $want" >&2
