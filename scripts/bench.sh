#!/usr/bin/env bash
# Loopback benchmark: a release `mjolnir recv` and `mjolnir send` as two
# processes on 127.0.0.1 with one random file. Rows sweep connection
# counts, worker counts, chunk sizes, both ciphers, verification, the hash
# check, and two no-disk modes (MJOLNIR_BENCH, see src/benchmode.rs):
#   discard  the receiver drops plaintext instead of writing it
#   memory   the sender serves chunks from a copy of the file in memory
# Every disk-writing run's output is checked with SHA-256. Each row also
# records both processes' CPU time (in cores busy on average) and the
# receiver's time per phase; on Windows, typeperf adds machine-wide CPU.
#
# usage: scripts/bench.sh [WORKDIR]
#   SIZE_MIB  file size in MiB (default 2048)
#   REPEAT    runs per configuration; rates show median and range (default 3)
#   PORT      listen port (default 7799)
#   ROWS      only run rows whose "connections threads chunk cipher verify
#             hash mode" matches this extended regex, e.g. ROWS='^8 0 1MiB'
set -euo pipefail
# Git Bash on Windows rewrites arguments that start with '/' into Windows
# paths, and a base64 key can start with '/'.
export MSYS_NO_PATHCONV=1

root="$(cd "$(dirname "$0")/.." && { pwd -W 2> /dev/null || pwd; })"
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

cores() { sed -n 's/^cpu .* s, \([0-9.]*\) cores busy.*/\1/p' "$1"; }
transfer_rate() { sed -n 's/^transfer [0-9.]* s (\([0-9]*\) MiB\/s).*/\1/p' "$1"; }

# One transfer; prints "<MiB/s> <receiver transfer-phase MiB/s> <sender cores>
# <receiver cores> <machine CPU %>" and leaves both sides' phase lines in
# $work/phases.
run_once() {
  local n="$1" threads="$2" chunk="$3" cipher="$4" verify="$5" hash="$6" mode="$7"
  local out="$work/out" recv_flags=() send_flags=() recv_env="" send_env=""
  [ "$verify" = off ] && recv_flags+=(--no-verify)
  [ "$hash" = on ] && send_flags+=(--hash)
  case "$mode" in
    discard) recv_env=discard ;;
    memory) send_env=memory-source ;;
    memory+discard) recv_env=discard send_env=memory-source ;;
  esac
  rm -rf "$out" && mkdir -p "$out"
  MJOLNIR_BENCH="$recv_env" "$bin" recv --key "$work/r.key" --allow "$spub" \
    --listen "127.0.0.1:$port" --out "$out" --threads "$threads" "${recv_flags[@]}" \
    2> "$work/recv.log" &
  local rpid=$!
  for _ in $(seq 100); do
    grep -q "listening on" "$work/recv.log" 2>/dev/null && break
    sleep 0.05
  done
  if $have_typeperf; then
    typeperf '\Processor(_Total)\% Processor Time' -si 1 > "$work/cpu.txt" 2>&1 &
  fi
  if ! MJOLNIR_BENCH="$send_env" "$bin" send "127.0.0.1:$port" --key "$work/s.key" \
    --peer "$rpub" -n "$n" --threads "$threads" -c "$chunk" --cipher "$cipher" \
    "${send_flags[@]}" "$src" 2> "$work/send.log"; then
    kill "$rpid" 2> /dev/null || true
    cat "$work/send.log" >&2
    exit 1
  fi
  wait "$rpid"
  local cpu="-"
  if $have_typeperf; then
    taskkill /F /IM typeperf.exe > /dev/null 2>&1 || true
    wait 2> /dev/null || true
    cpu="$(tr -d '\r' < "$work/cpu.txt" | grep '^"[0-9]' | cut -d, -f2 | tr -d '"' |
      awk 'NF { s += $1; c++ } END { if (c) printf "%.0f", s / c; else print "-" }')"
  fi
  case "$mode" in
    *discard) ;;
    *)
      local got
      got="$(sha256sum "$out/$(basename "$src")" | cut -d' ' -f1)"
      if [ "$got" != "$want" ]; then
        echo "SHA-256 mismatch for $*" >&2
        exit 1
      fi
      ;;
  esac
  { sed -n 's/^transfer/receiver: transfer/p' "$work/recv.log"
    sed -n 's/^transfer/sender:   transfer/p' "$work/send.log"; } > "$work/phases"
  echo "$(sed -n 's/^sent .* s, \([0-9.]*\) MiB\/s.*/\1/p' "$work/send.log") \
$(transfer_rate "$work/recv.log") $(cores "$work/send.log") $(cores "$work/recv.log") $cpu"
}

median() { sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }

echo "| connections | threads | chunk | cipher | verify | hash | mode | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % |"
echo "|---|---|---|---|---|---|---|---|---|---|---|---|"
: > "$work/phase-table"
bench() {
  if [ -n "${ROWS:-}" ] && ! echo "$*" | grep -Eq "$ROWS"; then return; fi
  local runs
  runs="$(for _ in $(seq "$repeat"); do run_once "$@"; done)"
  col() { echo "$runs" | cut -d' ' -f"$1" | median; }
  # "median (min-max)" for the rate columns.
  spread() {
    echo "$runs" | cut -d' ' -f"$1" | sort -n |
      awk '{ v[NR] = $1 } END { printf "%.0f (%.0f-%.0f)", v[int((NR + 1) / 2)], v[1], v[NR] }'
  }
  local threads="$2"
  [ "$threads" = 0 ] && threads=auto
  echo "| $1 | $threads | $3 | $4 | $5 | $6 | $7 | $(spread 1) | $(spread 2) | $(col 3) | $(col 4) | $(col 5) |"
  { echo "$*"; sed 's/^/  /' "$work/phases"; } >> "$work/phase-table"
}
for n in 1 4 8 16; do bench "$n" 0 1MiB aes256gcm on off disk; done
for chunk in 4K 16K 256K 4MiB; do bench 8 0 "$chunk" aes256gcm on off disk; done
bench 8 0 1MiB chacha20poly1305 on off disk
bench 8 0 1MiB aes256gcm off off disk
bench 8 0 1MiB aes256gcm on on disk
for mode in memory discard memory+discard; do bench 8 0 1MiB aes256gcm off off "$mode"; done
for cipher in aes256gcm chacha20poly1305; do
  for n in 1 2; do
    for threads in 1 4 16 32; do bench "$n" "$threads" 1MiB "$cipher" off off memory+discard; done
  done
done
rm -rf "$work/out"
echo
echo "Time per phase (last run of each row):"
sed 's/^/    /' "$work/phase-table"
echo "all disk-writing outputs matched SHA-256 $want" >&2
