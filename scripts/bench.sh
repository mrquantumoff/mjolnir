#!/usr/bin/env bash
# Loopback benchmark: a release `mjolnir recv` and `mjolnir send` as two
# processes on 127.0.0.1 with one random file. Rows sweep connection
# counts, worker counts, chunk sizes, both ciphers, verification, the hash
# check, and two no-disk modes (MJOLNIR_BENCH, see src/benchmode.rs):
#   discard  the receiver drops plaintext instead of writing it
#   memory   the sender serves chunks from a copy of the file in memory
# Every disk-writing run's output is checked with SHA-256. Each row also
# records both processes' CPU time (in cores busy on average), their peak
# memory, and the receiver's time per phase; on Windows, typeperf adds
# machine-wide CPU.
#
# Two rows send a directory of many files instead (16 x 128 MiB and
# 64 x 32 MiB), to show whether files move in parallel.
#
# usage: scripts/bench.sh [WORKDIR]
#   SIZE_MIB  file size in MiB (default 2048)
#   REPEAT    runs per configuration; rates show median and range (default 3)
#   PORT      listen port (default 7799)
#   PAUSE     seconds to idle before each disk-writing run, so the drive can
#             finish flushing and cool down between runs (default 0)
#   ROWS      only run rows whose "connections threads chunk cipher verify
#             hash mode files" matches this extended regex, e.g. ROWS='^8 0 1MiB'
set -euo pipefail
# Git Bash on Windows rewrites arguments that start with '/' into Windows
# paths, and a base64 key can start with '/'.
export MSYS_NO_PATHCONV=1

root="$(cd "$(dirname "$0")/.." && { pwd -W 2> /dev/null || pwd; })"
work="${1:-$root/target/bench}"
# With path conversion off, a /c/... workdir would reach the Windows binary
# unconverted.
command -v cygpath > /dev/null 2>&1 && work="$(cygpath -m "$work")"
size_mib="${SIZE_MIB:-2048}"
repeat="${REPEAT:-3}"
port="${PORT:-7799}"
pause="${PAUSE:-0}"

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

# A directory of COUNT random files of MIB MiB each, with a checksum list
# relative to $work.
multi_dir() {
  local count="$1" mib="$2" dir="$work/files-${1}x${2}MiB"
  if [ ! -f "$dir.sha" ]; then
    echo "writing $count files of $mib MiB to $dir" >&2
    rm -rf "$dir" && mkdir -p "$dir"
    for i in $(seq -w "$count"); do head -c $((mib << 20)) /dev/urandom > "$dir/f$i.bin"; done
    (cd "$work" && sha256sum "$(basename "$dir")"/*.bin > "$dir.sha")
  fi
  echo "$dir"
}

rm -f "$work/s.key" "$work/r.key"
spub="$("$bin" keygen --out "$work/s.key" 2>/dev/null)"
rpub="$("$bin" keygen --out "$work/r.key" 2>/dev/null)"

# The receiver and typeperf of the run in progress, stopped on any exit so a
# failed or interrupted run leaves nothing behind.
rpid=""
tpid=""
stop_typeperf() {
  [ -n "$tpid" ] || return 0
  # typeperf is a native Windows process: stop it by its own PID, never by
  # image name, which would also end typeperf runs this script did not start.
  local winpid
  winpid="$(cat "/proc/$tpid/winpid" 2> /dev/null || true)"
  if [ -n "$winpid" ]; then
    taskkill /F /PID "$winpid" > /dev/null 2>&1 || true
  else
    kill "$tpid" 2> /dev/null || true
  fi
  wait "$tpid" 2> /dev/null || true
  tpid=""
}
cleanup() {
  if [ -n "$rpid" ]; then
    kill "$rpid" 2> /dev/null || true
    wait "$rpid" 2> /dev/null || true
  fi
  stop_typeperf
}
# Subshells do not inherit traps, and each row's runs happen in one.
clean_on_exit() {
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}
clean_on_exit

cores() { sed -n 's/^cpu .* s, \([0-9.]*\) cores busy.*/\1/p' "$1"; }
peak() { sed -n 's/^cpu .*, peak memory \([0-9.]*\) MiB.*/\1/p' "$1"; }
transfer_rate() { sed -n 's/^transfer [0-9.]* s (\([0-9]*\) MiB\/s).*/\1/p' "$1"; }

# One transfer; prints "<MiB/s> <receiver transfer-phase MiB/s> <sender cores>
# <receiver cores> <machine CPU %> <sender peak MiB> <receiver peak MiB>" and
# leaves both sides' phase lines in $work/phases.
run_once() {
  local n="$1" threads="$2" chunk="$3" cipher="$4" verify="$5" hash="$6" mode="$7" files="$8"
  local out="$work/out" recv_flags=() send_flags=() recv_env="" send_env="" input="$src"
  if [ "$files" != 1 ]; then
    local mib="${files#*x}"
    input="$(multi_dir "${files%x*}" "${mib%MiB}")"
  fi
  [ "$verify" = off ] && recv_flags+=(--no-verify)
  [ "$hash" = on ] && send_flags+=(--hash)
  case "$mode" in
    discard) recv_env=discard ;;
    memory) send_env=memory-source ;;
    memory+discard) recv_env=discard send_env=memory-source ;;
  esac
  rm -rf "$out" && mkdir -p "$out"
  case "$mode" in *discard) ;; *) sleep "$pause" ;; esac
  MJOLNIR_BENCH="$recv_env" "$bin" recv --key "$work/r.key" --allow "$spub" \
    --listen "127.0.0.1:$port" --out "$out" --threads "$threads" "${recv_flags[@]}" \
    2> "$work/recv.log" &
  rpid=$!
  for _ in $(seq 100); do
    grep -q "listening on" "$work/recv.log" 2>/dev/null && break
    sleep 0.05
  done
  if $have_typeperf; then
    typeperf '\Processor(_Total)\% Processor Time' -si 1 > "$work/cpu.txt" 2>&1 &
    tpid=$!
  fi
  if ! MJOLNIR_BENCH="$send_env" "$bin" send "127.0.0.1:$port" --key "$work/s.key" \
    --peer "$rpub" -n "$n" --threads "$threads" -c "$chunk" --cipher "$cipher" \
    "${send_flags[@]}" "$input" 2> "$work/send.log"; then
    cat "$work/send.log" >&2
    exit 1
  fi
  wait "$rpid"
  rpid=""
  local cpu="-"
  if $have_typeperf; then
    stop_typeperf
    cpu="$(tr -d '\r' < "$work/cpu.txt" | grep '^"[0-9]' | cut -d, -f2 | tr -d '"' |
      awk 'NF { s += $1; c++ } END { if (c) printf "%.0f", s / c; else print "-" }')"
  fi
  case "$mode" in
    *discard) ;;
    *)
      if [ "$files" != 1 ]; then
        if ! (cd "$out" && sha256sum -c --quiet "$input.sha"); then
          echo "SHA-256 mismatch for $*" >&2
          exit 1
        fi
      else
        local got
        got="$(sha256sum "$out/$(basename "$src")" | cut -d' ' -f1)"
        if [ "$got" != "$want" ]; then
          echo "SHA-256 mismatch for $*" >&2
          exit 1
        fi
      fi
      ;;
  esac
  { sed -n 's/^transfer/receiver: transfer/p' "$work/recv.log"
    sed -n 's/^transfer/sender:   transfer/p' "$work/send.log"; } > "$work/phases"
  echo "$(sed -n 's/^sent .* s, \([0-9.]*\) MiB\/s.*/\1/p' "$work/send.log") \
$(transfer_rate "$work/recv.log") $(cores "$work/send.log") $(cores "$work/recv.log") $cpu \
$(peak "$work/send.log") $(peak "$work/recv.log")"
}

median() { sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }

echo "| connections | threads | chunk | cipher | verify | hash | mode | files | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % | sender peak MiB | receiver peak MiB |"
echo "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
: > "$work/phase-table"
bench() {
  local files="${8:-1}"
  local row="$1 $2 $3 $4 $5 $6 $7 $files"
  if [ -n "${ROWS:-}" ] && ! echo "$row" | grep -Eq "$ROWS"; then return; fi
  local runs
  runs="$(clean_on_exit; for _ in $(seq "$repeat"); do run_once "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$files"; done)"
  col() { echo "$runs" | cut -d' ' -f"$1" | median; }
  # "median (min-max)" for the rate columns.
  spread() {
    echo "$runs" | cut -d' ' -f"$1" | sort -n |
      awk '{ v[NR] = $1 } END { printf "%.0f (%.0f-%.0f)", v[int((NR + 1) / 2)], v[1], v[NR] }'
  }
  local threads="$2"
  [ "$threads" = 0 ] && threads=auto
  echo "| $1 | $threads | $3 | $4 | $5 | $6 | $7 | $files | $(spread 1) | $(spread 2) | $(col 3) | $(col 4) | $(col 5) | $(col 6 | awk '{ printf "%.0f", $1 }') | $(col 7 | awk '{ printf "%.0f", $1 }') |"
  { echo "$row"; sed 's/^/  /' "$work/phases"; } >> "$work/phase-table"
}
for n in 1 4 8 16; do bench "$n" 0 1MiB aes256gcm on off disk; done
for files in 16x128MiB 64x32MiB; do bench 8 0 1MiB aes256gcm on off disk "$files"; done
for chunk in 4K 16K 256K 4MiB 64MiB; do bench 8 0 "$chunk" aes256gcm on off disk; done
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
