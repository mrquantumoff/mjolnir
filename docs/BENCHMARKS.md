# Benchmarks

Measured on 2026-09-29 at commit 9df9b84, with
[`scripts/bench.sh`](../scripts/bench.sh), REPEAT=3 and PAUSE=20. Each row
sends 2 GiB of random data between a release `mjolnir recv` and a release
`mjolnir send`, running as two processes on 127.0.0.1: one 2 GiB file, or
for the two `files` rows a directory of 16 x 128 MiB or 64 x 32 MiB files.
Rates are the median of three runs, with the min-max range in parentheses.
Every disk-writing run's output matched the source's SHA-256.

- **MiB/s** is the sender's whole session: connecting, the handshake, every
  round, the read-back verification, the hash check, and finalizing.
- **Transfer phase MiB/s** counts only the time data was moving.
- **Cores** is each process's CPU time divided by the elapsed time.
- **Peak MiB** is each process's peak resident memory (the peak working
  set on Windows, `ru_maxrss` on Linux), median of the three runs.
- **Modes.** `disk` is a normal transfer. `discard` makes the receiver drop
  the plaintext instead of writing it. `memory` makes the sender serve
  chunks from a copy of the file in RAM. The memory copy is made inside the
  timed session, which is why those rows' end-to-end rate is low and their
  sender peak is 2 GiB; compare their transfer phase instead.
- **Baseline.** [`scripts/rawdisk.py`](../scripts/rawdisk.py) measures the
  drive without mjolnir. It writes 2 GiB in 1 MiB blocks and then fsyncs,
  once from one writer and once from 8 threads writing interleaved blocks,
  3 runs each.

Loopback numbers say nothing about a real network. Rerun both scripts on
your own hosts.

## Machine

AMD Ryzen 9 9950X (16 cores, 32 threads), 64 GB RAM, Windows 11 Pro (build
26200), Rust 1.98.1, Samsung 970 EVO Plus 2 TB NVMe. The source file was in
the page cache. The WSL2 VM was running during the Windows rows and both
OSes share the drive. Other work on the machine (another build, a desktop
app) was not stopped; the machine CPU column shows when it was busy.

## Windows

Native Windows build, run from Git Bash. The data lived in `%LOCALAPPDATA%\Temp`
on the system drive.

Raw disk after a 60 s rest: **1 writer 1459 MiB/s** (1435-1478), 8 writers
1348 MiB/s (1315-1390).

| connections | threads | chunk | cipher | verify | hash | mode | files | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % | sender peak MiB | receiver peak MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 846 (682-869) | 984 (787-1002) | 0.8 | 1.2 | 28 | 13 | 90 |
| 4 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 857 (723-861) | 978 (816-990) | 0.8 | 1.4 | 13 | 25 | 90 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 859 (825-870) | 990 (948-1002) | 0.9 | 1.4 | 17 | 41 | 90 |
| 16 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 828 (820-892) | 962 (958-1016) | 0.8 | 1.4 | 14 | 73 | 91 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 16x128MiB | 958 (756-998) | 1189 (920-1234) | 1.8 | 2.7 | 15 | 41 | 90 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 64x32MiB | 638 (564-641) | 846 (786-857) | 1.5 | 2.3 | 19 | 41 | 90 |
| 8 | auto | 4K | aes256gcm | on | off | disk | 1 | 242 (241-260) | 257 (257-277) | 1.8 | 1.8 | 16 | 9 | 12 |
| 8 | auto | 16K | aes256gcm | on | off | disk | 1 | 594 (469-645) | 711 (562-761) | 1.7 | 1.9 | 22 | 9 | 13 |
| 8* | auto | 256K | aes256gcm | on | off | disk | 1 | 861 (860-887) | 995 (990-1021) | 0.8 | 1.4 | 10 | 17 | 30 |
| 8 | auto | 4MiB | aes256gcm | on | off | disk | 1 | 983 (946-1012) | 1180 (1143-1229) | 1.0 | 1.7 | 22 | 137 | 330 |
| 8 | auto | 64MiB | aes256gcm | on | off | disk | 1 | 844 (660-885) | 989 (747-1055) | 1.1 | 1.7 | 28 | 969 | 970 |
| 8 | auto | 1MiB | chacha20poly1305 | on | off | disk | 1 | 991 (891-1000) | 1174 (1100-1196) | 1.0 | 1.7 | 24 | 41 | 90 |
| 8 | auto | 1MiB | aes256gcm | off | off | disk | 1 | 1125 (1100-1153) | 1144 (1117-1167) | 1.1 | 1.7 | 24 | 41 | 90 |
| 8 | auto | 1MiB | aes256gcm | on | on | disk | 1 | 765 (690-796) | 992 (889-1035) | 0.9 | 1.2 | 17 | 41 | 90 |
| 8 | auto | 1MiB | aes256gcm | off | off | memory | 1 | 743 (728-805) | 898 (897-983) | 0.8 | 1.3 | 18 | 2089 | 90 |
| 8 | auto | 1MiB | aes256gcm | off | off | discard | 1 | 4240 (4143-4260) | 4427 (4403-4463) | 4.6 | 3.4 | - | 41 | 20 |
| 8 | auto | 1MiB | aes256gcm | off | off | memory+discard | 1 | 2556 (2543-2617) | 5996 (5672-6145) | 3.9 | 7.4 | - | 2089 | 28 |
| 1 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1098 (1013-1140) | 1459 (1323-1512) | 1.1 | 1.0 | 13 | 2059 | 27 |
| 1 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1643 (1602-1667) | 2707 (2705-2737) | 1.7 | 1.7 | 23 | 2060 | 16 |
| 1 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1795 (1639-1835) | 3047 (2659-3171) | 1.8 | 2.2 | 14 | 2060 | 16 |
| 1 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1834 (1507-1969) | 3189 (2411-3504) | 2.0 | 2.6 | 19 | 2061 | 17 |
| 2 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1126 (1119-1136) | 1496 (1493-1507) | 1.2 | 1.0 | 6 | 2060 | 23 |
| 2 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 2274 (2113-2278) | 4487 (4126-4491) | 2.6 | 3.5 | - | 2064 | 21 |
| 2 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 2136 (2135-2177) | 4159 (4073-4337) | 2.7 | 4.2 | 13 | 2064 | 20 |
| 2 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 2115 (2003-2213) | 3949 (3658-4466) | 2.3 | 2.6 | 11 | 2065 | 20 |
| 1 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 953 (902-987) | 1274 (1210-1279) | 1.2 | 1.1 | 25 | 2059 | 20 |
| 1 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1838 (1829-1844) | 3261 (3208-3318) | 2.2 | 2.9 | 26 | 2060 | 16 |
| 1 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1771 (1632-2008) | 2988 (2546-3634) | 1.9 | 2.3 | 15 | 2060 | 16 |
| 1 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1817 (1800-1906) | 3039 (3020-3426) | 2.1 | 2.4 | 13 | 2061 | 17 |
| 2 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1036 (1022-1046) | 1356 (1339-1358) | 1.2 | 1.1 | 8 | 2060 | 27 |
| 2 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 2196 (2042-2366) | 4397 (3806-4833) | 3.0 | 4.1 | - | 2064 | 21 |
| 2 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 2017 (2009-2022) | 3707 (3660-3898) | 2.7 | 3.4 | 26 | 2064 | 20 |
| 2 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 2060 (2044-2099) | 3962 (3875-4326) | 2.7 | 3.6 | 21 | 2065 | 21 |

The row marked with an asterisk ranged from 399 to 962 MiB/s during the
sweep, with the machine busy (see "Noise and the drive"), and was rerun
after a three-minute rest, with PAUSE=45.

## Linux (WSL2)

WSL2 kernel 6.18.33.2 with 32 vCPUs and 31 GiB RAM. The Linux build, the
clone and the data all lived in the Linux home directory, on the WSL ext4
virtual disk, not under `/mnt/c` (which is much slower for I/O). WSL2 runs
in a VM, so bare-metal Linux may differ.

Raw disk after a 60 s rest: **1 writer 1711 MiB/s** (975-1742), 8 writers
1735 MiB/s (1712-1778).

| connections | threads | chunk | cipher | verify | hash | mode | files | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % | sender peak MiB | receiver peak MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 911 (910-916) | 944 (938-957) | 0.8 | 1.7 | - | 8 | 84 |
| 4 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 946 (889-946) | 976 (916-976) | 0.9 | 1.7 | - | 20 | 84 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 886 (662-893) | 912 (676-922) | 0.9 | 1.6 | - | 36 | 84 |
| 16 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 921 (898-922) | 950 (926-950) | 1.0 | 1.7 | - | 68 | 83 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 16x128MiB | 966 (871-1039) | 1100 (969-1200) | 2.7 | 4.4 | - | 36 | 85 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 64x32MiB | 550 (517-569) | 706 (662-733) | 1.9 | 2.8 | - | 36 | 86 |
| 8 | auto | 4K | aes256gcm | on | off | disk | 1 | 191 (178-193) | 195 (193-195) | 1.6 | 3.4 | - | 4 | 7 |
| 8 | auto | 16K | aes256gcm | on | off | disk | 1 | 419 (390-421) | 425 (418-428) | 1.2 | 2.5 | - | 4 | 7 |
| 8 | auto | 256K | aes256gcm | on | off | disk | 1 | 830 (817-842) | 854 (842-866) | 0.9 | 1.8 | - | 12 | 24 |
| 8 | auto | 4MiB | aes256gcm | on | off | disk | 1 | 838 (834-894) | 890 (866-947) | 1.3 | 2.2 | - | 132 | 324 |
| 8 | auto | 64MiB | aes256gcm | on | off | disk | 1 | 704 (657-706) | 760 (710-764) | 1.7 | 2.5 | - | 964 | 964 |
| 8 | auto | 1MiB | chacha20poly1305 | on | off | disk | 1 | 894 (793-900) | 924 (822-928) | 1.0 | 1.8 | - | 36 | 83 |
| 8 | auto | 1MiB | aes256gcm | off | off | disk | 1 | 889 (888-891) | 901 (899-902) | 1.0 | 1.5 | - | 36 | 84 |
| 8 | auto | 1MiB | aes256gcm | on | on | disk | 1 | 822 (797-862) | 866 (842-905) | 1.5 | 1.7 | - | 36 | 84 |
| 8 | auto | 1MiB | aes256gcm | off | off | memory | 1 | 470 (219-523) | 791 (666-874) | 1.0 | 1.5 | - | 2084 | 84 |
| 8 | auto | 1MiB | aes256gcm | off | off | discard | 1 | 3868 (3702-3902) | 4201 (4079-4284) | 12.0 | 7.7 | - | 36 | 28 |
| 8 | auto | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1005 (707-1509) | 3923 (2717-4443) | 3.5 | 7.9 | - | 2084 | 30 |
| 1 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 876 (867-876) | 1403 (1387-1404) | 1.2 | 1.1 | - | 2055 | 22 |
| 1 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1265 (1139-1396) | 3278 (3206-3314) | 1.9 | 2.7 | - | 2056 | 10 |
| 1 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1030 (1028-1385) | 3303 (3187-3405) | 1.7 | 2.8 | - | 2056 | 10 |
| 1 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1067 (1039-1105) | 3281 (3166-3394) | 1.7 | 2.7 | - | 2056 | 12 |
| 2 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 859 (764-899) | 1399 (1350-1423) | 1.2 | 1.1 | - | 2056 | 22 |
| 2 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1391 (1247-1582) | 4710 (4646-4970) | 2.4 | 4.2 | - | 2060 | 17 |
| 2 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1490 (964-1639) | 5019 (2431-5078) | 2.4 | 4.3 | - | 2060 | 13 |
| 2 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1254 (1254-1589) | 4771 (4424-4919) | 2.3 | 4.2 | - | 2060 | 13 |
| 1 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 832 (766-835) | 1256 (1243-1270) | 1.1 | 1.1 | - | 2055 | 22 |
| 1 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1293 (1127-1378) | 3160 (3057-3238) | 2.0 | 2.8 | - | 2056 | 11 |
| 1 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1083 (998-1086) | 3072 (2985-3178) | 1.8 | 2.9 | - | 2056 | 10 |
| 1 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 521 (434-569) | 1245 (1223-1302) | 1.4 | 1.7 | - | 2056 | 13 |
| 2 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 712 (512-739) | 1116 (986-1223) | 1.2 | 1.2 | - | 2056 | 22 |
| 2 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1118 (785-1242) | 3430 (2291-3527) | 2.4 | 3.9 | - | 2060 | 17 |
| 2 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1410 (1242-1411) | 3896 (3893-4567) | 2.7 | 4.5 | - | 2060 | 15 |
| 2 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1288 (1234-1496) | 4584 (2624-5039) | 2.5 | 4.6 | - | 2060 | 15 |

## What changed since the last run

The tables at 4daa636 were followed by a performance review with eleven
proposals. The first five are in, each measured on its own with
interleaved A/B builds (A B A B ...), REPEAT=3, PAUSE=20 before disk runs,
and rests between rows. Rates are medians; CPU is seconds per GiB moved.

- **Missing chunks counted from bitmap words (f189dfe).** Each round no
  longer lists every missing chunk. A microbenchmark on 2^26 chunks went
  from 406 ms and 1536 MiB of temporaries to 1.6 ms and none for a fresh
  transfer. A 2 GiB file has at most 524,288 chunks, so the tables do not
  show it.
- **Control messages sealed in place, file hash streamed (95d0a77).** A
  64 MiB `Have` holds 63 MiB of buffers instead of 127, and the file hash
  over 2^24 digests reads 1 MiB at a time instead of 256 MiB at once.
  Also below what these rows can show.
- **A real buffer budget, borrowed buffers for the checks (3a9cfd8).** At
  64 MiB chunks, 8 connections: Windows sender peak 2057 to 969 MiB,
  receiver 3082 to 971, CPU 1.47 to 1.21 (sender) and 2.51 to 2.05
  (receiver); Linux sender 2052 to 964 MiB, receiver 2948 to 964, CPU 5.07
  to 2.56 and 8.22 to 4.07, verify 0.46 to 0.18 s, rate 520 to 662 MiB/s.
  With 64 x 32 MiB files and `--hash` on Windows, sender peak 73 to 41 MiB
  and receiver 99-106 to 82-92, with rates and CPU within noise (CPU was
  higher in one of three blocks and lower in the other two). On Linux the
  64-file row kept its rate and CPU, receiver peak 100 to 86 MiB.
- **A smaller receive buffer for large frames (d29c1a2).** One connection,
  memory+discard, two blocks in both orders (six runs per build). Windows
  transfer phase 1875 to 2027 MiB/s at 4 workers, 1539 to 1880 at 16, 1093
  to 1647 at 32. Receiver CPU went 0.60 to 0.80 at 4 workers, 0.84 to 0.91
  at 16, and 0.98 to 0.86 at 32, inside the spread of identical builds on
  these rows (see below). Linux, where CPU is steady: no change in rate or
  CPU (receiver 0.92 against 0.92 at 4 workers). The 4 KiB row keeps its
  256 KiB buffer and did not change on either OS. Socket reads per GiB
  were the same with either buffer.
- **Read-back checks in runs (73ec15c).** Verification and `--hash` read
  small chunks in runs of up to 64 KiB. Windows, 8 connections: 4 KiB
  verify 4.08 to 0.64 s, end to end 145 to 192 MiB/s, receiver CPU 11.9 to
  9.6; 16 KiB verify 1.69 to 0.69 s, 372 to 459 MiB/s, CPU 4.8 to 3.9;
  4 KiB with `--hash` 136 to 211 MiB/s, the sender's hash pass 3.45 to
  0.46 s. Linux reads its page cache far faster: 4 KiB verify 0.26 to
  0.07 s, rates unchanged within noise. Peak memory unchanged.

One correctness change shows in the tables too. The staging journal with
durable publishing (4055638) syncs each file as it is published, so the
64 x 32 MiB row's finalize phase went from 0.21 to 0.65 s on Windows and
0.06 to 0.65 s on Linux. That is most of why the row's end-to-end rate
is lower than at 4daa636 (718 to 638 MiB/s on Windows, 725 to 550 on
Linux). Its Linux transfer phase is lower as well (805 to 706); an A/B
without the buffer budget showed the same rate (697 against 688), so that
drop is not from these changes, and it was not traced further.

## What the numbers show

- **The drive is the limit with a disk in the loop.** Both OSes write one
  file at 830-950 MiB/s end to end from 1 to 16 connections (Windows
  828-859, Linux 886-946), with the receiver at 1.2-1.7 cores. That is
  55-60% of today's raw one-writer rate (1459 and 1711 MiB/s). The drive
  was in its fast state for this sweep; at 4daa636 its raw rate was 868
  and 1311. The 16-file rows reach 958-966 MiB/s.
- **Crypto scales with cores, up to what the network threads can feed.**
  Without disk, one connection moves about 1.2-1.4 GiB/s on 1 worker and
  2.6-3.3 GiB/s on 4 to 32 on both OSes, where Windows reached 2.5 at
  4daa636. Two connections reach 3.6-4.4 GiB/s on Windows and 3.4-4.9 on
  Linux. AES-256-GCM and ChaCha20-Poly1305 land within about 20% of each
  other, apart from one Linux row (ChaCha20, 1 connection, 32 workers, at
  1245 MiB/s in all three runs). The 8-connection discard rows run at
  3.8-4.1 GiB/s end to end.
- **Chunk size.** 256 KiB to 4 MiB perform alike. 4 KiB chunks now cost
  3.5x (Windows, 242 against 859 MiB/s) to 4.6x (Linux, 191 against 886)
  and 16 KiB 1.4-2.1x; at 4daa636 Windows 4 KiB cost 5x, most of the
  difference being verification. 64 MiB chunks cost 2-21%.
- **Checks.** Verification costs 0.3 s per 2 GiB on Windows and 0.04 s on
  Linux at 1 MiB chunks. `--hash` costs about 11% on Windows and 7% on
  Linux end to end.
- **Memory is bounded by the buffer pools.** The receiver holds
  `2 x workers + 16` chunk buffers (80 with 32 workers): 83-91 MiB at 1 MiB
  chunks, 7-13 MiB at 4-16 KiB, 324-330 MiB at 4 MiB, and 964-970 MiB at
  64 MiB, where the 1 GiB budget caps the pool at 15 buffers. The sender
  holds 4 frames per connection, and at least 8 for the hash pass:
  8-13 MiB on 1 connection, 68-73 MiB on 16.

## Not yet done

The remaining six proposals from the review, with its estimates. None of
these gains is measured; each is the review's expectation, to be tested
the same way as the five above.

| # | Change | Review's estimate | Risk |
|---|---|---|---|
| 6 | Claim, submit, and send small chunks in batches (16-32 frames), with vectored socket writes and shared storage for split chunk lists | Up to 16x fewer queue, claim, and send operations per batch; a strong candidate for much of the small-chunk deficit, though not 4x throughput | Medium |
| 7 | Keep one writer per file, but let it drain and coalesce adjacent finished chunks into one write, with their digests in one write | Up to 16x fewer write calls (2 instead of 32 for 16 adjacent 4 KiB chunks) and fewer blocked workers; mostly CPU and small-chunk throughput | Medium-high |
| 8 | Skip syncs a finished checkpoint already covers, and run a few files' checkpoints at once | Up to two fewer sync calls per file per verification pass (six per file today at the end, 384 for 64 files); lower many-file finish latency, little if clean syncs are cheap | Medium |
| 9 | Report and optionally set socket buffer sizes against the bandwidth-delay product | Potentially large on a window-limited WAN (a 1 MiB window at 10 ms RTT allows about 100 MiB/s per connection); zero or negative on loopback | Low |
| 10 | Sparse NTFS part files, and read-ahead hints once reads are contiguous | 1.3-1.9x page-cache write throughput in the microbenchmark, but no end-to-end gain in the earlier A/B; hints help only cold reads | Low-medium |
| 11 | Split the sender's feeder from its socket writer, later an asynchronous I/O backend | At most `1 / max(p, 1 - p)` of the one-connection ceiling if socket work is a fraction `p` of that thread's time, so 1.25x at `p = 0.8`, before handoff costs | High |

## Noise and the drive

Rates on this machine swing 2-3x between identical runs once the drive
has absorbed a few tens of GiB: a sweep writes 33 rows x 3 x 2 GiB. After
a rest of a few minutes the fast state returns. The drive's temperature
is not readable without admin rights, so this is attributed to the SSD's
write cache and heat, not measured. Hence PAUSE=20 before each disk run,
one OS per block, rests between blocks, and medians with ranges. This
sweep stayed in the fast state except the Windows 256 KiB row (399-962
MiB/s, with the machine busy at 60% CPU), which is marked with an asterisk
and was rerun after a three-minute rest with PAUSE=45. Treat differences
under about 20% between disk rows as noise.

CPU columns are steadier than rates on Linux: identical builds stayed
within about 5% of each other. On Windows, the no-disk rows are not
steady in CPU either: two runs of the same build on the same row used
0.97 and 3.44 receiver CPU seconds for the same 2 GiB. Compare builds
there by interleaved A/B runs, several blocks, and both orders. The
no-disk rates are not steady on either OS: on Linux, `memory+discard` at
8 connections ranged from 2717 to 4443 MiB/s in the transfer phase
across its three runs.

One NTFS effect is worth knowing and was left alone: writing far past
the valid data length of a pre-sized file makes NTFS zero-fill up to
there. With N connections on one file the receiver now writes N regions
of the file at once, and the page-cache phase of the microbenchmark
halved (2262-2620 MiB/s against 3979-4353 for near-sequential writes;
a sparse file restores 3373-4304). The zeros are overwritten before the
2 s checkpoint flushes more than a fraction of them, and an interleaved
A/B of the two builds showed no end-to-end difference, so it costs
memory bandwidth, not disk time, and no Windows-only ioctl was added.
