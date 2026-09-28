# Benchmarks

Measured on 2026-09-28 at commit b8f5e18, with
[`scripts/bench.sh`](../scripts/bench.sh) and REPEAT=3. Each row sends one
2 GiB file of random data between a release `mjolnir recv` and a release
`mjolnir send`, running as two processes on 127.0.0.1. Rates are the median
of three runs, with the min-max range in parentheses. Every disk-writing
run's output matched the source's SHA-256.

- **MiB/s** is the sender's whole session: connecting, the handshake, every
  round, the read-back verification, the hash check, and finalizing.
- **Transfer phase MiB/s** counts only the time data was moving.
- **Cores** is each process's CPU time divided by the elapsed time.
- **Modes.** `disk` is a normal transfer. `discard` makes the receiver drop
  the plaintext instead of writing it. `memory` makes the sender serve
  chunks from a copy of the file in RAM. The memory copy is made inside the
  timed session, which is why those rows' end-to-end rate is low; compare
  their transfer phase instead.
- **Baseline.** [`scripts/rawdisk.py`](../scripts/rawdisk.py) measures the
  drive without mjolnir. It writes 2 GiB in 1 MiB blocks and then fsyncs,
  once from one writer and once from 8 threads writing interleaved blocks,
  3 runs each.

Loopback numbers say nothing about a real network. Rerun both scripts on
your own hosts.

## Machine

AMD Ryzen 9 9950X (16 cores, 32 threads), 64 GB RAM, Windows 11 Pro (build
26200), Rust 1.98.1. The source file was in the page cache.

## Windows

Native Windows build, run from Git Bash. The data lived in `%LOCALAPPDATA%\Temp`
on the system drive.

Raw disk: **1 writer 2007 MiB/s** (1962-2050), 8 writers 2117 MiB/s
(1940-2593).

| connections | threads | chunk | cipher | verify | hash | mode | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | auto | 1MiB | aes256gcm | on | off | disk | 670 (603-988) | 736 (649-1121) | 0.8 | 1.1 | 15 |
| 4 | auto | 1MiB | aes256gcm | on | off | disk | 1206 (1184-1218) | 1412 (1391-1427) | 1.6 | 1.8 | 13 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 1155 (1153-1170) | 1358 (1353-1364) | 1.0 | 1.9 | 15 |
| 16 | auto | 1MiB | aes256gcm | on | off | disk | 1110 (1090-1122) | 1294 (1270-1314) | 1.1 | 1.9 | 17 |
| 8 | auto | 4K | aes256gcm | on | off | disk | 231 (218-274) | 364 (356-385) | 2.1 | 2.4 | 28 |
| 8 | auto | 16K | aes256gcm | on | off | disk | 613 (596-655) | 899 (893-934) | 1.7 | 2.0 | 18 |
| 8 | auto | 256K | aes256gcm | on | off | disk | 1178 (1152-1210) | 1402 (1373-1460) | 1.1 | 2.0 | 16 |
| 8 | auto | 4MiB | aes256gcm | on | off | disk | 1154 (1050-1169) | 1394 (1265-1419) | 1.1 | 1.9 | 9 |
| 8 | auto | 1MiB | chacha20poly1305 | on | off | disk | 1202 (1154-1218) | 1420 (1368-1422) | 1.1 | 2.0 | 15 |
| 8 | auto | 1MiB | aes256gcm | off | off | disk | 1360 (1353-1385) | 1375 (1365-1395) | 1.2 | 1.8 | 13 |
| 8 | auto | 1MiB | aes256gcm | on | on | disk | 998 (986-1024) | 1334 (1304-1386) | 1.2 | 1.6 | 15 |
| 8 | auto | 1MiB | aes256gcm | off | off | memory | 1010 (992-1037) | 1262 (1251-1301) | 1.1 | 2.0 | 19 |
| 8 | auto | 1MiB | aes256gcm | off | off | discard | 4530 (4460-4751) | 4753 (4680-4852) | 5.3 | 4.1 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | memory+discard | 2349 (2239-2467) | 4541 (4220-4664) | 3.3 | 5.3 | - |
| 1 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1131 (1128-1135) | 1484 (1458-1490) | 1.2 | 1.1 | 16 |
| 1 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1519 (1309-1752) | 2143 (1821-2635) | 1.6 | 1.6 | 14 |
| 1 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1442 (1370-1561) | 2061 (1918-2220) | 1.7 | 1.7 | 18 |
| 1 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1310 (1303-1736) | 1802 (1796-2755) | 1.6 | 1.8 | 11 |
| 2 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1141 (1128-1170) | 1491 (1490-1505) | 1.2 | 1.1 | 11 |
| 2 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 2038 (1844-2147) | 3305 (2885-3775) | 2.1 | 2.6 | - |
| 2 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1990 (1654-2110) | 3312 (2475-3773) | 2.0 | 2.5 | - |
| 2 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1940 (1660-2249) | 3133 (2513-3970) | 2.1 | 2.6 | - |
| 1 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1058 (1056-1073) | 1355 (1344-1365) | 1.2 | 1.1 | 9 |
| 1 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1449 (1330-1494) | 2034 (1787-2098) | 1.5 | 1.6 | 15 |
| 1 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1688 (1542-1748) | 2503 (2280-2718) | 1.8 | 2.0 | 12 |
| 1 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1527 (1518-1818) | 2255 (2142-2814) | 1.8 | 1.9 | 13 |
| 2 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1023 (1020-1088) | 1299 (1298-1372) | 1.1 | 1.0 | 8 |
| 2 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 2087 (2030-2148) | 3626 (3299-3878) | 2.4 | 3.3 | - |
| 2 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1925 (1794-1938) | 3155 (2746-3217) | 2.2 | 3.2 | - |
| 2 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1852 (1619-2000) | 2871 (2341-3452) | 2.3 | 2.8 | 14 |

## Linux (WSL2)

WSL2 kernel 6.18.33.2 with 32 vCPUs and 31 GiB RAM. The Linux build, the
clone and the data all lived in the Linux home directory, on the WSL ext4
virtual disk, not under `/mnt/c` (which is much slower for I/O). WSL2 runs
in a VM, so bare-metal Linux may differ.

Raw disk: **1 writer 1802 MiB/s** (1088-1812), 8 writers 1691 MiB/s
(1387-1702).

| connections | threads | chunk | cipher | verify | hash | mode | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | auto | 1MiB | aes256gcm | on | off | disk | 1950 (1123-2035) | 2053 (1157-2148) | 1.8 | 3.0 | - |
| 4 | auto | 1MiB | aes256gcm | on | off | disk | 1696 (1370-1726) | 1777 (1425-1802) | 2.0 | 12.3 | - |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 1167 (621-1193) | 1206 (631-1232) | 1.4 | 8.9 | - |
| 16 | auto | 1MiB | aes256gcm | on | off | disk | 888 (834-1217) | 908 (853-1260) | 1.5 | 9.1 | - |
| 8 | auto | 4K | aes256gcm | on | off | disk | 309 (299-386) | 315 (304-394) | 2.7 | 17.6 | - |
| 8 | auto | 16K | aes256gcm | on | off | disk | 689 (586-776) | 704 (596-794) | 1.9 | 12.1 | - |
| 8 | auto | 256K | aes256gcm | on | off | disk | 1338 (867-1373) | 1380 (885-1419) | 1.7 | 8.3 | - |
| 8 | auto | 4MiB | aes256gcm | on | off | disk | 1153 (745-1173) | 1204 (767-1225) | 2.0 | 8.3 | - |
| 8 | auto | 1MiB | chacha20poly1305 | on | off | disk | 1130 (932-1204) | 1168 (959-1243) | 1.6 | 9.6 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | disk | 940 (901-1266) | 943 (904-1271) | 1.2 | 9.3 | - |
| 8 | auto | 1MiB | aes256gcm | on | on | disk | 855 (816-1147) | 896 (851-1219) | 1.7 | 9.1 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | memory | 515 (428-559) | 734 (680-788) | 0.9 | 11.2 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | discard | 4978 (4591-5000) | 5107 (4810-5124) | 13.3 | 9.3 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | memory+discard | 1111 (1068-1696) | 4992 (4918-5060) | 3.9 | 10.1 | - |
| 1 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 867 (682-933) | 1418 (1414-1418) | 1.2 | 1.1 | - |
| 1 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1347 (1316-1446) | 3405 (3162-3559) | 2.0 | 3.0 | - |
| 1 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1002 (966-1388) | 3531 (3367-3572) | 1.7 | 3.1 | - |
| 1 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 981 (970-1004) | 3219 (3128-3451) | 1.7 | 2.9 | - |
| 2 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 927 (886-937) | 1416 (1375-1478) | 1.2 | 1.2 | - |
| 2 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1662 (1332-1693) | 5096 (5051-5342) | 2.4 | 4.7 | - |
| 2 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1164 (1164-1806) | 5948 (5573-5984) | 2.1 | 5.5 | - |
| 2 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1649 (1209-1851) | 5973 (5420-6006) | 2.5 | 5.5 | - |
| 1 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 835 (694-852) | 1261 (1239-1275) | 1.1 | 1.2 | - |
| 1 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1462 (1059-1474) | 3430 (3296-3534) | 2.1 | 3.2 | - |
| 1 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1084 (1082-1095) | 3286 (3151-3358) | 1.9 | 3.2 | - |
| 1 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1125 (1097-1130) | 3401 (3245-3422) | 1.9 | 3.2 | - |
| 2 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 827 (723-836) | 1244 (1229-1255) | 1.2 | 1.2 | - |
| 2 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1523 (1327-1693) | 4734 (4693-4812) | 2.4 | 4.6 | - |
| 2 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1462 (1364-1562) | 5211 (5105-5753) | 2.5 | 5.7 | - |
| 2 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1383 (1283-1820) | 5726 (5454-5912) | 2.3 | 5.8 | - |

## What the numbers show

- **Crypto scales with cores, up to what the network threads can feed.**
  Without disk, one connection goes from about 1.4 GiB/s on 1 worker to
  about 3.4 GiB/s on 4 or more on Linux (1.5 to 2.1 GiB/s on Windows). Two
  connections reach about 5.9 GiB/s on Linux and 3.3-3.6 GiB/s on Windows.
  Past about 4 workers per connection, the connection's single network
  thread is the limit, not the cipher. AES-256-GCM and ChaCha20-Poly1305
  land within about 10% of each other.
- **The receive write path is the bottleneck, not the drive.**
  - Linux with 1 connection writes at raw disk speed (1950 MiB/s end to end,
    against 1802 for raw writes).
  - With more connections on Linux, disk rows get slower (1696, 1167 and
    888 MiB/s at 4, 8 and 16 connections), while the receiver burns 9-12
    cores. That fits many workers doing positional writes into one file and
    contending on the file's inode lock, whose waiters spin before they
    sleep.
  - On Windows, disk rows plateau at about 1.4 GiB/s in the transfer phase,
    about 70% of the raw 2.0 GiB/s. The same rows reach about 4.7 GiB/s when
    the receiver discards the data.
  - Likely fix, not done yet: cap concurrent writers per file, and coalesce
    adjacent chunks into larger writes.
- **Chunk size.** 256 KiB to 4 MiB perform alike. 16 KiB costs about half
  the throughput, and 4 KiB costs about 4-5 times. See
  [Chunks, frames, and the MTU](PROTOCOL.md#chunks-frames-and-the-mtu).
- **Checks.** Read-back verification costs about 15% on Windows; it is
  noise-level on Linux. `--hash` costs another 10-15% for the sender's
  re-read.
- **Noise.** Single-connection disk rows on Windows varied widely
  (603-988 MiB/s). Treat differences under about 20% between rows as noise.
