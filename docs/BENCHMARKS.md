# Benchmarks

Measured on 2026-09-28 at commit 4daa636, with
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
26200), Rust 1.98.1, Samsung 970 EVO Plus 2 TB NVMe. The source file was in
the page cache. The WSL2 VM was running during the Windows rows and both
OSes share the drive.

## Windows

Native Windows build, run from Git Bash. The data lived in `%LOCALAPPDATA%\Temp`
on the system drive.

Raw disk after a 60 s rest: **1 writer 868 MiB/s** (482-1281), 8 writers
1209 MiB/s (443-1282).

| connections | threads | chunk | cipher | verify | hash | mode | files | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 823 (641-830) | 956 (726-973) | 1.0 | 1.3 | 23 |
| 4 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 783 (686-798) | 891 (776-910) | 0.8 | 1.3 | 22 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 786 (779-848) | 893 (889-960) | 0.9 | 1.4 | 25 |
| 16 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 771 (693-784) | 875 (779-892) | 0.9 | 1.4 | 26 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 16x128MiB | 1059 (1056-1061) | 1276 (1269-1282) | 2.8 | 3.5 | 33 |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 64x32MiB | 718 (590-742) | 872 (768-921) | 1.6 | 2.4 | 28 |
| 8 | auto | 4K | aes256gcm | on | off | disk | 1 | 156 (147-167) | 204 (194-223) | 1.5 | 1.6 | 30 |
| 8 | auto | 16K | aes256gcm | on | off | disk | 1 | 379 (291-428) | 494 (450-564) | 1.1 | 1.5 | 26 |
| 8* | auto | 256K | aes256gcm | on | off | disk | 1 | 780 (727-914) | 891 (831-1096) | 0.8 | 1.4 | 19 |
| 8* | auto | 4MiB | aes256gcm | on | off | disk | 1 | 927 (868-934) | 1110 (1018-1125) | 0.8 | 1.6 | 22 |
| 8* | auto | 1MiB | chacha20poly1305 | on | off | disk | 1 | 918 (906-929) | 1077 (1062-1086) | 1.0 | 1.6 | 22 |
| 8* | auto | 1MiB | aes256gcm | off | off | disk | 1 | 1079 (1035-1120) | 1086 (1044-1131) | 1.0 | 1.6 | 25 |
| 8* | auto | 1MiB | aes256gcm | on | on | disk | 1 | 851 (823-855) | 1156 (1115-1165) | 1.1 | 1.3 | 19 |
| 8* | auto | 1MiB | aes256gcm | off | off | memory | 1 | 877 (850-906) | 1091 (1065-1137) | 1.1 | 1.6 | 21 |
| 8 | auto | 1MiB | aes256gcm | off | off | discard | 1 | 3553 (3423-3662) | 3631 (3559-3753) | 4.6 | 3.6 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | memory+discard | 1 | 2031 (1994-2056) | 3800 (3648-3866) | 4.2 | 7.0 | 47 |
| 1 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1076 (1074-1079) | 1424 (1418-1435) | 1.3 | 1.1 | 23 |
| 1 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1323 (1088-1416) | 1890 (1457-2066) | 1.7 | 1.9 | 30 |
| 1 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1598 (1474-1694) | 2486 (2267-2758) | 2.0 | 2.3 | 31 |
| 1 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1627 (1599-1792) | 2559 (2518-3015) | 1.9 | 2.2 | 26 |
| 2 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1079 (1032-1083) | 1439 (1434-1443) | 1.2 | 1.2 | 27 |
| 2 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1686 (1555-1790) | 2945 (2455-3029) | 2.1 | 2.6 | 35 |
| 2 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1462 (1326-1618) | 2218 (2137-2568) | 1.9 | 2.6 | 36 |
| 2 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1025 (1019-1333) | 1497 (1417-1978) | 1.6 | 1.9 | 65 |
| 1 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 660 (580-975) | 954 (691-1276) | 1.0 | 0.8 | 39 |
| 1 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1180 (1051-1205) | 1654 (1447-1753) | 1.3 | 1.3 | 44 |
| 1 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1212 (974-1527) | 1853 (1307-2430) | 1.5 | 1.6 | 31 |
| 1 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1117 (947-1370) | 1518 (1257-2032) | 1.4 | 1.4 | 40 |
| 2 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 952 (943-993) | 1235 (1231-1292) | 1.2 | 1.1 | 32 |
| 2 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1606 (1551-1727) | 2557 (2383-2969) | 2.2 | 2.6 | 27 |
| 2 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1430 (991-1655) | 2118 (1285-2677) | 1.7 | 2.0 | 28 |
| 2 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1495 (1399-1600) | 2322 (2136-2621) | 2.2 | 2.9 | 31 |

The six rows marked with an asterisk drifted into the drive's slow state
during the sweep (see "Noise and the drive") and were rerun in a second
block after a five-minute rest, with PAUSE=45.

## Linux (WSL2)

WSL2 kernel 6.18.33.2 with 32 vCPUs and 31 GiB RAM. The Linux build, the
clone and the data all lived in the Linux home directory, on the WSL ext4
virtual disk, not under `/mnt/c` (which is much slower for I/O). WSL2 runs
in a VM, so bare-metal Linux may differ.

Raw disk after a 60 s rest: **1 writer 1311 MiB/s** (1099-1793), 8 writers
1631 MiB/s (1289-1666).

| connections | threads | chunk | cipher | verify | hash | mode | files | MiB/s, median (min-max) | transfer phase MiB/s, median (min-max) | sender cores | receiver cores | machine CPU % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 844 (382-884) | 867 (386-905) | 0.7 | 1.6 | - |
| 4 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 848 (689-872) | 869 (709-892) | 0.8 | 1.6 | - |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 744 (644-844) | 758 (655-863) | 0.7 | 1.4 | - |
| 16 | auto | 1MiB | aes256gcm | on | off | disk | 1 | 845 (824-848) | 864 (850-867) | 0.9 | 1.7 | - |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 16x128MiB | 1090 (988-1122) | 1143 (1032-1178) | 3.4 | 5.1 | - |
| 8 | auto | 1MiB | aes256gcm | on | off | disk | 64x32MiB | 725 (674-726) | 805 (741-818) | 2.5 | 3.9 | - |
| 8 | auto | 4K | aes256gcm | on | off | disk | 1 | 154 (152-162) | 156 (153-163) | 1.3 | 2.8 | - |
| 8 | auto | 16K | aes256gcm | on | off | disk | 1 | 406 (404-406) | 412 (408-412) | 1.1 | 2.4 | - |
| 8 | auto | 256K | aes256gcm | on | off | disk | 1 | 737 (732-739) | 752 (747-753) | 0.8 | 1.6 | - |
| 8 | auto | 4MiB | aes256gcm | on | off | disk | 1 | 807 (806-809) | 838 (836-842) | 1.3 | 1.9 | - |
| 8 | auto | 1MiB | chacha20poly1305 | on | off | disk | 1 | 701 (631-804) | 714 (641-822) | 0.8 | 1.5 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | disk | 1 | 853 (829-865) | 856 (832-868) | 0.9 | 1.4 | - |
| 8 | auto | 1MiB | aes256gcm | on | on | disk | 1 | 782 (736-795) | 812 (770-827) | 1.3 | 1.6 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | memory | 1 | 538 (510-551) | 842 (772-862) | 0.9 | 1.4 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | discard | 1 | 3713 (3519-3769) | 3757 (3560-3826) | 5.5 | 5.2 | - |
| 8 | auto | 1MiB | aes256gcm | off | off | memory+discard | 1 | 762 (496-928) | 1487 (596-2778) | 1.7 | 2.2 | - |
| 1 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 922 (660-957) | 1366 (869-1430) | 1.1 | 1.2 | - |
| 1 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 995 (921-1596) | 1579 (1359-3688) | 1.3 | 1.4 | - |
| 1 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1263 (1052-1485) | 3614 (1691-3700) | 1.9 | 3.2 | - |
| 1 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1516 (1042-1526) | 3252 (2514-3450) | 2.1 | 3.0 | - |
| 2 | 1 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 926 (768-938) | 1414 (1410-1427) | 1.2 | 1.2 | - |
| 2 | 4 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1721 (1384-1802) | 5012 (4928-5079) | 2.5 | 4.6 | - |
| 2 | 16 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1579 (1394-1877) | 5583 (5545-5625) | 2.5 | 5.6 | - |
| 2 | 32 | 1MiB | aes256gcm | off | off | memory+discard | 1 | 1443 (1221-1797) | 5613 (5007-5726) | 2.6 | 5.6 | - |
| 1 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 813 (759-914) | 1294 (1287-1319) | 1.1 | 1.2 | - |
| 1 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1259 (1192-1602) | 3448 (3323-3531) | 2.0 | 3.2 | - |
| 1 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1522 (1196-1564) | 3356 (3298-3401) | 2.2 | 3.2 | - |
| 1 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1436 (1224-1535) | 3361 (3269-3389) | 2.1 | 3.2 | - |
| 2 | 1 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 891 (796-894) | 1305 (1176-1308) | 1.1 | 1.2 | - |
| 2 | 4 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1758 (1490-1798) | 4637 (4617-4794) | 2.6 | 4.6 | - |
| 2 | 16 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1806 (1527-1920) | 5451 (5413-5642) | 2.9 | 5.9 | - |
| 2 | 32 | 1MiB | chacha20poly1305 | off | off | memory+discard | 1 | 1861 (1485-1880) | 5109 (4948-5631) | 2.9 | 5.8 | - |

## What changed since the last run

The tables at b8f5e18 showed the receive write path as the bottleneck:
Linux disk rows got slower with more connections (1950, 1696, 1167 and
888 MiB/s at 1, 4, 8 and 16) while the receiver burned 9-12 cores. Two
changes since then, each measured on its own:

- **One writer per part file (bf429cd).** Every pool worker used to write
  chunks into the same file at once. Concurrent positional writes into one
  file serialize on the inode lock anyway, and on ext4 the waiters spin. A
  standalone pwrite benchmark reproduced it without mjolnir: 32 threads
  writing 1 MiB blocks into one 2 GiB file ran at 830 MiB/s and 15 cores,
  one thread at 1.2 GiB/s and 0.3 cores; capping the writers at 1 or 2
  restored both. In mjolnir, on the same day and the same drive state,
  the receiver went from 6.8, 7.2, 7.3 and 12.2 cores (1, 4, 8 and 16
  connections) to 1.4-1.9 cores, and the rate stopped falling with the
  connection count. Windows never had the CPU problem (NTFS does not spin)
  and showed no change either way. The chunk write and the digest write
  now happen under a per-file gate; the claim, the present bit, and the
  checkpoint order are unchanged.
- **Files move in parallel (9ac5521).** The sender's scheduler gives each
  connection one file's chunks in order and takes the largest unowned file
  next, so a directory transfer no longer sends its files one after
  another. The 64 x 32 MiB row gained about 50-70% on both OSes (Linux
  411 to 692 MiB/s, Windows 472 to 707, measured in the same session
  before and after), the 16 x 128 MiB row 10-30%. Single-file rows did not
  change outside noise in interleaved A/B runs.

## What the numbers show

- **The drive is now the limit with a disk in the loop.** Both OSes write
  one file at 750-850 MiB/s end to end from 1 to 16 connections, with the
  receiver at 1.3-1.7 cores, and the rerun Windows rows, after a longer
  rest, at 850-1080. The 16-file rows reach 1059-1090 MiB/s, the best disk
  rows on either OS: NTFS and ext4 both write several files faster than
  one. Today's raw disk figures (0.9-1.3 GiB/s with fsync) are well below
  the 2.0 GiB/s the same drive gave at b8f5e18; see the noise section.
- **Crypto scales with cores, up to what the network threads can feed.**
  Without disk, one connection goes from about 1.4 GiB/s on 1 worker to
  about 3.3-3.6 GiB/s on 16 or more on Linux (1.4 to 2.5 GiB/s on
  Windows). Two connections reach about 5.6 GiB/s on Linux and 2.2-2.9
  GiB/s on Windows. AES-256-GCM and ChaCha20-Poly1305 land within about
  10% of each other. The 8-connection discard rows run at 3.5-3.6 GiB/s
  on both OSes.
- **Chunk size.** 256 KiB to 4 MiB perform alike on Linux. 16 KiB costs
  about half the throughput, and 4 KiB about 4-5 times. See
  [Chunks, frames, and the MTU](PROTOCOL.md#chunks-frames-and-the-mtu).
- **Checks.** Read-back verification and `--hash` each cost about 10%
  on Linux. The Windows rows for them come from the rested second block,
  so they cannot be compared with the first block's verify-on row.

## Noise and the drive

Rates on this machine swing 2-3x between identical runs once the drive
has absorbed a few tens of GiB: a sweep writes 32 rows x 3 x 2 GiB. After
a rest of a few minutes the fast state returns (a page-cache write
microbenchmark gave 1018 and 1374 MiB/s with fsync after resting, and
330-1258 without). The drive's temperature is not readable without admin
rights, so this is attributed to the SSD's write cache and heat, not
measured. Hence PAUSE=20 before each disk run, one OS per block, rests
between blocks, and medians with ranges. Treat differences under about
20% between disk rows as noise, and use the CPU columns, which are
stable, when comparing builds. The no-disk rows do not touch the drive,
so its state does not explain their spread, but they are not steady
either: on Linux, `memory+discard` at 8 connections ranged from 596 to
2,778 MiB/s in the transfer phase across its three runs. Read them by
median and range like the disk rows; the tables keep each row's range.

One NTFS effect is worth knowing and was left alone: writing far past
the valid data length of a pre-sized file makes NTFS zero-fill up to
there. With N connections on one file the receiver now writes N regions
of the file at once, and the page-cache phase of the microbenchmark
halved (2262-2620 MiB/s against 3979-4353 for near-sequential writes;
a sparse file restores 3373-4304). The zeros are overwritten before the
2 s checkpoint flushes more than a fraction of them, and an interleaved
A/B of the two builds showed no end-to-end difference, so it costs
memory bandwidth, not disk time, and no Windows-only ioctl was added.
