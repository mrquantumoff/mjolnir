# Prior art: fast, encrypted, parallel bulk file transfer

Survey date: 2026-09-27. Status fields (latest release, last push) were read
from GitHub, PyPI and the project sites on that date. Every claim links to a
source in [References](#references). Where a source did not settle something,
the text says "not documented" instead of guessing.

The question: which existing tools move very large files quickly by splitting
them into chunks and sending the chunks over several connections or streams at
once, with encryption in transit? And is there room for Mjolnir
([PROTOCOL.md](PROTOCOL.md)): Noise IK with pinned X25519 keys, per-chunk AEAD,
N parallel TCP connections that each read, seal and send on their own thread,
positional writes on the receiver, and round-based resend with crash-safe
resume.

---

## 1. Comparison table

Legend: **Par** = how data is spread in parallel. "Intra-file" means one file
is split across connections or streams. "Inter-file" means only whole files go
in parallel.

| Tool | Encrypted by default? (crypto) | Peer authentication | Par | Chunk size tunable | Transport | Resume / integrity | License, language | Status (Sep 2026) |
|---|---|---|---|---|---|---|---|---|
| **Mjolnir** (this repo) | Yes. AES-256-GCM (default) or ChaCha20-Poly1305 on each chunk; keys from Noise IK + HKDF | Pinned static X25519 keys on both sides (`known_hosts`/`authorized_keys` style) | Intra-file, N TCP connections on one port, one thread each | Yes, 4 KiB to 64 MiB | TCP | Bitmap resume with fsync ordering; each chunk authenticated by AEAD with AAD bound to (session, file, index) | BSD-2-Clause, Rust | v0.2.0 (Sep 2026) |
| **mscp** [1][2][3] | Yes, SSH (cipher set with `-c`) | SSH (keys/password, via patched libssh) | Intra-file, N SSH/SFTP connections, `-n` default `floor(log(cores)*2)+1` | Yes, `-s` min (default 16 MiB) and `-S` max | TCP (SSH) | Checkpoint `-W`/resume `-R`; integrity is SSH's per-connection MAC | GPL-3.0, C | Active. v0.2.4 (2025-11-08), pushed 2026-07 [4] |
| **HPN-SSH** [5][6][7] | Yes, SSH. Adds multithreaded AES-CTR and ChaCha20 ciphers. An optional NONE cipher sends data in the clear after auth | SSH | **No.** One connection; the speedup comes from matching SSH window to TCP buffer and from parallel ciphers | No chunking (SSH buffers) | TCP (SSH) | `hpnscp` resume compares a BLAKE2b-512 hash of the file | BSD-style (OpenSSH), C | Very active. hpn-18.11.1 (2026-09-17), based on OpenSSH 10.5p1 |
| **bbcp** [8][9] | **No** for the data. SSH is used only to start the remote side; the help text has compression but no cipher option | SSH login to both ends | Intra-file, `-s` streams (default 4) | Yes, `-B` buffer size, `-w` window | TCP | `-a` append/restart; `-e`/`-E` MD5 and other checksums | GPL-3.0/LGPL files (GitHub mirror), C++ | Unmaintained. The SLAC page is gone; MPCDF lists it "only ... for legacy reasons" |
| **GridFTP (GCT)** [10][11] | Control channel yes. **Data channel is authenticated but not encrypted by default**; optional integrity or full encryption (PROT) | GSI X.509 certificates or SSH | Intra-file (parallel TCP streams, striping across nodes) | Yes (block/buffer settings) | TCP | Restart markers; checksums | Apache-2.0, C | Community fork (GCT) maintained. v6.2.20260123 |
| **Globus** (service) [12][13][14] | Control yes. **Data unencrypted by default** unless "encrypt transfer" is chosen or the collection sets `force_encryption` (always on for High Assurance) | Globus Auth identities + endpoint credentials | Intra-file parallelism + concurrency, tuned automatically | Managed by the service | GridFTP/UDT, HTTPS | Automatic retries for days; checksum verification | Proprietary SaaS (GCS agent) | Active commercial service |
| **Facebook WDT** [15][16][17] | Yes, AES-128-GCM by default (`encryption_type`, tag every 4 MiB) | **Shared secret**: the receiver makes a URL carrying a transfer id and the symmetric key, which is passed out of band | Intra-file, 8 TCP ports by default (`num_ports{8}`) | Yes, `block_size_mbytes` (default 16) | TCP | Download resumption is **off by default** (`enable_download_resumption{false}`); GCM gives integrity | Open source (custom LICENSE file), C++ (folly, glog) | Maintenance-only. Last release tag v1.27 (2016); 2026 commits are lint fixes |
| **IBM Aspera FASP** [18][19] | Yes, AES-128-GCM by default; AES-192/256, CFB or GCM | SSH (password or key); access keys/tokens in products | Rate-controlled UDP. Several `ascp` sessions can run on separate UDP ports | Datagram/rate tuning | UDP data + TCP/SSH control | Resume; per-datagram integrity check | Proprietary, patented | Active commercial product |
| **FileCatalyst / Signiant** [20][21] | Yes. AES-256 on data; TLS on control | Product accounts/portals | UDP acceleration (proprietary) | Vendor-tuned | UDP + TCP control | Guaranteed delivery, resume | Proprietary | Active commercial products |
| **FDT (Caltech)** [22][23][24] | **No data encryption documented.** Its security schemes cover authentication only (IP filter, SSH-started, GSI-SSH, GSI) | SSH or GSI; otherwise IP filter only | Intra-file, `-P` streams (default 4) | Yes, `-bs` buffer (default 512K) | TCP (Java NIO) | "Resumes ... without loss"; `-md5` per file | Apache-2.0, Java | Low activity. 0.27.0 (2024-11) |
| **rclone multi-thread** [25][26][27] | Depends on backend (SFTP = SSH, HTTPS for cloud) | Depends on backend | Intra-file only when the **destination** supports `OpenWriterAt`/`OpenChunkWriter` (local, s3, azureblob, b2, smb, ...). SFTP does **not** support multithread upload | Yes, `--multi-thread-chunk-size` (64 MiB), `--multi-thread-streams` (4) | TCP | Checksums/hash compare; no mid-file resume for a single transfer | MIT, Go | Very active. v1.75.1 (2026-09-04) |
| **lftp `pget` / `mirror --use-pget-n`** [28][29] | Yes over `sftp://` (SSH) or FTPS | SSH / TLS | Intra-file, **download only**, N connections (`pget -n`) | No (N segments) | TCP | `pget -c` with a `.lftp-pget-status` file | GPL-3.0, C++ | Slow. v4.9.3 (2024-11) |
| **croc** [30][31][32] | Yes. PAKE (default curve P-256) → AES-GCM (ChaCha20-Poly1305 code also present) | **PAKE code phrase** | Multiplexed over several relay TCP ports (default 9009-9013; `--no-multi` disables). Since 2026 defaults to TCP streams over an in-process Tailscale/WireGuard ("Tailcat") path via DERP | Not exposed | TCP via relay, or WireGuard/UDP when NAT traversal works | Resume supported; xxhash file hashes by default | MIT, Go | Very active. v11.5.4 (2026-09-26) |
| **magic-wormhole** [33][34][35] | Yes. SPAKE2 → NaCl secretbox (XSalsa20-Poly1305) records | **PAKE code** (16-bit default) | **No.** One transit connection (the sender picks the winner of racing sockets). "Dilation" adds durable subchannels on one connection | No | TCP, direct or transit relay | Classic file transfer: no resume documented; Dilation survives reconnects while both processes live | MIT, Python (Rust and Go ports) | Active. 0.24.0 (2026-05-05) |
| **iroh / sendme** [36][37][38][39][40] | Yes. QUIC + TLS 1.3 with raw public keys (Ed25519 endpoint IDs) | Endpoint public key inside a **ticket**; anyone holding the ticket can fetch | One QUIC connection with streams; iroh 1.x (noq fork of quinn) supports **QUIC multipath** | Fixed BLAKE3 chunk groups (16 KiB) | QUIC/UDP with hole punching, relay fallback | BLAKE3 verified streaming (Bao), resumable, content-addressed | Apache-2.0/MIT, Rust | Very active. iroh 1.0.0 (2026-06-15), 1.2.0 (2026-09-11); sendme v0.36.0 |
| **qcp** [41] | Yes. QUIC/TLS with self-signed certs swapped over the SSH pipe | SSH (bootstrap) | One QUIC session. `-j` sets how many files go at once (v0.9) | Tuning is by rate/RTT (`--rx/--tx/--rtt`), not chunk | QUIC/UDP (quinn) | Not documented beyond `--skip-existing` | AGPL-3.0, Rust | Active. v0.9.0 (2026-06-24) |
| **UDT** [42][43] | No (library, no crypto) | None | UDP with its own congestion control | App-level | UDP | Reliable stream only | BSD, C++ | Dead. 4.11 (2013) |
| **UFTP** [44][45] | **Off by default** (`-Y none`); optional AES-128/256-GCM/CCM, TLS-1.3-style key exchange | Optional RSA/ECDSA client keys (`-c`), fingerprints | Multicast to many receivers | Yes, `-b` block (default 1300 B) | UDP (multicast), TFMCC | Restart file (`-f`/`-F`); NAK-based repair | GPL, C | Dormant. 5.0.3 (2023-12) |
| **Tsunami UDP** [46][47] | **No** data encryption | Shared secret by XOR+MD5 challenge (hard-coded default `"kitten"`) | UDP blasting, TCP control | 32 KB blocks | UDP + TCP | Retransmit requests | Open source, C | Dead (last activity 2009-2011) |
| **parsyncfp / fpsync** [48][49][50] | Yes if rsync runs over SSH | SSH | **Inter-file only** (parallel rsync/tar/cpio jobs on fpart partitions) | No (file lists) | TCP (SSH) | rsync's delta and checksum | GPL-3.0 Perl / BSD-2 C | fpsync active (fpart 1.7.1, 2026-07); parsyncfp stale since 2022, succeeded by parsyncfp2 (2025) |
| **XRootD `xrdcp`** [51] | `roots://` TLS on control and data; `--tlsnodata` turns data encryption off | X.509 / tokens / others | Intra-file, `--streams` (max 15) | Server-side | TCP | `--continue`, `--cksum` (adler32/crc32/md5) | LGPL, C++ | Active. v5.9.8 (2026-09-25) |
| **Syncthing** [52] | Yes, TLS 1.3 | Device IDs (certificate hashes), pinned | `numConnections` (since v1.25) spreads requests over several TCP/QUIC connections; default 1 | Block size set automatically | TCP or QUIC, relays | Block hashes, resumable sync | MPL-2.0, Go | Very active. v2.1.x |
| **SimpleX XFTP** [53] | Yes. The **whole file** is encrypted first (NaCl secretbox), then split into padded chunks of 64 KB/256 KB/1 MB/4 MB; TLS + per-recipient crypto_box | Per-chunk Ed25519 access keys | Chunks go to several relays | Fixed size classes | HTTP/2 over TLS, via store-and-forward relays | Chunk digests | AGPL-3.0, Haskell | Active |

Also relevant, briefly:
- `scp-chunk` [54] splits a file and runs several `scp` processes.
- `aria2` [55] does segmented downloads over SFTP (and HTTP/FTP).
- `wormhole-william` (Go magic-wormhole), `portal` and Coder's `wush` (Tailscale/DERP-based) belong to the PAKE/NAT-traversal family [56].

---

## 2. Tool-by-tool notes

### mscp (multi-threaded scp)
- Copies files "over multiple SSH (SFTP) connections by multiple threads". Big files are cut into chunks that go in parallel [1].
- Chunk sizing: `-s` sets the minimum chunk (default 16 MiB). The maximum defaults to file size / connections / 4 [2].
- `-n` sets how many connections to open. `-u`/`-I` throttle SSH connection attempts so the server's MaxStartups and brute-force defenses are not tripped [2].
- Checkpoint (`-W`) and resume (`-R`) exist [2].
- It needs a patched libssh and a standard `sshd` on the far side [1].
- The PEARC '23 paper reports mscp at up to 240 times faster than scp in the Data Mover Challenge 2023 [3].
- This is the closest match to Mjolnir in *security model and use case*: key-authenticated, host-to-host, intra-file parallel over TCP. The difference is that every data connection is a full SSH session.

### HPN-SSH
- A soft fork of OpenSSH that sizes the application receive buffer to match the TCP buffer. It reports up to more than 100 times OpenSSH's throughput on some paths [5].
- Multithreaded AES-CTR and ChaCha20 (the default) give a typical 30% gain [5].
- Parallel ciphers are unavailable in FIPS mode [6].
- `NoneEnabled`/`NoneSwitch` send data in the clear after authentication. `NoneMacEnabled` also drops integrity [6].
- `hpnscp` resumes by comparing BLAKE2b-512 hashes [6].
- It is *one* connection, not parallel streams. Releases track OpenSSH closely: 18.11.x is based on OpenSSH 10.5p1, September 2026 [7].

### bbcp
- The original SLAC page (`slac.stanford.edu/~abh/bbcp`) now redirects to a "no userdir" page.
- The source mirror's help text lists `-s` streams (default 4), `-w` window, `-B` buffer size, `-a` append/restart and `-e`/`-E` checksums. It has **no encryption option**. SSH (`ssh -x -a ...`) only starts the remote end [8].
- MPCDF keeps it "only ... for legacy reasons" [9].

### GridFTP / Globus
- GridFTP gets its speed from parallel TCP streams and striping over several nodes, with restart markers. Its data channel can be authentication-only, integrity-protected, or fully encrypted [10].
- Globus Toolkit itself reached end of life. The Grid Community Toolkit fork is still maintained (v6.2.20260123) [11].
- The Globus service: "By default the data channel is authenticated, but unencrypted." Encryption can be picked per transfer [12].
- A collection can set `force_encryption`, which is always on for High Assurance storage gateways. Data then goes over TLS 1.2 with OpenSSL ciphers [13].
- Globus uses "GridFTP and UDT", tunes parallelism and concurrency automatically, and retries for up to three days [14].

### Facebook WDT
- "An embeddable library (and command line tool) aiming to transfer data between 2 systems as fast as possible over multiple TCP paths" [15].
- Defaults from `WdtOptions.h` [16]:
  - `num_ports{8}`
  - `block_size_mbytes{16}`
  - `encryption_type = ENC_AES128_GCM`
  - `encryption_tag_interval_bytes{4 MiB}`
  - `enable_download_resumption{false}`
  - `enable_checksum{false}` ("redundant [with] gcm")
- The connection URL (`wdt://host?ports=...&id=...`) carries the transfer id, and the serialized encryption parameters include the key material. The key is therefore a bearer secret shared out of band. There are no long-term identities and no forward secrecy [16][17].
- Architecturally this is the **closest prior art**: N TCP connections, fixed-size blocks, AEAD, resumption. The last release tag is v1.27 (2016). 2026 commits are code-quality lint fixes.

### IBM Aspera FASP; FileCatalyst; Signiant
- FASP is patented, proprietary and UDP-based. Its rate control reacts to changes in delivery time, not to packet loss. Control runs over TCP/22 [19].
- `ascp` defaults to aes-128-gcm. It also offers 192/256-bit keys in CFB or GCM, and the server can force a stronger cipher [18].
- FileCatalyst: UDP acceleration, AES-256 on data, TLS 1.3 on control [20].
- Signiant: a proprietary UDP protocol, AES-256, TLS [21].
- These are the benchmark Mjolnir will be compared against on long-RTT, lossy paths, which is exactly where TCP is weakest.

### FDT (Caltech)
- Java NIO. "Transfers data in parallel on multiple TCP streams" [22].
- `-P` streams (default 4), `-bs` 512K buffers, `-md5` [24].
- Its security page covers authentication and authorization only: IP filter, SSH-started, GSI-SSH, Globus-GSI. No data-channel encryption is documented [23].

### rclone
- Multi-thread transfers begin above `--multi-thread-cutoff` (256M), with `--multi-thread-streams` 4 and `--multi-thread-chunk-size` 64Mi [25].
- They only happen when the destination backend implements `OpenWriterAt` or `OpenChunkWriter` [25].
- The overview table marks SFTP as **not** supporting MultithreadUpload [27].
- The SFTP backend pipelines up to `--sftp-concurrency` 64 outstanding requests per file, with 32 KiB packets [26].

### lftp
- `pget -n` downloads one file over several connections. `mirror --use-pget-n` does the same per file. `pget -c` resumes from a `.lftp-pget-status` file [28].
- It works over `sftp://`, so each segment is its own SSH connection [29]. Upload is not parallel.

### croc
- A code phrase drives a PAKE whose key is used for end-to-end encryption [30].
- The PAKE curve defaults to `p256` (`--curve`). File hashes default to xxhash. Multiplexing over relay ports is on unless `--no-multi` is set [31].
- The data AEAD is AES-GCM (`crypt.NewAESGCM`). A ChaCha20-Poly1305 path also exists [31][32].
- The relay uses TCP 9009-9013 [30].
- Since v11.3.3 (2026-08-28) the default `--transport auto` builds PAKE-bound "Tailcat" identities and runs TCP streams over an in-process Tailscale userspace WireGuard network. It starts on DERP and upgrades to direct UDP when NAT traversal succeeds [30].

### magic-wormhole
- SPAKE2 PAKE with a 16-bit code by default. Data is encrypted with NaCl secretbox [33].
- Transit races several sockets and keeps one, the first past negotiation. Each record costs 44 bytes of overhead, length prefix and nonce included [34].
- The Dilation protocol adds durable, reconnecting subchannels [35].
- No parallel data connections.

### iroh / sendme
- sendme uses iroh-blobs: "blake3 verified streaming, including resuming interrupted downloads". It does hole punching and falls back to a relay [36].
- iroh 1.0.0 shipped 2026-06-15 [37].
- iroh dials by Ed25519 key and uses raw public keys in TLS [38].
- It runs on noq, n0's fork of quinn with full QUIC Multipath and QUIC NAT traversal [39].
- iroh-blobs keeps outboards at 16 KiB chunk groups [40].
- This is the most modern design in the list: content-addressed, verified, resumable, NAT-traversing. Its throughput is bounded by one QUIC connection's congestion control and user-space UDP processing (see §3).

### qcp
- Starts over SSH, then "both sides generate a TLS key and exchange self-signed certs over the ssh pipe" and move the files over QUIC [41].
- It is tuned by bandwidth and RTT. NewReno is an option. v0.9 added `-j` for parallel transfers.
- It needs inbound UDP that is not NATed [41].

### UDT, UFTP, Tsunami
- UDT is a UDP congestion-control library with no crypto. The last release is 4.11 (2013) [42][43].
- UFTP multicasts files. It is **unencrypted by default** (`-Y none`), with optional AES-GCM/CCM, RSA or ECDSA client authentication, 1300-byte blocks, TFMCC congestion control and restart files [44][45].
- Tsunami blasts UDP in 32 KB blocks. Its only authentication is a shared secret checked with an XOR+MD5 challenge, default `"kitten"`. There is no data encryption [46][47].

### parsyncfp / fpsync
- Both run many rsync (or tar/cpio) jobs over file partitions built by fpart. The parallelism is **per file**, so one huge file gets no speedup [48][49][50].

### QUIC-based options in general
- QUIC gives TLS 1.3, stream multiplexing, connection migration and (with multipath) several paths. All of that sits on one congestion-controlled connection per path.
- Most stacks do packet protection and ACKs in user space. The WWW '24 paper "QUIC is not Quick Enough over Fast Internet" measured up to **45.2% lower data rate** than TCP+TLS+HTTP/2 on fast links. It traced the gap to receiver-side overhead: too many packets and user-space ACKs [57].
- Several QUIC connections, or TCP with kernel offloads, remain the practical way to fill 10-100 Gbit/s links from one host.

---

## 3. Is there a gap for Mjolnir?

### What Mjolnir combines
1. **No SSH dependency, no PKI, no bearer secrets.** It uses WireGuard-style pinned static keys with Noise IK: mutual authentication, forward secrecy, and one round trip for the handshake.
2. **Intra-file parallelism over N TCP connections on a single port.** Admission uses a cheap HMAC over a fresh challenge, so there is no second handshake per connection.
3. **Per-chunk AEAD with keys derived per (round, connection).** Connections never coordinate nonces, so the crypto scales with cores the way mscp scales by running N SSH sessions. There is no SSH channel/window layer and no SFTP request/response round trips.
4. **Position-bound chunks.** The AAD covers session_id, file_id and chunk_index, so a chunk cannot be replayed into another session or moved to another offset. Positional writes into a sparse part file.
5. **Crash-safe resume.** The bitmap is snapshotted, then the data is fsynced, then the state file is atomically replaced. Round-based resend of whatever is missing.
6. **Tunable chunk size** from 4 KiB to 64 MiB. **AES-256-GCM** by default.

### Which existing tool is closest
- **By architecture: Facebook WDT.** It has N TCP ports (8), 16 MiB blocks, AES-GCM and download resumption. But its authentication is a **symmetric key inside a URL** passed out of band, with no identities and no forward secrecy. Resumption is off by default, it needs 8 ports, it is a C++/folly build, and it is effectively in maintenance mode since 2016 [15][16].
- **By security model and use case: mscp.** It has key-authenticated, host-to-host, intra-file parallel TCP with tunable chunks and checkpoint/resume. But every connection is a full SSH session, which needs `sshd`, a patched libssh, and MaxStartups throttling. There is no Windows build in its README [1][2].
- Honourable mentions:
  - HPN-SSH, for single-stream speed.
  - croc and sendme, for "just works" peer-to-peer transfer with NAT traversal.
  - XRootD, for TLS with parallel streams in HEP.

**Verdict:** the gap is real but narrow. No maintained, standalone, open-source tool found here combines modern public-key mutual authentication (Noise/WireGuard style), intra-file parallel TCP, independent per-chunk AEAD, and crash-safe resume in one small cross-platform binary. WDT comes closest and is weaker on authentication and maintenance. mscp covers the same ground by sitting on SSH. The niche is **server-to-server or workstation-to-server bulk moves over high-bandwidth-delay-product links where you control both ends and can open one TCP port.**

### What Mjolnir has to beat them on (and prove with numbers)
- **Throughput per host at 10/25/100 Gbit/s**, and CPU cost per GB, against mscp, HPN-SSH (parallel ciphers), WDT, rclone/lftp over SFTP, croc, sendme and qcp. Use the same hardware, with `netem` RTTs of 1/50/150/300 ms and loss of 0 / 0.01% / 0.1% / 1%.
  - AES-256-GCM with AES-NI/VAES should reach several GB/s per core. The per-chunk design has to actually scale linearly with N and cores: no global lock on the file, and no serialized writes.
- **Setup cost.** One Noise handshake plus N HMAC admissions, against N SSH handshakes (mscp) or N segment logins (lftp). Many small files: check manifest size and the per-file cost of the round logic.
- **Resume correctness.** `kill -9` the receiver and pull power in the middle of a transfer. Resume must never report a chunk that is not on disk, and must re-send only what is missing. mscp, WDT and lftp have not been tested this way in public.
- **Operability.**
  - One port, where WDT uses 8, croc 5, and GridFTP and FDT need data-port ranges.
  - One static binary for Linux, macOS and Windows.
  - Key files that feel like WireGuard/SSH.
  - Clear error messages.
- **Straggler handling.** Chunks should be pulled from a shared queue (work stealing), not pre-assigned. Otherwise one slow TCP flow holds up the whole round. The spec does not say how chunks are distributed. That choice drives tail latency on real WAN paths, which is where mscp and WDT compete.

### Where Mjolnir is honestly worse
- **No NAT traversal or relay.** The receiver must accept inbound TCP. croc (DERP/WireGuard plus its own relay), sendme/iroh (hole punching plus relay), magic-wormhole (transit relay) and Syncthing all work between two NATed laptops. Mjolnir does not (PROTOCOL.md says so).
- **No short-code pairing (PAKE).** Keys must be swapped ahead of time, which is fine for servers and clumsy for ad-hoc person-to-person sends.
- **TCP congestion control, not UDP rate control.**
  - On long, lossy paths, each TCP flow's loss-based congestion control (CUBIC; BBR if the OS is set up for it) backs off. FASP, FileCatalyst, Signiant, UDT and Tsunami keep sending at the measured capacity.
  - N parallel flows cover much of this gap, which is why GridFTP, bbcp, WDT and mscp all use them.
  - But they take N shares of a shared bottleneck, which is unfair to other traffic. They also still suffer at high loss.
  - There is no multipath across interfaces, which iroh 1.x has.
- **No SSH ecosystem.** mscp, HPN-SSH, lftp and rclone reuse existing `sshd`, keys, agents, bastions, FIDO tokens and audit logging. Mjolnir needs its own listener and its own key distribution. Revocation means editing a file.
- **One transfer at a time.** A receiver serves one transfer, then exits, or with `--keep-listening` serves transfers one after another. There are no concurrent sessions, no multi-tenant access control, no third-party transfers (GridFTP/Globus/FDT do these) and no multicast (UFTP).
  - A bogus or unauthorized handshake does not end a waiting receiver: it drops that connection, logs it, and keeps listening, as does a failed session. Only a finished transfer (without `--keep-listening`) or a local cancel ends it.
- **Integrity scope.** The per-chunk AEAD proves that chunks arrived intact from the authenticated sender. Some gaps remain:
  - The sender compares each file's size and mtime with the offer after every round, so a source that grows, shrinks or is touched during the transfer fails it. A change that keeps both goes unnoticed unless `--hash` is on, which re-reads every file after delivery and sends again each chunk whose digest differs. `file_hash` is a BLAKE3 over those chunk digests, not a hash of the file's bytes (compare sendme's BLAKE3 root or `hpnscp`'s BLAKE2b).
  - Resumed data is read back and checked by default, like every chunk. It is checked against digests saved by the earlier session, though, so this proves the bytes are what arrived then, not that they still match the source. Only `--hash` compares them with fresh digests from the sender.
  - Resume matching uses `size`, `mtime` and `chunk_size` only.
- **Metadata leakage.** File sizes and timing are visible, since there is no padding. XFTP pads its chunks [53].
- **Maturity.** Every tool above has years of field use or a published evaluation (mscp: PEARC '23; WDT: Facebook production; FASP: industry standard). Mjolnir has none yet.

### Bottom line
Build it if the target is "the fastest *self-contained*, key-pinned, resumable host-to-host copy over fat TCP pipes". Measure it first against **mscp**, the incumbent open tool in this niche, and **WDT**, the architectural twin. If it cannot clearly beat mscp on throughput per core and on resume robustness, the operational cost of not being SSH will be hard to justify. Anything that needs NAT traversal, ad-hoc pairing or lossy intercontinental links belongs to croc, sendme or iroh, or to commercial UDP accelerators.

---

## References

1. mscp README: https://github.com/upa/mscp
2. mscp manual (`-n`, `-s`, `-S`, `-W`, `-R`, `-c`, `-u`, `-I`): https://github.com/upa/mscp/blob/main/doc/mscp.rst
3. Nakamura & Kuga, "Multi-threaded scp: Easy and Fast File Transfer over SSH", PEARC '23: https://doi.org/10.1145/3569951.3597582 ; Data Mover Challenge note: https://www.itc.u-tokyo.ac.jp/en/blog/2024/02/22/post-20182/
4. mscp releases: https://github.com/upa/mscp/releases
5. HPN-SSH README: https://github.com/rapier1/hpn-ssh
6. HPN-README (FIPS/parallel ciphers, NONE cipher, hpnscp resume): https://github.com/rapier1/hpn-ssh/blob/master/HPN-README
7. HPN-SSH releases: https://github.com/rapier1/hpn-ssh/releases
8. bbcp source mirror, option help in `src/bbcp_Config.C`: https://github.com/eeertekin/bbcp
9. MPCDF data transfer tools: https://docs.mpcdf.mpg.de/doc/data/data-transfer/data-transfer.html
10. GCT GridFTP key concepts: https://gridcf.org/gct-docs/latest/gridftp/key/index.html
11. Grid Community Toolkit: https://github.com/gridcf/gct
12. Globus security FAQ: https://docs.globus.org/faq/security/
13. Globus collection `force_encryption` / High Assurance: https://docs.globus.org/globus-connect-server/v5/reference/collection/create/ ; https://docs.globus.org/guides/overviews/security/high-assurance-overview/
14. Globus transfer FAQ: https://docs.globus.org/faq/transfer-sharing/
15. WDT README: https://github.com/facebook/wdt
16. WDT defaults: https://github.com/facebook/wdt/blob/main/WdtOptions.h ; encryption params: https://github.com/facebook/wdt/blob/main/util/EncryptionUtils.cpp
17. WDT CLI wiki (URL format, 8 ports): https://github.com/facebook/wdt/wiki/Getting-Started-with-the-WDT-command-line ; releases: https://github.com/facebook/wdt/releases
18. IBM Aspera `ascp` reference (cipher defaults): https://www.ibm.com/docs/en/ahts/4.4.x?topic=atfcl-ascp-command-reference-2
19. FASP overview: https://en.wikipedia.org/wiki/Fast_and_Secure_Protocol ; IBM FASP security model: https://www.ibm.com/downloads/cas/QGRQMREW
20. FileCatalyst: https://www.goanywhere.com/products/filecatalyst ; https://www.goanywhere.com/products/goanywhere-mft/connectivity/filecatalyst-service
21. Signiant Media Shuttle: https://www.signiant.com/resources/articles/the-magic-behind-media-shuttle-file-transfers-acceleration-reliability-and-security/
22. FDT README: https://github.com/fast-data-transfer/fdt
23. FDT security: https://github.com/fast-data-transfer/fdt/blob/master/docs/doc-security.md
24. FDT options: https://github.com/fast-data-transfer/fdt/wiki/FDT-command-options
25. rclone global flags (multi-thread): https://rclone.org/docs/
26. rclone SFTP backend: https://rclone.org/sftp/
27. rclone backend feature matrix: https://rclone.org/overview/
28. lftp manual: https://lftp.yar.ru/lftp-man.html
29. lftp pget over SFTP: https://brandonrozek.com/blog/parallel-scp/
30. croc README: https://github.com/schollz/croc
31. croc CLI defaults (`--curve p256`, `--no-multi`, `--hash xxhash`): https://github.com/schollz/croc/blob/main/src/cli/cli.go ; releases: https://github.com/schollz/croc/releases
32. croc crypt package: https://pkg.go.dev/github.com/schollz/croc/v11/src/crypt
33. magic-wormhole overview: https://magic-wormhole.readthedocs.io/en/latest/welcome.html
34. magic-wormhole Transit: https://magic-wormhole.readthedocs.io/en/latest/transit.html
35. magic-wormhole Dilation: https://magic-wormhole.readthedocs.io/en/latest/dilation-protocol.html ; PyPI: https://pypi.org/project/magic-wormhole/
36. sendme README: https://github.com/n0-computer/sendme
37. iroh releases: https://github.com/n0-computer/iroh/releases ; "The road to iroh 1.0": https://www.iroh.computer/blog/the-road-to-iroh-1-0
38. iroh raw public keys in TLS: https://www.iroh.computer/blog/iroh-0-34-0-raw-public-keys
39. noq (QUIC multipath fork): https://www.iroh.computer/blog/noq-announcement ; https://www.iroh.computer/blog/iroh-on-QUIC-multipath
40. iroh-blobs design (16 KiB chunk groups): https://www.iroh.computer/blog/blob-store-design-challenges ; https://github.com/n0-computer/iroh-blobs
41. qcp: https://github.com/crazyscot/qcp
42. UDT: https://en.wikipedia.org/wiki/UDP-based_Data_Transfer_Protocol
43. UDT project: https://udt.sourceforge.io/
44. UFTP: https://uftp-multicast.sourceforge.net/
45. uftp(1): https://manpages.ubuntu.com/manpages/jammy/man1/uftp.1.html
46. Tsunami UDP: https://tsunami-udp.sourceforge.net/
47. Tsunami README (authentication): https://github.com/res0nat0r/tsunami-udp
48. parsyncfp: https://github.com/hjmangalam/parsyncfp
49. parsyncfp2: https://github.com/hjmangalam/parsyncfp2
50. fpart / fpsync: https://github.com/martymac/fpart
51. xrdcp(1): https://www.mankier.com/1/xrdcp
52. Syncthing numConnections: https://docs.syncthing.net/advanced/device-numconnections.html
53. SimpleX XFTP protocol: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/xftp.md
54. scp-chunk: https://github.com/sohonetlabs/scp-chunk
55. aria2c manual: https://aria2.github.io/manual/en/html/aria2c.html
56. wormhole-william: https://github.com/psanford/wormhole-william ; portal: https://github.com/SpatiumPortae/portal ; wush: https://github.com/coder/wush
57. Zhang et al., "QUIC is not Quick Enough over Fast Internet", WWW '24: https://arxiv.org/abs/2310.09423
