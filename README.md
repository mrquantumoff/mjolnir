# mjolnir

mjolnir copies large files between two hosts you control. It splits each
file into chunks, encrypts every chunk on its own with an AEAD, and sends
them over several TCP connections at once. The receiver decrypts each chunk
and writes it at its offset. Both hosts authenticate with static key pairs,
and an interrupted transfer resumes where it stopped.

It also forwards TCP ports, like `ssh -L` and `ssh -R`, over the same
authenticated sessions, and can stripe one TCP stream across several
connections; see [Tunnels](#tunnels).

## Install

Releases ship prebuilt binaries for Linux, macOS, and Windows on x86_64
and aarch64. The install scripts download the latest one from the release's
public URLs, check it, and install it. No GitHub account, login, or token is
needed.

Each release holds a `SHA256SUMS` file and `SHA256SUMS.sig`, an ECDSA P-256
signature of it. The release's public key is written into both scripts and
into the binary. The scripts check the signature first and refuse the
release if it is missing or does not verify, then check the archive against
its `SHA256SUMS` line. `install.ps1` verifies with .NET and always checks
the signature. `install.sh` verifies with `openssl`; on a system without
`openssl` it prints a warning and checks only the checksum, which guards
against a corrupt download but not against a swapped release. Releases up
to v0.2.0 carry no signature, so the scripts refuse to install them.

On Linux and macOS, [`scripts/install.sh`](scripts/install.sh) installs to
`~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/mrquantumoff/mjolnir/master/scripts/install.sh | bash
```

On Windows, [`scripts/install.ps1`](scripts/install.ps1) installs to
`%LOCALAPPDATA%\Programs\mjolnir` and adds that folder to the user `PATH`:

```powershell
irm https://raw.githubusercontent.com/mrquantumoff/mjolnir/master/scripts/install.ps1 | iex
```

Both scripts read `MJOLNIR_VERSION` to install a specific tag instead of
the latest, and `MJOLNIR_INSTALL_DIR` to install somewhere else.
`MJOLNIR_REPO` downloads from a fork instead, and `MJOLNIR_RELEASE_KEY` then
replaces the release key with the fork's; the scripts ignore it for the
default repository. From a checkout, run either script directly;
`install.ps1` also takes `-Version`, `-InstallDir`, and `-Repo`.

To build from source instead, run `cargo build --release`; the binary lands
in `target/release`.

### Updating

`mjolnir update` replaces the running binary with the latest release, and
`mjolnir update --check` only reports whether one exists. It reads the
latest tag from GitHub's `releases/latest` redirect and downloads
`SHA256SUMS` and `SHA256SUMS.sig` from the public release URLs with the
system's `curl`. It refuses the release unless `SHA256SUMS.sig` is a valid
signature of `SHA256SUMS` by the release key built into the binary. Then it
downloads this platform's archive, refuses it if it does not match its
`SHA256SUMS` line, unpacks it with the system's `tar`, and swaps the new
binary in only after it runs `--version`. Windows 10 and later ship both
tools; on Windows the old binary is moved to `mjolnir.exe.old` and deleted
on the next run. It never downgrades, and it refuses on platforms that have
no release build.

`MJOLNIR_RELEASES_URL` points it at a fork or mirror with the same layout.
A mirror of the official releases needs nothing else. A fork that signs its
own releases also sets `MJOLNIR_RELEASE_KEY` to its public key, in the
format of `RELEASE_KEY` in [`src/update.rs`](src/update.rs). The binary
ignores `MJOLNIR_RELEASE_KEY` unless `MJOLNIR_RELEASES_URL` is set.

The updater is the `self-update` Cargo feature, on by default. Packagers who
ship mjolnir through a package manager should build without it, which
removes the `update` command:

```sh
cargo build --release --no-default-features
```

## Quick start

On each host, create a key pair. `keygen` writes the private key and prints
the public key:

```sh
mjolnir keygen --out mjolnir.key
```

Swap public keys through any channel you trust. On the receiver, allow the
sender's key and start listening:

```sh
mjolnir recv --key mjolnir.key --allow <SENDER_PUBLIC_KEY> --out ./incoming
```

On the sender, pin the receiver's key and send files or directories:

```sh
mjolnir send receiver.example:7777 --key mjolnir.key \
    --peer <RECEIVER_PUBLIC_KEY> big.iso photos/
```

Both sides print progress to stderr about once a second and a summary line
at the end.

## Commands and flags

`mjolnir keygen [--out PATH]` writes a new private key (default
`mjolnir.key`) and prints its public key. It refuses to overwrite an
existing file. On Unix the file has mode `0600`. On Windows it gets an
access list of its own, inheriting nothing from its folder, that grants
only your account, SYSTEM, and Administrators. Every command that reads a
key refuses one that other accounts can read or change, and says how to
restrict it (`chmod 600` or `icacls`).

`mjolnir pubkey --key PATH` prints the public key of an existing private
key.

`mjolnir recv` receives one transfer, or with `--keep-listening` one
transfer after another:

| Flag | Default | Meaning |
|---|---|---|
| `--key PATH` | required | this host's private key |
| `--authorized FILE` | | allowed sender keys, one `[options] <base64> [comment]` per line; `#` comments and blank lines are ignored. A line with tunnel options (see [Tunnels](#tunnels)) sends files only if it also says `transfer` |
| `--allow KEY` | | allow one sender key; repeatable |
| `--listen ADDR` | `0.0.0.0:7777` | address to listen on |
| `--out DIR` | `.` | where files land |
| `--force` | off | overwrite existing files; without it a file that appears at the destination during the transfer fails the transfer instead of being replaced |
| `--no-verify` | off | skip reading every chunk back before finishing |
| `--threads N` | `0` (one per core) | workers that decrypt, write, and verify chunks, at most 1024 |
| `--allow-owner` | off | apply file owners from the sender (only as root, on Unix) |
| `--allow-special-bits` | off | keep setuid, setgid, and sticky bits from the sender |
| `-k, --keep-listening` | off | after a transfer, print its summary and wait for the next sender instead of exiting |

At least one of `--authorized` or `--allow` is required. On start the
receiver prints its public key and listen address.

`mjolnir send <HOST:PORT> <PATH>...` sends files and directories.
Directories are sent recursively under their own name, so `photos/` arrives
as `incoming/photos/...`.

| Flag | Default | Meaning |
|---|---|---|
| `--key PATH` | required | this host's private key |
| `--peer KEY` | required | the receiver's public key |
| `-n, --connections N` | `8` | parallel data connections, 1 to 256 |
| `-c, --chunk-size SIZE` | `1MiB` | chunk size, 4 KiB to 64 MiB; accepts `64K`, `256KiB`, `1M`, `4MiB` |
| `--cipher NAME` | `aes256gcm` | `aes256gcm` or `chacha20poly1305` |
| `--threads N` | `0` (one per core) | workers that read and encrypt chunks, at most 1024 |
| `--hash` | off | after delivery, re-read every file and have the receiver compare chunk digests; mismatched chunks are sent again |
| `--preserve LIST` | `perms` | metadata to copy: `none`, or any of `perms`, `times`, `owner` |
| `--no-follow-symlinks` | off (links followed) | skip symbolic links, including ones given as paths, instead of sending what they point to |

`mjolnir serve [--listen 127.0.0.1:7878] [--key PATH] [--no-open]` starts a
local web UI; see [docs/WEB.md](docs/WEB.md).

`mjolnir tunnel` and `mjolnir tunnel-server` forward TCP ports; see
[Tunnels](#tunnels).

`mjolnir update [--check]` updates the binary from the latest GitHub
release; see [Updating](#updating).

## Tunnels

A `tunnel-server` carries TCP connections for authorized clients. The
server decides what each key may reach; nothing is allowed by default:

```sh
mjolnir tunnel-server --key server.key --allow <CLIENT_PUBLIC_KEY> \
    --permit-open db.internal:5432 --permit-listen 127.0.0.1:8080
```

The client forwards ports in either direction, with the same
`[BIND:]PORT:HOST:HOSTPORT` specs as ssh:

```sh
# localhost:15432 here reaches db.internal:5432 from the server.
mjolnir tunnel server.example:7778 --key client.key --peer <SERVER_PUBLIC_KEY> \
    -L 15432:db.internal:5432
# 127.0.0.1:8080 on the server reaches localhost:3000 here.
mjolnir tunnel server.example:7778 --key client.key --peer <SERVER_PUBLIC_KEY> \
    -R 8080:localhost:3000
```

Every forwarded connection travels over its own connections to the server,
so streams never stall each other. With `-n N`, each stream is striped
across N connections and put back in order on the other side, which helps
on high-latency links and on paths that throttle each connection. `-W
HOST:PORT` carries one stream over stdin and stdout, for use as an ssh
`ProxyCommand`; it exits 0 only once the server has written everything to
the target. A stream that breaks resets the application's connection
instead of ending it, so a cut-off download never looks complete. With
`--reconnect`, the client sets up a new session whenever one ends,
waiting 1 second at first and up to 60 seconds between attempts, and
keeps its `-L` ports bound meanwhile. The first session must still
succeed.
Permissions, per-key `permitopen`, `permitlisten`, and `transfer` options,
the server's limits, and the wire format are in
[docs/TUNNEL.md](docs/TUNNEL.md).

## How it works

The sender opens a control connection and runs a Noise IK handshake. The
receiver checks the sender's static key against its allowed list before it
replies, and its reply carries a fresh random secret that both sides feed
through HKDF, bound to the handshake transcript, to derive every session
key. The sender offers a manifest; the receiver answers with a bitmap of the
chunks it already holds from an earlier attempt. The sender then opens N data
connections. A scheduler gives each connection one file's missing chunks in
order, so files move in parallel and each file is read sequentially; when
files run out, connections split the largest remaining range. Connections
only move bytes: a pool of `--threads` workers reads each chunk with a positional
read and seals it with a key unique to its connection, and the connection
writes the sealed frames in order. On the receiver a connection's reader
hands each frame to the same kind of pool. A worker opens the chunk, claims
it so a duplicate is never written twice, writes it with a positional write
into a part file under `<out>/.mjolnir-staging/` (a directory only the
receiving user can read), stores a 16-byte BLAKE3 digest of it next to the
part, and marks it present. Every two seconds it syncs the part and sums
files and saves the bitmap, so a crash or a cancel loses at most a few
seconds of work. A resumed transfer first has the sender re-read the chunks
the receiver already holds and drops any whose digest changed, so stale
bytes from an earlier attempt are never kept. When every chunk is present
the receiver reads each one back from disk and checks it against its
digest. A chunk that fails, including one carried over from an earlier
session, goes back to missing, and the next round fetches only that
chunk. With `send --hash`, the sender
then re-reads its files and the receiver compares those digests too, which
catches a source that changed without its size or mtime changing. Last, the
receiver renames the part files into place and applies the sender's file
map: directories, including empty ones, and the metadata chosen with
`--preserve`. The wire format is specified in
[docs/PROTOCOL.md](docs/PROTOCOL.md), and [docs/prior-art.md](docs/prior-art.md)
compares mjolnir with existing tools.

## Security model

Keys are pinned in the WireGuard and SSH style. The sender only talks to the
holder of the receiver key it passed with `--peer`, and the receiver only
accepts senders whose keys it was given. There are no certificates and no
trust on first use. The handshake is `Noise_IK_25519_ChaChaPoly_SHA256` as
implemented by the [snow](https://crates.io/crates/snow) crate; mjolnir does
not implement Noise itself. The session secret travels under ephemeral
Diffie-Hellman keys, so recorded traffic stays private even if both static
keys later leak. Every chunk is authenticated together with the session,
file, and chunk index, so a chunk cannot be altered, replayed into another
session, or moved to another offset. The manifest and every control message
are encrypted and authenticated too.

A rejected handshake leaves no files behind, and the receiver keeps
listening, so a stranger who reaches the port cannot stop it. An authorized
sender is trusted with the output directory: it chooses file names and
sizes. Names are validated so they cannot climb out of `--out`. Metadata
from the file map is applied through handles opened without following
links. On Unix every path component is opened relative to its parent, so
a link placed under `--out`, even one swapped in during the transfer,
cannot redirect a chmod, chown, or time change to a file outside it. On
Windows the parents are checked by path and only the final handle is
opened without following reparse points, so a junction swapped into a
parent between that check and the open is not caught; the guarantee there
covers links present when the check runs. File data and new directories
follow symlinks that already exist under `--out` on every platform. Do
not receive into a directory that other users can write to.

## Caveats

- No relay or NAT traversal. The sender must reach the receiver's port
  directly. (A tunnel client must likewise reach the tunnel server, but
  `-R` then serves connections back through it.)
- A `recv` process receives one transfer at a time. It keeps listening
  through failed handshakes and failed sessions and exits after one
  transfer completes, or with `--keep-listening` runs until you stop it
  with Ctrl-C. Ctrl-C ends it at once, even mid-transfer; the interrupted
  transfer resumes from staging when the sender retries. A later transfer
  of a file that already arrived fails without `--force`. The
  `--authorized` file is read once at start, so restart the receiver to
  revoke a key. One session at a time may receive into an output
  directory; a second receiver pointed at the same `--out` refuses its
  session.
- The receiver keeps `<out>/.mjolnir-staging/` with a lock file, and
  under it one directory per interrupted transfer (keyed by sender key,
  chunk size, and the files' paths, sizes, and mtimes). Re-running the
  same send resumes from it; a transfer that was never retried stays
  there until you delete it. A transfer interrupted while its files were
  being renamed into place, or whose final `Finished` was lost, resumes
  without `--force`.
- Only regular files and directories are sent. Symbolic links are followed
  by default and arrive as the files and directories they point to, even
  when the target is outside the sent folder, so check what a tree links to
  before sending it. Two links to one target send it twice. Special files,
  dangling links, and link loops are skipped with a warning, and so is
  every link with `--no-follow-symlinks`, including a link given as a path.
  A followed link given as a path arrives under the link's own name. File
  names travel as raw bytes, so a
  name that the receiver's file system cannot store (a `:` or a trailing
  `.` on Windows, invalid UTF-8 on macOS) is stored with the affected
  characters escaped as U+F000 plus the byte, the Cygwin and WSL
  convention, and comes back unchanged when sent back.
- Permissions are copied by default (on Windows only as the read-only
  attribute); times and owners only when asked for. Windows ACLs and
  extended attributes are not copied.
- Tunnels: a stream fails if any one of its connections fails; there is no
  retransmission above TCP, and no stream outlives its session. The
  client exits when its session ends unless run with `--reconnect`. After
  a network loss that never closed the old session, a reconnect can take
  about a minute: the server holds that session, and its `-R` ports,
  until TCP keepalive gives up on it.
- Private key files are stored unencrypted, protected only by file
  permissions.
- A source that changes during a transfer is caught only by its size or
  mtime, which the sender re-checks after every round. An in-place edit that
  keeps both, such as a tool that restores the mtime, goes out as a mix of
  old and new bytes, and every check still passes, because each chunk is
  exactly what the sender read. `send --hash` re-reads every file after
  delivery and resends any chunk that differs; use it when sources may
  change while they are being sent.
- Integrity is checked per chunk: the AEAD tag in transit, then a BLAKE3
  digest when the receiver reads the chunk back, and with `--hash` a digest
  of the sender's re-read. The `file_hash` both sides print with `--hash` is
  a BLAKE3 of the chunk digests, not `b3sum` of the file. The read-back can
  be served from the OS page cache, so it catches
  write-path bugs, stale resume data, and memory faults, but it does not
  prove what the disk holds. `--no-verify` skips the read-back; the sender's
  summary says whether the receiver verified.

## Benchmark

Full tables and method: [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Loopback on
one machine (Ryzen 9 9950X, Samsung 970 EVO Plus), 2 GiB of random data,
medians of 3 runs, commit 9df9b84. Every disk-writing output matched the
source's SHA-256; the discard rows write nothing to check.

| Setup | Windows | Linux (WSL2, ext4) |
|---|---|---|
| Raw disk write + fsync, 1 writer | 1459 MiB/s | 1711 MiB/s |
| 1 connection, 1 MiB chunks | 846 MiB/s | 911 MiB/s |
| 8 connections, 1 MiB chunks | 859 MiB/s | 886 MiB/s |
| 8 connections, 16 files of 128 MiB | 958 MiB/s | 966 MiB/s |
| 8 connections, 4 KiB chunks | 242 MiB/s | 191 MiB/s |
| 8 connections, receiver discards data (no disk) | 4240 MiB/s | 3868 MiB/s |
| No disk, 2 connections, 16 workers (transfer phase) | 4159 MiB/s | 5019 MiB/s |

Crypto scales with `--threads` until the connections' network threads are
the limit, at about 1.2-1.4 GiB/s per connection with 1 worker and up to
3.3 GiB/s with 4 or more. With a disk in the loop, the drive is the limit:
both OSes write one file at 830-950 MiB/s from 1 to 16 connections with the
receiver on 1.2-1.7 cores, and 16 large files go faster because files move
in parallel. 4 KiB chunks cost 3.5-4.6x throughput. Memory is bounded by
the buffer pools: the receiver peaks at about 90 MiB with the default
1 MiB chunks and under 1 GiB at 64 MiB. Chunk size is independent of the
network MTU; see [Chunks, frames, and the
MTU](docs/PROTOCOL.md#chunks-frames-and-the-mtu).

Rerun with `scripts/bench.sh [WORKDIR]` (`SIZE_MIB`, `REPEAT`, `PORT`,
`ROWS`, `PAUSE`), and measure the raw drive with `python scripts/rawdisk.py FILE`.

## CI and releases

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) builds release
binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `aarch64-apple-darwin`,
and `x86_64-apple-darwin`. It runs the tests on x86_64 Linux, x86_64
Windows, and Apple silicon macOS (on APFS). The other targets cross-compile,
the aarch64 Linux and Windows ones on x86_64 runners and Intel macOS on the
Apple silicon runner, so their tests do not run. It runs only for tags that start with
`v`, or when started by hand from the Actions tab, which builds without
publishing anything. Every action it uses is pinned to a commit SHA, and
the toolchain to an exact Rust release.

[`.github/workflows/audit.yml`](.github/workflows/audit.yml) runs
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) with
[`deny.toml`](deny.toml). It fails on a dependency with a known
vulnerability or an unsound advisory, an unmaintained direct dependency, a
license outside the allow-list, or a source other than crates.io. It runs
on pushes to `master`, on pull requests, and weekly, since advisories
appear without any change here. The release job waits for it, so a tag with
a flagged dependency publishes nothing.

Pushing a `v` tag builds and publishes a release from that tag:

```sh
git tag v0.2.0
git push origin v0.2.0
```

The release holds `mjolnir-<target>.tar.gz` for Linux and macOS,
`mjolnir-<target>.zip` for Windows, a `SHA256SUMS` file covering them, and
`SHA256SUMS.sig`, which is the layout the install scripts and
`mjolnir update` expect.

The release job signs `SHA256SUMS` with the ECDSA P-256 private key in the
repository secret `RELEASE_SIGNING_KEY`, a PEM file such as
`openssl ecparam -name prime256v1 -genkey -noout` writes. It writes the key
to a file only the runner's user can read, signs, and deletes the file.
Then it checks the signature against the public key in
[`scripts/install.sh`](scripts/install.sh), so a secret that does not match
the key users have fails the release. Without the secret the job fails and
nothing is published. The public key appears in `scripts/install.sh`,
`scripts/install.ps1`, and `RELEASE_KEY` in [`src/update.rs`](src/update.rs),
and a unit test fails if the three differ. To rotate the key, generate a new
one, put its base64 SubjectPublicKeyInfo DER
(`openssl pkey -in key.pem -pubout -outform DER | openssl base64 -A`) in all
three places, and
replace the secret. Binaries released before the rotation trust only the old
key, so `mjolnir update` refuses later releases until reinstalled with the
scripts.

## License

BSD 2-Clause; see [LICENSE](LICENSE).
