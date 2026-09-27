# mjolnir

mjolnir copies large files between two hosts you control. It splits each
file into chunks, encrypts every chunk on its own with an AEAD, and sends
them over several TCP connections at once. The receiver decrypts each chunk
and writes it at its offset. Both hosts authenticate with static key pairs,
and an interrupted transfer resumes where it stopped.

## Install

Releases ship prebuilt binaries for Linux and Windows on x86_64 and
aarch64. The install scripts download the latest one, check it against the
release's `SHA256SUMS`, and install it. They download with the GitHub CLI
when it is logged in, and otherwise with a personal access token in
`GH_TOKEN` or `GITHUB_TOKEN` that can read this repository's contents.

On Linux, [`scripts/install.sh`](scripts/install.sh) installs to
`~/.local/bin`:

```sh
gh api repos/mrquantumoff/mjolnir/contents/scripts/install.sh \
    -H "Accept: application/vnd.github.raw" | bash
```

With a token and no GitHub CLI:

```sh
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github.raw" \
    https://api.github.com/repos/mrquantumoff/mjolnir/contents/scripts/install.sh | bash
```

On Windows, [`scripts/install.ps1`](scripts/install.ps1) installs to
`%LOCALAPPDATA%\Programs\mjolnir` and adds that folder to the user `PATH`:

```powershell
gh api repos/mrquantumoff/mjolnir/contents/scripts/install.ps1 `
    -H "Accept: application/vnd.github.raw" | Out-String | Invoke-Expression
```

Both scripts read `MJOLNIR_VERSION` to install a specific tag instead of
the latest, and `MJOLNIR_INSTALL_DIR` to install somewhere else. From a
checkout, run either script directly; `install.ps1` also takes `-Version`
and `-InstallDir`.

To build from source instead, run `cargo build --release`; the binary lands
in `target/release`.

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
existing file. On Unix the file has mode `0600`.

`mjolnir pubkey --key PATH` prints the public key of an existing private
key.

`mjolnir recv` receives one transfer:

| Flag | Default | Meaning |
|---|---|---|
| `--key PATH` | required | this host's private key |
| `--authorized FILE` | | allowed sender keys, one `<base64> [comment]` per line; `#` comments and blank lines are ignored |
| `--allow KEY` | | allow one sender key; repeatable |
| `--listen ADDR` | `0.0.0.0:7777` | address to listen on |
| `--out DIR` | `.` | where files land |
| `--force` | off | overwrite existing files |
| `--no-verify` | off | skip reading every chunk back before finishing |
| `--threads N` | `0` (one per core) | workers that decrypt, write, and verify chunks |
| `--allow-owner` | off | apply file owners from the sender (only as root, on Unix) |
| `--allow-special-bits` | off | keep setuid, setgid, and sticky bits from the sender |

At least one of `--authorized` or `--allow` is required. On start the
receiver prints its public key and listen address.

`mjolnir send <HOST:PORT> <PATH>...` sends files and directories.
Directories are sent recursively under their own name, so `photos/` arrives
as `incoming/photos/...`.

| Flag | Default | Meaning |
|---|---|---|
| `--key PATH` | required | this host's private key |
| `--peer KEY` | required | the receiver's public key |
| `-n, --connections N` | `8` | parallel data connections |
| `-c, --chunk-size SIZE` | `1MiB` | chunk size, 4 KiB to 64 MiB; accepts `64K`, `256KiB`, `1M`, `4MiB` |
| `--cipher NAME` | `aes256gcm` | `aes256gcm` or `chacha20poly1305` |
| `--threads N` | `0` (one per core) | workers that read and encrypt chunks |
| `--hash` | off | after delivery, re-read every file and have the receiver compare chunk digests; mismatched chunks are sent again |
| `--preserve LIST` | `perms` | metadata to copy: `none`, or any of `perms`, `times`, `owner` |

`mjolnir serve [--listen 127.0.0.1:7878] [--key PATH] [--no-open]` starts a
local web UI; see [docs/WEB.md](docs/WEB.md).

## How it works

The sender opens a control connection and runs a Noise IK handshake. The
receiver checks the sender's static key against its allowed list before it
replies, and its reply carries a fresh random secret that both sides feed
through HKDF, bound to the handshake transcript, to derive every session
key. The sender offers a manifest; the receiver answers with a bitmap of the
chunks it already holds from an earlier attempt. The sender then opens N data
connections that pull chunk numbers from one shared queue. Connections only
move bytes: a pool of `--threads` workers reads each chunk with a positional
read and seals it with a key unique to its connection, and the connection
writes the sealed frames in order. On the receiver a connection's reader
hands each frame to the same kind of pool. A worker opens the chunk, claims
it so a duplicate is never written twice, writes it with a positional write
into
`<name>.mjolnir-part`, stores a 16-byte BLAKE3 digest of it in
`<name>.mjolnir-sums`, and marks it present. Every two seconds it syncs the
part and sums files and saves the bitmap, so a crash or a cancel loses at
most a few seconds of work. When every chunk is present it reads each one
back from disk and checks it against its digest. A chunk that fails,
including one carried over from an earlier session, goes back to missing,
and the next round fetches only that chunk. With `send --hash`, the sender
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
sizes. Names are validated so they cannot climb out of `--out`, but
symlinks that already exist under `--out` are followed.

## Caveats

- No relay or NAT traversal. The sender must reach the receiver's port
  directly.
- One transfer per `recv` process. The receiver keeps listening through
  failed handshakes and failed sessions and exits after one transfer
  completes.
- Only regular files and directories are sent. Symbolic links and special
  files are skipped with a warning. File names travel as raw bytes, so a
  name that the receiver's file system cannot store (a `:` or a trailing
  `.` on Windows, invalid UTF-8 on macOS) is stored with the affected
  characters escaped as U+F000 plus the byte, the Cygwin and WSL
  convention, and comes back unchanged when sent back.
- Permissions are copied by default (on Windows only as the read-only
  attribute); times and owners only when asked for. Windows ACLs and
  extended attributes are not copied.
- Private key files are stored unencrypted, protected only by file
  permissions.
- Integrity is checked per chunk: the AEAD tag in transit, then a BLAKE3
  digest when the receiver reads the chunk back, and with `--hash` a digest
  of the sender's re-read. The `file_hash` both sides print with `--hash` is
  a BLAKE3 of the chunk digests, not `b3sum` of the file. The read-back can
  be served from the OS page cache, so it catches
  write-path bugs, stale resume data, and memory faults, but it does not
  prove what the disk holds. `--no-verify` skips the read-back; the sender's
  summary says whether the receiver verified.

## Benchmark

Measured with [`scripts/bench.sh`](scripts/bench.sh): a release build,
`recv` and `send` as two processes on 127.0.0.1, one 2 GiB file of random
data, three runs per row, median shown. Every run's output matched the
source's SHA-256. The rate is the sender's summary line, which covers
connecting, the handshake, all rounds, and the receiver's final sync and
rename. The source file was in the page cache, and the receiver wrote to the
same drive the source lives on.

Machine: AMD Ryzen 9 9950X (16 cores, 32 threads), 64 GB RAM, Windows 11 Pro
(build 26200), Rust 1.98.1.

| connections | chunk size | cipher | MiB/s |
|---|---|---|---|
| 1 | 1 MiB | AES-256-GCM | 514 |
| 4 | 1 MiB | AES-256-GCM | 1614 |
| 8 | 1 MiB | AES-256-GCM | 1604 |
| 16 | 1 MiB | AES-256-GCM | 1437 |
| 8 | 4 KiB | AES-256-GCM | 469 |
| 8 | 16 KiB | AES-256-GCM | 833 |
| 8 | 256 KiB | AES-256-GCM | 1617 |
| 8 | 4 MiB | AES-256-GCM | 1479 |
| 8 | 1 MiB | ChaCha20-Poly1305 | 1647 |

An earlier full sweep on the same machine differed from this one by up to
20% per row, in both directions (615 MiB/s at 1 connection, 1715 at 4, 1595
at 256 KiB chunks), so treat differences under about 20% as noise. Throughput peaks around 1600 MiB/s
with 4 to 8 connections and chunks of 256 KiB to 1 MiB. At 8 connections the
two ciphers land within 5% of each other, so past one connection the cipher
is not what limits this setup. These numbers were not broken down further,
so which of disk writes, loopback TCP, or scheduling sets the ceiling is not
established. Small chunks cost real throughput: 4 KiB chunks run at under a
third of the 1 MiB rate. Chunk size is independent of the network MTU;
[Chunks, frames, and the MTU](docs/PROTOCOL.md#chunks-frames-and-the-mtu)
explains why. Loopback numbers say nothing about a real network; rerun the
script on your own hosts.

Rerun with `scripts/bench.sh [WORKDIR]`; `SIZE_MIB`, `REPEAT`, and `PORT`
override the defaults.

## CI and releases

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) builds release
binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`, and `aarch64-pc-windows-msvc`, and runs the tests
on the two x86_64 targets. The aarch64 targets cross-compile on x86_64
runners, so their tests do not run. It runs only for tags that start with
`v`, or when started by hand from the Actions tab, which builds without
publishing anything.

Pushing a `v` tag builds and publishes a release from that tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release holds `mjolnir-<target>.tar.gz` for Linux,
`mjolnir-<target>.zip` for Windows, and a `SHA256SUMS` file covering them,
which is the layout the install scripts expect.
