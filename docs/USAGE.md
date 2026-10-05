# Commands and flags

`mjolnir keygen [--out PATH]` writes a new private key (default
`mjolnir.key`) and prints its public key. It refuses to overwrite an
existing file. On Unix the file has mode `0600`. On Windows it gets an
access list of its own, inheriting nothing from its folder, that grants
only your account, SYSTEM, and Administrators. Every command that reads a
key refuses one that other accounts can read or change, and says how to
restrict it (`chmod 600` or `icacls`). On Windows, `keygen --system`
instead writes a key owned by Administrators that only SYSTEM and
Administrators can use, for a [Windows
service](SERVICE.md); it needs an elevated terminal.

`mjolnir pubkey --key PATH` prints the public key of an existing private
key.

`mjolnir recv` receives one transfer, or with `--keep-listening` one
transfer after another:

| Flag | Default | Meaning |
|---|---|---|
| `--key PATH` | required | this host's private key |
| `--authorized FILE` | | allowed sender keys, one `[options] <base64> [comment]` per line; `#` comments and blank lines are ignored. A line with tunnel options (see [Tunnels](TUNNEL.md)) sends files only if it also says `transfer` |
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
| `--cipher NAME` | `aes256gcm` | `aes256gcm` or `chacha20poly1305`; the default is `chacha20poly1305` on a Windows ARM64 CPU without the Cryptography Extension |
| `--threads N` | `0` (one per core) | workers that read and encrypt chunks, at most 1024 |
| `--hash` | off | after delivery, re-read every file and have the receiver compare chunk digests; mismatched chunks are sent again |
| `--preserve LIST` | `perms` | metadata to copy: `none`, or any of `perms`, `times`, `owner` |
| `--no-follow-symlinks` | off (links followed) | skip symbolic links, including ones given as paths, instead of sending what they point to |

`mjolnir serve [--listen 127.0.0.1:7878] [--key PATH] [--no-open]` starts a
local web UI; see [WEB.md](WEB.md).

`mjolnir tunnel` and `mjolnir tunnel-server` forward TCP ports; see
[Tunnels](TUNNEL.md).

`mjolnir update [--check]` updates the binary from the latest GitHub
release; see [Updating](RELEASING.md#updating).

On Windows, `mjolnir service` runs a receiver or a tunnel as a Windows
service; see [Running as a Windows service](SERVICE.md).

## Behavior worth knowing

- No relay or NAT traversal. The sender must reach the receiver's port
  directly. (A tunnel client must likewise reach the tunnel server, but
  `-R` then serves connections back through it.)
- A `recv` process receives one transfer at a time. It keeps listening
  through failed handshakes and failed sessions and exits after one
  transfer completes, or with `--keep-listening` runs until you stop it
  with Ctrl-C or stop its service. Either ends it at once, even
  mid-transfer; the interrupted transfer resumes from staging when the
  sender retries. A later transfer
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
- Windows ARM64 builds run AES-256-GCM on the ARMv8 Cryptography Extension,
  with no software fallback. On a CPU without it, `send` and `tunnel`
  default to `chacha20poly1305` and refuse `--cipher aes256gcm`, and `recv`
  and `tunnel-server` refuse a session that uses it. Senders talking to
  such a receiver need `--cipher chacha20poly1305`.
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
[PROTOCOL.md](PROTOCOL.md), and [prior-art.md](prior-art.md)
compares mjolnir with existing tools.
