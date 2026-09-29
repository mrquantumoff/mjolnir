# Mjolnir protocol, version 2

Mjolnir moves large files between two hosts over N parallel TCP connections.
Files are split into fixed-size chunks (the sender picks the size). Each chunk
is sealed with an AEAD on its own, so every connection reads, encrypts, and
sends independently, and the receiver decrypts and writes each chunk at its
offset with a positional write. Nothing is encrypted as a whole file first.

Fixed-layout fields (preambles, length prefixes, Noise framing, data
connection hellos, frame headers, nonces, and key-derivation inputs) are
big-endian. Control messages are postcard-encoded, and postcard writes
integers as LEB128 varints, strings and byte strings with a varint length
prefix, and enum tags as varints.

## Roles

The **receiver** listens on a TCP port. The **sender** connects, both sides
authenticate with their static key pairs, the sender offers a manifest, and
then it opens data connections.

A receiver serves one transfer at a time and stops after one transfer
completes. It runs each incoming handshake on its own thread (at most 256 at
once; connections beyond that are closed at once) and requires the preamble and Noise message 1 to arrive within 10
seconds, so a peer that trickles bytes cannot hold up a real sender.
Message 1 must be exactly 96 bytes, its size in IK with an empty payload. Message 1 can be
replayed, and the receiver answers a replay like the original, so a
finished handshake does not prove the sender is live; its `Confirm` does,
because only the real sender can seal it. Each handshake thread therefore
also waits (up to 10 seconds) for that connection's `Confirm`, and only a
connection whose `Confirm` decrypted takes the session. `Confirm` is a
fixed 17-byte message, and the handshake thread reads exactly that many
bytes, so a peer that only replayed message 1 can make the receiver
buffer at most 21 bytes per connection, under 8 KiB across all 256
handshake slots, before it is dropped. The `Offer`, which may be up to
64 MiB, is read only by the connection that holds the session, within
10 seconds. A replay never gets that far, so it cannot hold the session,
lock out a real sender, or fill the receiver's memory. A
sender whose control connection is closed during the handshake, as happens
while another session is active, retries twice, after 1 and 3 seconds. Until then it keeps listening. A failed handshake (unknown key,
garbage, a port scanner) drops only that connection. It is logged, and the
receiver keeps waiting, so nobody who merely reaches the port can shut a
receiver down. While a session is active, further control connections are
closed right after the preamble. If an admitted session fails midway (the
sender disconnects, a control message fails to decrypt, the sender sends
`Error`), the receiver checkpoints every file and goes back to waiting. The
sender can simply run again and resume.

## Identities

Every host has a static X25519 key pair, created with `mjolnir keygen`.
Keys are encoded as standard base64 of the 32 raw bytes (44 characters), the
same form WireGuard uses.

- The private key lives in a file holding the base64 text and a newline. On
  Unix it is created with mode `0600`.
- The sender pins the receiver's public key (`--peer`), like an SSH
  `known_hosts` entry.
- The receiver admits only senders whose public key is listed in its
  authorized keys file (`--authorized`), like SSH `authorized_keys`. Each
  line is `[options] <base64 key> [comment]`; blank lines and lines
  starting with `#` are ignored. A line with tunnel options (see
  [TUNNEL.md](TUNNEL.md)) authorizes a sender only if it also carries the
  `transfer` option. `--allow <KEY>` adds a key from the command line.

## Connection preamble

Every TCP connection starts with the sender writing 6 bytes:

```
"MJLN" (4 bytes) | version u8 = 2 | kind u8 (0 = control, 1 = data)
```

Kinds 2 and 3 belong to tunnels, which share the preamble, handshake, and
key schedule but run their own protocol; see [TUNNEL.md](TUNNEL.md).

The first connection must be the control connection. Data connections are
accepted only after the control handshake has finished.

## Control handshake (Noise IK)

The control connection runs `Noise_IK_25519_ChaChaPoly_SHA256` with prologue
`mjolnir v2`. The sender is the initiator and already knows the receiver's
static public key. Each Noise message is framed with a length:

```
S -> R : u16 len | Noise msg 1   (-> e, es, s, ss)   payload empty
R -> S : u16 len | Noise msg 2   (<- e, ee, se)      payload = master (32 random bytes)
```

After message 1 the receiver knows the sender's static key. If that key is
not authorized, the receiver closes the connection without replying and
keeps listening. If the sender pinned the wrong receiver key, the receiver
cannot decrypt message 1 and also closes. The sender reports both cases as "the
receiver rejected the handshake".

The receiver's reply carries `master`, a fresh random 32-byte secret. The
message 2 payload is encrypted under keys that mix both ephemeral keys and
both static keys, so only the authenticated sender can read it, and it stays
secret even if both static private keys later leak (forward secrecy). A
replayed message 1 gets the attacker nothing, because reading message 2
needs the sender's ephemeral private key.

Noise transport mode is not used after the handshake: its 65535-byte message
limit is too small for large `Have` bitmaps. Instead both sides derive their
own keys from `master`, bound to the handshake transcript:

```
h    = Noise handshake hash after message 2
PRK  = HKDF-SHA256-Extract(salt = h, ikm = master)
E(l) = HKDF-SHA256-Expand(PRK, info = l, 32 bytes)
```

| Name          | Derivation                          | Use                                   |
|---------------|-------------------------------------|---------------------------------------|
| `k_ctrl_s2r`  | `E("ctrl s2r")`                     | control messages sender to receiver   |
| `k_ctrl_r2s`  | `E("ctrl r2s")`                     | control messages receiver to sender   |
| `k_hello`     | `E("hello")`                        | data connection admission MAC         |
| `session_id`  | first 16 bytes of `E("session id")` | bound into every data chunk's AAD     |
| `k_data(r,i)` | `E("data" | r u32 | i u32)`         | data connection `i` in round `r`      |

The sender's first control message (`Confirm`) is sealed under
`k_ctrl_s2r`, so a successful decrypt confirms to the receiver that the
sender is live and holds the key it authenticated with, before the
receiver reads anything of a size the sender chooses.

## Control channel

After the handshake, each control message is:

```
u32 len | ChaCha20-Poly1305(key, nonce = 0u32 | counter u64, aad = "", postcard(msg))
```

Each direction has its own key and its own counter starting at 0. `len`
counts ciphertext plus tag and is capped at 64 MiB.

Messages (a postcard-encoded enum; the variant tag is the row index below,
starting at 0):

| Message                              | Direction | Meaning                                                   |
|--------------------------------------|-----------|-----------------------------------------------------------|
| `Offer { chunk_size, cipher, files, dirs }` | S to R | manifest; `files[j] = { path, size, mtime }`; `dirs`: every directory under the sent roots, including empty ones, same path encoding |
| `Have { bitmaps }`                   | R to S    | per file, the chunks the receiver already holds           |
| `RoundStart { round }`               | S to R    | sender is about to open data connections for `round`      |
| `RoundEnd { round, connections }`    | S to R    | sender's data connections for `round` are closed; `connections` is how many the receiver admitted |
| `Delivered`                          | R to S    | every chunk is present and verified; ready for `Finalize` |
| `Digests { file, first, digests }`   | S to R    | optional hash check: the sender's freshly re-read 16-byte digests for chunks `first..` of `file` |
| `Finalize { hash, map }`             | S to R    | end of data; `hash` says whether `Digests` were sent; `map` is the file map |
| `Finished { verified, hashed, warnings }` | R to S | files renamed into place, file map applied; `warnings` lists metadata that could not be applied |
| `Error { message }`                  | both      | ends the session; the sender exits, the receiver checkpoints and waits again |
| `Cancel`                             | both      | the user cancelled; handled like `Error`, reported as a cancel |
| `Verifying`                          | R to S    | the receiver starts reading chunks back; for progress display only |
| `Confirm`                            | S to R    | the first message after the handshake; empty, sealed, so it proves the sender is live |
| `Resume`                             | S to R    | the sender's fresh `Digests` for every chunk `Have` reported present are complete; the receiver answers with a corrected `Have` |
| `Ack`                                | S to R    | the sender received `Finished`; the receiver may drop its journal |

Field encodings: `chunk_size` is a `u32`; `cipher` is an enum
(`Aes256Gcm` = 0, `ChaCha20Poly1305` = 1); each file is
`{ path: [bytes], size: u64, mtime: u64 }` with `mtime` in nanoseconds since
the Unix epoch (0 if unknown); each entry of `dirs` is a `[bytes]` path
like a file's; `round` and `connections` are `u32`. `bitmaps`
holds one byte string per file, in offer order, of exactly
`ceil(chunk_count / 8)` bytes: chunk `k` is bit `k % 8` (least significant
first) of byte `k / 8`. The sender rejects a `Have` whose shape does not
match the offer, and refuses up front to offer more chunks than a `Have`
could carry in one 64 MiB message. In `Digests`, `file` is a `u32`,
`first` a `u64`, and `digests` one byte string of concatenated 16-byte
digests. `Finalize.map` is the file map below, and `Finished.warnings` a
list of strings.

`path` is a list of components, each a byte string: the file's raw name,
not necessarily UTF-8 (see "File names"). The receiver rejects empty paths,
empty components, `.` and `..` components, components containing NUL or
`/`, paths deeper than 256 components or longer than 4096 bytes (the
components joined with `/`), components whose folded name (below) ends in
`.mjolnir-part`, `.mjolnir-state`, `.mjolnir-state.tmp`, `.mjolnir-sums`,
`.mjolnir-journal`, `.mjolnir-journal.tmp`, or `.mjolnir-staging`, and
offers whose names collide (below). The same rules apply to `dirs`. The
suffix rule covers directories
too, because a directory `a.mjolnir-part` would collide with the part file
of a sibling `a`, and it compares folded names because on a
case-insensitive file system `a.MJOLNIR-PART` and `a.mjolnir-ſums` (with a
long s) are those side files. Case-insensitive file systems (Windows,
macOS) treat `README` and `readme` as one file, and APFS also treats the
NFC and NFD spellings of a name (`café` as one code point or as `e` plus a
combining accent) as one file.

A component's folded name is its macOS name (see "File names"),
NFC-normalized, with each character `c` then replaced on its own: `u` is
the uppercase of `c` if that is a single character, else `c`, and the
result is the lowercase of `u` if that is a single character, else `u`.
The mapping ignores context, as the NTFS upcase table does, so `ς`, `σ`,
and `Σ` all fold to `σ`, the Kelvin sign to `k`, `ı` to `i`, `ſ` to `s`,
and `ẞ` to `ß`, while `ß` and `İ`, whose case mappings expand, stay as
they are. (Context-sensitive lowercasing would turn `AΣ` into `aς` but
`aσ` into `aσ`, two keys for what Windows stores as one file.) The rule
uses one key on every OS, so the same offer is valid or invalid
everywhere, and any two names that collide on Windows also collide under
it; it may reject a few pairs Windows would keep apart.

The receiver creates every file, every directory in `dirs`, and every
parent of either (`a/b/c` has the parents `a` and `a/b`) in one tree, so
they form one namespace, keyed by the path with each component folded.
The receiver rejects an offer in which two different paths share a key, a
key is both a file and a directory (listed or parent), or a directory is
listed twice. A listed directory that is also a parent is one entry, not a
collision. So a file `tree/a` and a directory `tree/A` collide, as do the
files `a` and `a/b` and the files `Docs/x` and `docs/y`. `file_id` is the
index into `files`.

Each sent root arrives at the top of that tree under its own name, so two
roots with the same name collide like any other two paths. Sending `x/data`
and `y/data` fails as a duplicate directory ("directory data is listed
twice"), where earlier versions merged the two into one `data`, and two
root files `x/f.txt` and `y/f.txt` fail as a duplicate name. The sender
builds the same manifest, so it reports the collision before it connects.

`chunk_size` is between 4 KiB and 64 MiB. File `j` has
`ceil(size / chunk_size)` chunks. Chunk `k` covers bytes
`[k * chunk_size, min(size, (k + 1) * chunk_size))`. An empty file has zero
chunks.

`cipher` is `Aes256Gcm` (default; AES-NI and CLMUL are detected at run
time on x86-64, and ARMv8 AES and PMULL on aarch64 Linux and macOS, while
Windows ARM64 builds use software AES because the cipher crates have no
CPU-feature detection there)
or `ChaCha20Poly1305`.

### Session flow

```
S -> R : Confirm              (17 sealed bytes; proves the sender is live)
S -> R : Offer
R -> S : Have                 (resume state; all zero on a fresh transfer)
if Have reports any chunk present:
    S re-reads those chunks and computes their digests
    S -> R : Digests { file, first, digests }   (repeated, present runs only)
    S -> R : Resume
    R drops every chunk whose stored digest differs (see "Receiver
      storage and resume")
    R -> S : Have             (corrected)
loop round = 0, 1, ...:
    S -> R : RoundStart { round }
    S opens up to N data connections, sends every chunk missing from Have
    S -> R : RoundEnd { round, connections }
    R waits until `connections` data connections of this round have closed
      (at most 30 s), then shuts down any of the round's connections still
      open and waits for their reader threads to exit, so nothing of this
      round can land after this point
    if every chunk is present:
        R syncs, reads every chunk back and checks its digest
        (see "Verification"); mismatches become missing again
    if every chunk is still present:
        if the data is already finalized (a hash repair round just ended):
            go to APPLY
        R -> S : Delivered
        if the sender's hash check is on (see "Hash check"):
            S re-reads every file and computes chunk digests
            S -> R : Digests { file, first, digests }   (repeated)
        S -> R : Finalize { hash, map }
        if hash: R compares, and mismatched chunks become missing
        if anything became missing:
            R -> S : Have     (repair round; loop continues)
        APPLY:
        R renames files into place and applies the file map
        R -> S : Finished { verified, hashed, warnings }
        S -> R : Ack          (best effort; lets R drop its journal)
    else:
        R -> S : Have         (sender sends what is still missing)
```

After sending `Finalize`, the sender answers every `Have` with another
round, as before, until `Finished` arrives. `Delivered` comes only once per
session. When a hash repair round completes, the receiver applies the file
map it already holds without asking again.

Either side may send `Error` or `Cancel` at any point after the handshake
and then close every connection.

A round that makes no progress counts as a failure. After 3 consecutive
failed rounds the sender sends `Error` and gives up. A chunk that arrives
more than once is written only the first time (see "Ordering, duplicates,
and late data").

The sender hands chunks to its connections through one scheduler that
keeps each file's missing chunks in order (see "Parallelism"). A connection
claims a chunk when it is ready for one, so a slow connection takes fewer
chunks instead of holding up the round. Each connection works through one
file at a time, so files are read sequentially and different connections
carry different files whenever there are enough files.

Before each `RoundEnd`, the sender re-stats every file. If any size or mtime
differs from the `Offer`, the source changed underneath the transfer: the
sender sends `Error` and fails instead of finishing with mixed old and new
bytes. The receiver's saved state then no longer matches the file, so the
next run starts that file over.

## File names

Names travel as raw bytes, so every name that exists on the sender's disk
can be sent: names containing `:`, `*`, `?`, `\`, or control characters,
names ending in `.` or a space, names like `CON` or `aux.txt`, and names
that are not valid UTF-8. Each side maps between the wire bytes and what
its file system can store, using one reversible escape. **Byte `b` is
escaped as the code point U+F000 + b**, from the Unicode Private Use Area.
This is the same convention Cygwin and WSL use for these characters on
Windows, so their tools display such names the same way.

Sender, reading names:

- Linux and other Unix except macOS: the component's raw `OsStr` bytes.
- macOS: the UTF-8 name, with every code point in U+F001 to U+F0FF turned
  back into its byte. Invalid bytes, possible only on non-APFS volumes, go
  out as they are.
- Windows: the UTF-16 name encoded as WTF-8, so unpaired surrogates survive.
  Every code point in U+F001 to U+F0FF is then turned back into its byte.
  A name escaped by an earlier mjolnir, Cygwin, or WSL receiver therefore
  goes back out as the original name.

A local name that reads back as something no wire path may hold (U+F02F
reads as `/`, and a name of U+F02E U+F02E reads as `..`) cannot be sent.

Receiver, creating names:

- Linux and other Unix except macOS: the bytes as they are.
- macOS: APFS stores names as UTF-8 and rejects invalid sequences, so each
  byte of an invalid UTF-8 sequence is escaped. A literal code point in
  U+F001 to U+F0FF has each of its three UTF-8 bytes escaped, so that it
  does not read back as the byte it stands for. Other valid UTF-8 is
  unchanged.
- Windows: the bytes are decoded as WTF-8. Valid UTF-8 becomes UTF-16, and
  the three-byte form of a surrogate becomes that surrogate, unless it is a
  lead directly followed by a trail: those two would pair up into a
  different code point, so the lead's bytes are escaped instead. Each byte
  of any other invalid sequence is escaped, and so is each UTF-8 byte of a
  literal U+F001 to U+F0FF. Then these characters are escaped:
  `\ : * ? " < > |`, U+0001 to U+001F, the first character of a Windows
  device name, and a trailing `.` or space. A device name is one whose
  stem (the text before the first `.`, trailing spaces dropped) is `CON`,
  `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM1` to `COM9`, `LPT1` to
  `LPT9`, or `COM` or `LPT` followed by a superscript `¹`, `²`, or `³`, in
  any case. The result
  never contains a separator, a drive, or a stream, and never opens a
  device. All file operations use `\\?\` verbatim paths, so paths longer
  than 260 characters work.

Round trips are exact, and distinct wire names always get distinct local
names. A name sent from any OS to any other and back arrives with the same
bytes it started with, and a Windows name with an unpaired surrogate comes
back to Windows unchanged. The one ambiguity: a genuine file on Windows or
macOS whose name contains a character in U+F001 to U+F0FF is read as the
escaped byte when sent. Cygwin and WSL have the same limitation.

Terminal output, logs, and the web UI show names lossily (invalid bytes as
U+FFFD). Only the display changes; the file itself gets the exact name.

Only regular files and directories go on the wire; links are resolved on
the sender. By default it follows symbolic links: a link to a file is sent
as a regular file with the target's contents, and a link to a directory is
walked as a directory, both under the link's own name and with the
target's size, mtime, and mode. Links are followed wherever they point,
including outside the sent root, and two links to one target send it
twice, once under each name. A link given as a root is followed the same
way and named after the link, so `latest` pointing to `run-42` arrives as
`latest`. The sender skips, and lists in a warning, special files (FIFOs,
sockets, devices) and links to them, dangling links, and links that loop:
a directory link back to one of its ancestors, or a chain of links that
never reaches a target. With `send --no-follow-symlinks`, it skips every
link, roots included, with the warning "symbolic link, not followed", and
does not descend into directory links.

## File map

Data comes first and metadata last. Once every chunk is delivered, the
sender sends a file map in `Finalize`. The receiver applies it after renaming
every file into place, because writing into a directory changes its mtime,
and a read-only directory would block the writes.

```
FileMap { entries: [Entry] }
Entry {
    path:  [bytes],               same encoding as Offer paths
    kind:  File { file_id } | Dir,
    mode:  Option<u32>,           permission bits (st_mode & 0o7777)
    mtime: Option<i64>,           ns since the Unix epoch
    atime: Option<i64>,
    owner: Option<(u32, u32)>,    uid, gid
}
```

The map lists every sent file and every directory under the sent roots,
including empty directories. **Every directory in the `Offer` is created
before the files are published, whatever the preserve options, and failing
to create one fails the transfer.** The receiver validates each entry's
path exactly like an `Offer` path. A `File` entry's path must match its
`file_id` in the offer, and a `Dir` entry's path must be one of the
offer's `dirs`.

What the sender fills in is chosen with `send --preserve`, a comma-separated
list:

| Item    | Default | Filled field | Source on Windows senders |
|---------|---------|--------------|---------------------------|
| `perms` | on      | `mode`       | `0o644` files, `0o755` dirs, without the write bits when the read-only attribute is set |
| `times` | off     | `mtime`, `atime` | file times |
| `owner` | off     | `owner`      | not available, left empty |

`--preserve none` sends only the directory structure.

The receiver applies the map in this order. First it creates every
directory. Then it applies each file's metadata. Last it applies each
directory's metadata, deepest first. Within an entry it sets the owner
first, because chown clears the setuid and setgid bits, then the times, then
the mode. It leaves an entry alone, with a warning, if its path is a
symbolic link on the receiver or is a file where the map says directory (or
the reverse), so a link already in the output directory cannot redirect a
chmod. It checks this on the handle it then changes, not on the path: on
Unix it opens each component relative to its parent with `O_NOFOLLOW` and
uses `fchown`, `futimens`, and `fchmod`, so no component can be swapped
for a link between the check and the change. On Windows it opens the
entry and each parent by path with `FILE_FLAG_OPEN_REPARSE_POINT`,
refuses reparse points, and sets times and attributes through the final
handle; Win32 has no handle-relative open, so a parent replaced by a
junction between its check and the final open is not detected there. The
Windows guard therefore covers links that exist when the map is applied,
not ones raced in by a local writer, which is one more reason not to
receive into a directory other users can write to. Its policy guards
against a hostile or careless sender:

- **Mode.** On Unix it sets `mode & 0o777`. The setuid, setgid, and sticky
  bits are dropped unless `recv --allow-special-bits` is given. On Windows,
  a mode without the owner-write bit (`0o200`) sets the read-only attribute.
  Windows ACLs are not transferred.
- **Times.** It sets mtime and atime where the platform supports them.
- **Owner.** It chowns only with `recv --allow-owner`, only when running as
  root, and only on Unix. Otherwise it ignores the field and adds one
  warning.

A metadata failure never fails the transfer. The data is already in place,
so each failure becomes a line in `Finished.warnings`, printed on both
sides. Applying the map is idempotent. If a crash happens between the
renames and the map, the files are complete and only their metadata is
missing.

## Hash check

The per-chunk AEAD tags and the receiver's read-back verification prove
that the receiver holds exactly what the sender read during the transfer.
`send --hash` adds an end-to-end check that also catches the sender's own
read going wrong, or a source that changed without its size or mtime
changing.

Once the receiver reports `Delivered`, the sender reads every file again and
computes each chunk's 16-byte digest, `BLAKE3(chunk plaintext)`, in its worker
pool, all chunks in parallel. It streams the digests in `Digests` messages of
at most 1,048,576 digests each. The receiver compares them with its
`.mjolnir-sums` entries. Those entries were already confirmed against the
disk by the verification pass, so the receiver does not read the files a
third time.

A mismatched chunk becomes missing, and a repair round resends only those
chunks, never whole files. After that round the receiver compares the new
digests with the sender's digests from `Digests`. A chunk that still
differs ends the session with `Error { "<path> changed during transfer" }`.

For each file, the reports show `file_hash = BLAKE3(chunk_size u32 | all
chunk digests)` in hex. Both sides print the same value on success. This is
a hash of the chunk digests, so it does not match `b3sum` of the file.

`Phase::Hashing` covers the sender's re-read and the receiver's comparison.

## Chunks, frames, and the MTU

The protocol assumes a standard 1500-byte Ethernet MTU and needs nothing
larger. Mjolnir runs over TCP, so the kernel cuts every frame into segments
that fit the path MTU: at most 1460 payload bytes per packet over IPv4 and
1440 over IPv6 on a 1500-byte link. Jumbo frames help if the network has
them, but nothing depends on them.

A chunk is the unit of encryption, resume bookkeeping, and work
distribution, not a network packet. Each chunk costs 32 bytes on the wire
(16-byte header, 16-byte tag), one AEAD call, and one bitmap bit. At the
default 1 MiB that is about 0.003% overhead. A chunk the size of one packet
(about 1.4 KiB) would cost about 2% of the bytes and roughly 700 times more
per-chunk work, and TCP would still not keep it inside one packet. Hence the
4 KiB minimum and the 1 MiB default.

## Data connections

```
S -> R : preamble (kind = 1)
R -> S : challenge (32 random bytes)
S -> R : round u32 | conn u32 | HMAC-SHA256(k_hello, challenge | round | conn)
R -> S : 0x01 admitted, or 0x00 rejected (then close)
```

The receiver admits a connection only if the MAC is valid, `round` is the
current round, `(round, conn)` has not been admitted before, fewer than 256
connections have been admitted in this round, and fewer than 256 admitted
connections are open. Each admitted connection holds a thread and a read
buffer of at most 256 KiB (16 KiB for chunks of 256 KiB and up) until it
closes, so those two caps bound what an authorized sender can make the
receiver hold; `send --connections` stops at the same 256. The fresh
challenge stops a captured hello from being replayed.

`RoundStart` and the round's data connections travel on different TCP
connections, so a data connection can reach the receiver before the
receiver has read `RoundStart`. A connection whose MAC is valid and whose
`round` is the next one expected therefore waits (up to 10 seconds) for that
`RoundStart` instead of being rejected. Once `RoundEnd` has been handled the
round is closed, and late connections for it are rejected.

Then the sender streams frames:

```
header : file_id u32 | chunk_index u64 | ct_len u32          (16 bytes)
body   : AEAD(k_data(round, conn), nonce = 0u32 | counter u64,
              aad = session_id | header, chunk plaintext)    (ct_len bytes)
```

The counter is per connection, starts at 0, and increments per frame. Because
`k_data` is unique per `(round, conn)` and the counter never repeats on a
connection, a `(key, nonce)` pair is never reused, and no connection has to
coordinate with another. The AAD binds the chunk to this session, file, and
index, so a chunk cannot be replayed into another session or moved to
another offset.

The receiver checks `file_id < files.len()`, `chunk_index < chunk_count`, and
`ct_len == chunk_len + 16` before reading the body. Any failure (bad header,
tag mismatch) closes that connection; chunks it already delivered stay valid.

The last frame is the end marker: `file_id = 0xFFFFFFFF`, `chunk_index = 0`,
and an empty plaintext (`ct_len = 16`). The sender then closes. A connection
that ends without the marker still counts as closed for the round.

## Parallelism

Network parallelism and CPU parallelism are separate knobs. `--connections`
sets how many TCP streams carry data. `--threads` (default: the number of
CPU cores) sets how many workers seal and open chunks. A transfer over 2
connections can still use every core for crypto, and a 32-connection
transfer on a 4-core machine does not oversubscribe the CPU.

The per-connection nonce counter does not force serial crypto. The nonce for
a connection's k-th frame is `0u32 | k`, known before the frame is sealed or
opened, so frames can be processed out of order and the result is still
exact:

- **Receiver.** Each connection has a reader thread that only does I/O. It
  reads a frame's header and body into a pooled buffer and numbers it `k` in
  arrival order. It then hands `(conn key, k, header, buffer)` to a shared
  pool of `--threads` workers. A worker opens the frame, claims the chunk,
  does the positional write, writes the digest, sets `present`, and returns
  the buffer to the pool. Writes go to each chunk's own offset, so workers
  never wait on each other.
- **Sender.** Each connection has a writer thread with a small FIFO of
  pending slots (depth 4). The writer claims the next chunk from the
  scheduler and assigns it the connection's next counter value `k`. It
  submits "read and seal chunk as frame `k`" to the shared worker pool and
  pushes the pending result onto its FIFO. It writes results to the socket
  strictly in FIFO order, which is counter order. Up to 4 frames per
  connection are sealed in parallel while earlier ones are on the wire.

**File scheduling.** The sender's scheduler holds, per file, the chunks
the round still has to send: a contiguous range on a fresh transfer, a
sorted list on a resume or repair round. A connection owns one file's work
and claims from it in ascending order, so its reads are sequential and the
receiver gets that file's chunks in order on one connection. When its work
runs out, the connection takes the unowned file with the most remaining
chunks. When every file with work is owned (fewer files than connections,
or one big file), it steals the second half of the largest owned range or
list; both halves stay ascending. A range with fewer than 16 chunks left is
not split; its owner and the idle connections share it a chunk at a time.
A connection that ends early gives its work back. So with at least as many
files as connections, no two connections carry chunks of one file at the
same time; with fewer, the overlap on a file is bounded by how many times
its range was split. Each chunk is still claimed exactly once per round,
because the scheduler hands it out from exactly one range or list under
one lock, and frame counters are still per connection and assigned in the
order the connection claims, so the nonce rule is unchanged.

**Backpressure.** Buffers come from a bounded pool of
`2 * threads + connections` buffers of `chunk_size + 32` bytes. When the
pool is empty, readers stop reading, and TCP flow control slows the sender.
Memory therefore stays at about that many chunks, no matter how fast
either side is. If that would exceed 1 GiB (large chunks with many
threads), the pool shrinks to fit. It never goes below `threads`.

A frame that fails to open ends its connection, as before. Frames from that
connection that other workers already opened are valid on their own, since
each one authenticated under its own nonce, and they are kept.

## Ordering, duplicates, and late data

Chunks arrive in any order across connections, and that is by design.
Arrival order never decides where bytes go. Each chunk's `file_id` and
`chunk_index` are authenticated in its AAD, and the receiver writes the
plaintext at `chunk_index * chunk_size` with a positional write. A file
assembled from chunks that arrived in any order is byte-identical to the
source.

Within one connection the order is strict. TCP delivers the bytes in order,
and the AEAD nonce is the frame counter, so a frame that is dropped,
reordered, or replayed on a connection fails authentication, and the
connection closes. A connection is either exactly in order or dead.

**No duplicate writes.** The receiver keeps two bitsets per file:

- `claimed` is in memory only. A chunk is claimed with an atomic
  test-and-set right after its frame authenticates and before any write.
- `present` is checkpointed to disk. A chunk is set present only after its
  bytes and its digest (see "Verification") have been written.

If the claim finds the bit already set, the frame is a duplicate: it is
dropped without touching the file and counted in `duplicate_chunks`. If
the write fails, the claim is released, so the chunk stays missing and a
later round sends it again. The sender never sends the same chunk twice in
one round, because each connection claims chunks from a shared atomic cursor.
In later rounds it sends only what the receiver's `Have` reports missing.
An honest transfer therefore reports `duplicate_chunks = 0`, and the tests
assert that.

**Late data.** A data connection can outlive its round, for example when it
stalls, or when the receiver stops waiting for it after the round's
timeout. When a round closes, the receiver shuts down any of that round's
connections that are still open, waits for their reader threads to exit,
and discards frames still buffered in them. Closing the round is a
barrier: only once every reader of the round is gone does the receiver
wait for the frames they handed to the workers, and only then does it
judge whether every chunk is present. A reader that was mid-frame when
the round closed cannot slip that frame past the verification pass.
A late connection that tries to join a closed round is rejected at
admission, because its `round` no longer matches. If a late frame does get
through before the shutdown, the claim bitset handles it:

- Late frame for a chunk that is already present: dropped as a duplicate.
- Late frame for a missing chunk: it is authentic data, so it is written,
  and the copy the next round sends is dropped instead.

Either way each chunk's bytes are written once per session. The sender
learns what arrived only from `Have`, never from what it sent.

## Verification

Authenticated transport proves every chunk left the sender intact. It does
not prove that the bytes on the receiver's disk are still right at the end,
for example after a crash-and-resume, a disk or memory fault, or a bug in
the write path. So before finishing, the receiver checks its own disk.

- On receipt, after a chunk authenticates, the receiver computes
  `digest = BLAKE3(plaintext)` truncated to 16 bytes. It writes the digest
  at offset `chunk_index * 16` of `out/<path>.mjolnir-sums`, after writing
  the chunk and before setting its `present` bit. Digests live on disk, not
  in memory, so the cost scales to any file size.
- When every chunk is present, the receiver syncs the part and sums files.
  It then reads every chunk back from the part file, using a pool of up to
  16 threads, recomputes each digest, and compares it with the stored one.
  Chunks under 64 KiB are read in runs of adjacent chunks, up to 64 KiB
  per read with the run's digests in one more read, and each chunk is
  still hashed, compared, and repaired on its own. Chunks carried over
  from an earlier session are checked the same way; that is the main
  point.
- A mismatch clears that chunk's `present` and `claimed` bits. The receiver
  then sends `Have` instead of `Finished`, and the next round resends only
  the bad chunks, never the whole file. These count in `repaired_chunks`.
  Verification repairs count as progress for the 3-failed-rounds rule. A
  chunk that fails verification 3 times in one session ends the session
  with `Error { "chunk <k> of <path> keeps failing verification" }`,
  because that points at hardware, not the network.

Verification is on by default. `recv --no-verify` skips the read-back (the
digests are still written, so a later resume can still check them), and
`Finished { verified }` tells the sender which way it went.

The read-back can be served from the OS page cache. It catches software
bugs, stale resume data, and corruption in memory or on the write path. It
is not proof that the media holds the bytes; that is the filesystem's job.

## Receiver storage and resume

The receiver stages everything under `out/.mjolnir-staging/`, a directory
it creates readable by its owner only (mode `0700` on Unix, a DACL naming
only the current user and SYSTEM on Windows). That directory holds a
`lock` file on which each session takes an exclusive lock (`flock` or
`LockFileEx`), so only one session at a time receives into an output
directory; a second receiver fails its session with "another receiver is
using" and keeps waiting. The lock file stays after the transfer.

Each transfer has an **identity**: `BLAKE3("mjolnir transfer v2" |
sender public key | chunk_size | postcard(files))`, over the offered
files' paths, sizes, and mtimes. Its staging directory is
`out/.mjolnir-staging/<first 16 bytes of the identity, hex>/`, and file
`j` of the offer lives there as `j.part` (the bytes), `j.sums` (16-byte
digests, at `index * 16`), and `j.state` (`{ size, mtime, chunk_size,
bitmap }`). Staging files are created readable by their owner only
(`0600`), so no other user can read plaintext while it is staged or after
a cancel, and the short internal names keep a target name of any legal
length from growing past the file system's component limit. A transfer
from another sender, or of a source whose size or mtime changed, has a
different identity and shares nothing with an earlier attempt.

Every 2 seconds, at the end of each round, and when a session ends early,
the receiver checkpoints each file in this order: snapshot the `present`
bitmap, `sync_data` the part file and the sums file, write the snapshot to
`j.state.tmp`, sync it, rename it over `j.state`, and sync the directory.
A crash therefore loses at most the chunks received since the last
checkpoint, and never marks a chunk present whose bytes are not on disk.

On a new session under the same identity, a file whose part, sums, and
state files exist resumes from its bitmap. Chunks reported present in
`Have` are then checked against the source before round 0: the sender
re-reads them and sends their digests, then `Resume`, and the receiver
makes every chunk whose stored digest differs missing again and answers
with the corrected `Have`. So an earlier session's bytes are trusted only
if they still match what the sender would send now, whatever left them
there; these count in the receiver's `stale_chunks`. The read-back
verification alone proves the disk matches the receiver's own digests,
not that those digests came from this source, which is why this check
exists.

The receiver holds at most 256 part and sums handle pairs open at once
and reopens the rest as it works, so a tree of any number of files fits
in an ordinary descriptor limit; the sender keeps its source files open
the same way and re-checks size and mtime whenever it reopens one.

**Publication.** After the final round and verification, the receiver
publishes each file: it syncs the part file, sets its final mode while it
is still private (the file map's mode under the special-bit policy, or
what `creat` would give under the umask; on Windows the read-only bit is
applied afterwards through the file map), renames it to its target, and
syncs the target's directory (on Windows `MoveFileEx` with
`MOVEFILE_WRITE_THROUGH`). Without `--force` the rename refuses to replace
an existing target atomically (`RENAME_NOREPLACE`, `RENAME_EXCL`, or
`MoveFileEx` without `MOVEFILE_REPLACE_EXISTING`), so a file created at
the destination while the transfer ran fails the session instead of being
overwritten; the existence check at session start is only an early
error. `Finished` goes out only after every rename and directory sync has
returned.

**The journal.** The staging directory is the finalization journal. A
file's commit is its one rename, so a crash during publication leaves
every file either staged (its `j.part` exists) or published (its `j.part`
is gone while `j.sums` remains). A later session under the same identity
treats a published file whose target exists with the offered size as
held, keeps verifying it against `j.sums` (reading the published file
back), and repairs it in place if a chunk fails; it re-sends nothing that
is already right and needs no `--force`. When `Finished` is answered with
`Ack`, the receiver renames the staging directory to `<identity>.done`
and removes it, directory syncs included. Without an `Ack` within 5
seconds (the sender never saw `Finished`), it keeps the journal, and the
sender's retry replays the same way. A `<identity>.done` directory found
at startup is a cleanup that was interrupted after `Ack`; its files are
all published, and a missing `j.sums` is regenerated from the published
file. Journals of transfers that were never retried stay under
`.mjolnir-staging/` until the user removes them.

## What the protocol guarantees

Mutual authentication: the sender talks only to the holder of the pinned
receiver key, and the receiver accepts files only from authorized sender
keys. Confidentiality and integrity of every chunk, the manifest, and all
control messages against a network attacker. Forward secrecy, because
`master` travels under ephemeral Diffie-Hellman keys. Completeness and
order: the receiver finishes only when every chunk of every file has been
authenticated, written once at its own offset, and (by default) read back
and matched against its digest.

Not covered: NAT traversal or relays, hiding file sizes or timing, key
revocation beyond editing the authorized keys file, and protection against
an authorized peer.
