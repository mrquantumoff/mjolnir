# Gorynych protocol, version 1

Gorynych moves large files between two hosts over N parallel TCP connections.
Files are split into fixed-size chunks (the sender picks the size). Each chunk
is sealed with an AEAD on its own, so every connection reads, encrypts, and
sends independently, and the receiver decrypts and writes each chunk at its
offset with a positional write. Nothing is encrypted as a whole file first.

All integers on the wire are big-endian.

## Roles

The **receiver** listens on a TCP port. The **sender** connects, both sides
authenticate with their static key pairs, the sender offers a manifest, and
then it opens data connections. One receiver process serves one transfer,
then exits.

## Identities

Every host has a static X25519 key pair, created with `gorynych keygen`.
Keys are encoded as standard base64 of the 32 raw bytes (44 characters), the
same form WireGuard uses.

- The private key lives in a file holding the base64 text and a newline. On
  Unix it is created with mode `0600`.
- The sender pins the receiver's public key (`--peer`), like an SSH
  `known_hosts` entry.
- The receiver admits only senders whose public key is listed in its
  authorized keys file (`--authorized`), like SSH `authorized_keys`. Each
  line is `<base64 key> [comment]`; blank lines and lines starting with `#`
  are ignored. `--allow <KEY>` adds a key from the command line.

## Connection preamble

Every TCP connection starts with the sender writing 6 bytes:

```
"GRYN" (4 bytes) | version u8 = 1 | kind u8 (0 = control, 1 = data)
```

The first connection must be the control connection. Data connections are
accepted only after the control handshake has finished.

## Control handshake (Noise IK)

The control connection runs `Noise_IK_25519_ChaChaPoly_SHA256` with prologue
`gorynych v1`. The sender is the initiator and already knows the receiver's
static public key. Each Noise message is framed with a length:

```
S -> R : u16 len | Noise msg 1   (-> e, es, s, ss)   payload empty
R -> S : u16 len | Noise msg 2   (<- e, ee, se)      payload = master (32 random bytes)
```

After message 1 the receiver knows the sender's static key. If that key is
not authorized, the receiver closes the connection without replying and
exits. If the sender pinned the wrong receiver key, the receiver cannot
decrypt message 1 and also closes. The sender reports both cases as "the
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

The sender's first control message (`Offer`) is sealed under `k_ctrl_s2r`,
so a successful decrypt confirms to the receiver that the sender is live and
holds the key it authenticated with.

## Control channel

After the handshake, each control message is:

```
u32 len | ChaCha20-Poly1305(key, nonce = 0u32 | counter u64, aad = "", postcard(msg))
```

Each direction has its own key and its own counter starting at 0. `len`
counts ciphertext plus tag and is capped at 64 MiB.

Messages (a postcard-encoded enum):

| Message                              | Direction | Meaning                                                   |
|--------------------------------------|-----------|-----------------------------------------------------------|
| `Offer { chunk_size, cipher, files }`| S to R    | manifest; `files[j] = { path, size, mtime }`               |
| `Have { bitmaps }`                   | R to S    | per file, the chunks the receiver already holds           |
| `RoundStart { round }`               | S to R    | sender is about to open data connections for `round`      |
| `RoundEnd { round, connections }`    | S to R    | sender's data connections for `round` are closed; `connections` is how many the receiver admitted |
| `Finished`                           | R to S    | every chunk is present, synced, and renamed into place    |
| `Error { message }`                  | both      | fatal; the peer prints it and exits                       |

`path` uses `/` separators and is relative. The receiver rejects absolute
paths, drive or UNC prefixes, `\`, empty components, `.` and `..` components,
and duplicate paths. `file_id` is the index into `files`.

`chunk_size` is between 4 KiB and 64 MiB. File `j` has
`ceil(size / chunk_size)` chunks. Chunk `k` covers bytes
`[k * chunk_size, min(size, (k + 1) * chunk_size))`. An empty file has zero
chunks.

`cipher` is `Aes256Gcm` (default, hardware accelerated on x86-64 and ARMv8)
or `ChaCha20Poly1305`.

### Session flow

```
S -> R : Offer
R -> S : Have                 (resume state; all zero on a fresh transfer)
loop round = 0, 1, ...:
    S -> R : RoundStart { round }
    S opens up to N data connections, sends every chunk missing from Have
    S -> R : RoundEnd { round, connections }
    R waits until `connections` data connections of this round have closed
    if every chunk is present:
        R syncs files, renames them into place
        R -> S : Finished     (done)
    else:
        R -> S : Have         (sender sends what is still missing)
```

A round that makes no progress counts as a failure. After 3 consecutive
failed rounds the sender sends `Error` and gives up. Resending a chunk is
harmless because it rewrites identical bytes at the same offset.

## Data connections

```
S -> R : preamble (kind = 1)
R -> S : challenge (32 random bytes)
S -> R : round u32 | conn u32 | HMAC-SHA256(k_hello, challenge | round | conn)
R -> S : 0x01 admitted, or 0x00 rejected (then close)
```

The receiver admits a connection only if the MAC is valid, `round` is the
current round, and `(round, conn)` has not been admitted before. The fresh
challenge stops a captured hello from being replayed.

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

## Receiver storage and resume

For a target `out/<path>` the receiver writes `out/<path>.gorynych-part` and
keeps state in `out/<path>.gorynych-state`. The state holds
`{ size, mtime, chunk_size, bitmap }`.

Every 2 seconds, and at the end of each round, the receiver checkpoints each
file in this order: snapshot the bitmap, `sync_data` the part file, then
atomically replace the state file with the snapshot. A crash therefore loses
at most the chunks received since the last checkpoint, and never marks a chunk
present whose bytes are not on disk.

On a new session, if both the part and state files exist and the state's
`size`, `mtime`, and `chunk_size` match the offer, the receiver reports that
bitmap in `Have`. Otherwise it starts the file from scratch.

After the final round the receiver syncs every file, renames each part file
to its target, and deletes the state files. An existing target is an error
unless the receiver was started with `--force`.

## What the protocol guarantees

Mutual authentication: the sender talks only to the holder of the pinned
receiver key, and the receiver accepts files only from authorized sender
keys. Confidentiality and integrity of every chunk, the manifest, and all
control messages against a network attacker. Forward secrecy, because
`master` travels under ephemeral Diffie-Hellman keys. Completeness: the
receiver finishes only when every chunk of every file has been
authenticated and written.

Not covered: NAT traversal or relays, hiding file sizes or timing, key
revocation beyond editing the authorized keys file, and protection against
an authorized peer.
