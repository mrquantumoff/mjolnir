# Mjolnir tunnels

`mjolnir tunnel` forwards TCP ports through a `mjolnir tunnel-server`, the
way `ssh -L` and `ssh -R` do, using the same pinned X25519 keys and Noise IK
handshake as a file transfer. Each forwarded TCP connection is a **stream**.
A stream travels over its own K TCP connections to the server:

- **K = 1** (the default) is plain port forwarding. Streams are independent,
  so a slow or stalled stream never holds up another, unlike forwarding
  over one multiplexed SSH connection.
- **K > 1** (`-n K`) stripes each stream across K connections, frame by
  frame. This helps on long high-latency links, where one TCP connection's
  window caps throughput, and on paths that throttle each connection.

The client always opens every connection, so only the server has to be
reachable, and `-R` works from behind NAT.

## Quick start

On the server host, allow the client's key and say what it may reach:

```sh
mjolnir tunnel-server --key server.key --allow <CLIENT_PUBLIC_KEY> \
    --permit-open db.internal:5432 --permit-listen 127.0.0.1:8080
```

On the client, pin the server's key and forward:

```sh
# localhost:15432 on the client reaches db.internal:5432 from the server.
mjolnir tunnel server.example:7778 --key client.key --peer <SERVER_PUBLIC_KEY> \
    -L 15432:db.internal:5432

# 127.0.0.1:8080 on the server reaches localhost:3000 on the client.
mjolnir tunnel server.example:7778 --key client.key --peer <SERVER_PUBLIC_KEY> \
    -R 8080:localhost:3000

# One bulk stream striped over 8 connections.
mjolnir tunnel server.example:7778 --key client.key --peer <SERVER_PUBLIC_KEY> \
    -n 8 -L 9000:backup.internal:9000

# As an ssh ProxyCommand: stdin and stdout become one stream.
ssh -o ProxyCommand="mjolnir tunnel relay:7778 --key client.key --peer <KEY> -W %h:%p" host
```

## Commands and flags

`mjolnir tunnel <HOST:PORT>` connects to a tunnel server:

| Flag | Default | Meaning |
|---|---|---|
| `--key PATH` | required | this host's private key |
| `--peer KEY` | required | the server's public key |
| `-L, --local SPEC` | | `[BIND:]PORT:HOST:HOSTPORT`: listen on `BIND:PORT` here; each connection reaches `HOST:HOSTPORT` from the server; repeatable |
| `-R, --remote SPEC` | | `[BIND:]PORT:HOST:HOSTPORT`: the server listens on `BIND:PORT`; each connection reaches `HOST:HOSTPORT` from here; repeatable |
| `-W, --stdio HOST:PORT` | | carry one stream over stdin and stdout to `HOST:PORT` from the server, then exit |
| `-n, --connections N` | `1` | connections per stream, 1 to 32 |
| `--cipher NAME` | `aes256gcm` | `aes256gcm` or `chacha20poly1305`, for stream frames |
| `-v, --verbose` | off | log every stream |

`BIND` defaults to `127.0.0.1`; an empty `BIND` or `*` means every
interface (`0.0.0.0`). IPv6 addresses go in brackets: `[::1]:8080:web:80`.
The client sets up every `-R` listener and binds every `-L` listener before
it reports `tunnel up`, and exits with an error if any of them fails, or
when the session ends. Run it under a supervisor (systemd, `autossh`-style
loop) to reconnect.

`mjolnir tunnel-server` accepts clients:

| Flag | Default | Meaning |
|---|---|---|
| `--key PATH` | required | this host's private key |
| `--authorized FILE` | | allowed client keys, one `[options] <base64> [comment]` per line |
| `--allow KEY` | | allow one client key; repeatable |
| `--listen ADDR` | `0.0.0.0:7778` | address to listen on |
| `--permit-open HOST:PORT` | none | targets clients may reach with `-L` and `-W`; repeatable |
| `--permit-listen HOST:PORT` | none | addresses clients may listen on with `-R`; repeatable |
| `-v, --verbose` | off | log every stream |

The server serves any number of clients at once and runs until stopped.

## Permissions

A tunnel server that forwards to anywhere would hand every authorized key
the server's network position. So nothing is permitted by default: a key
may only open connections to targets matching a `permitopen` pattern, and
only listen on addresses matching a `permitlisten` pattern.

A pattern is `HOST:PORT`, where either side may be `*`, and `*` alone
matches everything. Hosts compare as the client wrote them, ignoring ASCII
case, before any name resolution: `localhost:22` does not permit
`127.0.0.1:22`, and a permitted name that resolves to a new address still
reaches it.

`--permit-open` and `--permit-listen` set the defaults for every key. A
line in the `--authorized` file can carry its own options, as in SSH's
`authorized_keys`, and a key with any options gets exactly those instead of
the defaults:

```
# Can reach the database, nothing else.
permitopen="db.internal:5432" AAAA...= laptop
# Can publish one port on the server's loopback, and reach nothing.
permitlisten="127.0.0.1:8080" BBBB...= ci-runner
# Gets the --permit-* defaults.
CCCC...= admin
```

Options are comma-separated `name=value` pairs with no spaces outside double
quotes. `mjolnir recv` reads the same file format and ignores the options.

Which side may start streams follows from the forward's direction. For
`-L`, the client asks and the server checks `permitopen`. For `-R`, the
server only ever reports a connection on a listener the client asked for,
and the client connects to the target it configured itself; the server
never names a destination, so it cannot steer the client anywhere.

## Protocol

Tunnels reuse the building blocks of [PROTOCOL.md](PROTOCOL.md): the
connection preamble, the Noise IK handshake and key schedule, and the
control channel framing. Fixed-layout fields are big-endian; control
messages are postcard-encoded.

### Connections

Every connection starts with the preamble `"MJLN" | version u8 = 2 | kind
u8`, with kind 2 for the tunnel control connection and kind 3 for a stream
connection. A `recv` that gets kind 2 or 3, or a `tunnel-server` that gets
kind 0 or 1, logs the mistake and closes the connection.

### Handshake and keys

The control connection runs `Noise_IK_25519_ChaChaPoly_SHA256` exactly as a
transfer does, with the client as initiator, but with the prologue
`mjolnir tunnel v1`. A handshake made for a transfer therefore never opens a
tunnel session, nor the reverse. The server rejects unknown keys silently,
with at most 256 connections in the handshake at once and 10 seconds for
the preamble and message 1.

Keys come from the same `PRK` as a transfer's (`E(l)` is HKDF-Expand of the
label `l`), plus:

| Name | Derivation | Use |
|---|---|---|
| `k_ctrl_s2r`, `k_ctrl_r2s` | `E("ctrl s2r")`, `E("ctrl r2s")` | control messages client to server, server to client |
| `k_hello` | `E("hello")` | stream connection admission MAC |
| `session_id` | first 16 bytes of `E("session id")` | bound into every frame's AAD |
| `route` | first 16 bytes of `E("tunnel route")` | names the session in stream hellos |
| `k_stream(s,i,d)` | `E("tunnel" \| s u32 \| i u32 \| d u8)` | connection `i` of stream `s`, direction `d` (0 client to server, 1 server to client) |

### Control channel

Control messages are framed and sealed as in a transfer (`u32 len |
ChaCha20-Poly1305(k, nonce = 0u32 | counter u64, postcard(msg))`), at most
64 KiB each. The postcard enum tags are:

| Tag | Message | Direction | Meaning |
|---|---|---|---|
| 0 | `Hello { cipher }` | C to S | first message; proves the client is live and picks the frame cipher |
| 1 | `Welcome { max_conns }` | S to C | the session is up |
| 2 | `Open { stream, host, port, conns }` | C to S | start `-L` stream `stream` to `host:port` over `conns` connections |
| 3 | `Listen { id, host, port, conns }` | C to S | listen on `host:port` for `-R` |
| 4 | `Listening { id, addr }` | S to C | listener `id` is bound to `addr` |
| 5 | `ListenFailed { id, message }` | S to C | listener `id` was refused |
| 6 | `Incoming { listener, stream, from }` | S to C | listener `listener` accepted `from`; it travels as stream `stream` |
| 7 | `Close { stream, message }` | both | stream `stream` failed to start |
| 8 | `Error { message }` | both | the sender is ending the session |

Noise message 1 can be replayed, so the server keeps a connection out of
the session until its `Hello` decrypts (within 10 seconds). Only then does
it register the session under its `route` and answer `Welcome`.

Client stream ids are 1, 2, 3, ... in the order of their `Open`s; server
stream ids (for `-R`) have the top bit set. The server refuses an `Open`
whose id is not above every earlier one, which lets it tell a stream that
is still to come from one that is over.

### Stream connections

For each stream, the client opens `conns` connections, in parallel, right
after sending `Open` (for `-L`) or on `Incoming` (for `-R`):

```
C -> S : preamble (kind 3)
S -> C : challenge (32 random bytes)
C -> S : route[16] | stream u32 | conn u32 | HMAC-SHA256(k_hello, challenge | stream | conn)
         ... the server connects to the target and gathers all conns connections ...
S -> C : 0x01 (admitted)
```

The server finds the session by `route` and checks the MAC in constant
time. A connection can arrive before its stream's `Open` is read, since
they travel on different TCP connections; one naming a client id above the
highest seen waits up to 15 seconds for it. Each connection index is taken
once. Once all `conns` connections are in and (for `-L`) the target
connection is up, the server writes the admission byte on every one of
them and the stream starts. If the target is refused or not permitted, or
the connections do not all arrive within 15 seconds, the server sends
`Close` with the reason and drops the connections. For `-R`, the client
connects to its target while its connections are admitted, and sends
`Close` if that fails.

### Frames

After admission, each connection carries frames both ways:

```
header = seq u64 | kind u32 (0 = data, 1 = fin) | ct_len u32
frame  = header | AEAD(k_stream(s, i, d), nonce = 0u32 | k u64,
                       aad = session_id | header, plaintext)
```

`k` counts frames per connection and direction from 0, so a frame cannot
be replayed, dropped, or reordered within a connection without failing to
open. `seq` numbers the frames of one direction of the stream across all
its connections, and each connection carries increasing `seq`s. A data
frame holds 1 to 65536 plaintext bytes; a fin frame holds none and ends
that direction, like a TCP half-close.

The sender reads its local socket, numbers each read as a frame, and hands
frames to whichever connection's writer is free, in order. The receiver
puts frames back in `seq` order in a buffer of at most `(K + 1) * 2` MiB (up
to 64 MiB), but always accepts the frame it needs next; since each
connection's `seq`s increase, the connection carrying that frame is never
stuck behind a later one, so a full buffer cannot deadlock. It stops reading
the connections that are ahead, and TCP flow control slows the sender.

A stream ends cleanly when both directions have delivered their fin. It
aborts on any error: a frame that fails to open, a connection that fails,
or every connection closing before the peer's fin. An aborted stream closes
its connections, which the peer sees as the connections ending without a
fin, and resets its local TCP connection (`SO_LINGER` 0), so an application
sees a failure rather than an end of stream that would pass a cut-off
download as complete. One failed connection aborts its whole stream:
frames on it are lost, and there is no retransmission above TCP.

When the control connection ends, every stream and listener of the session
ends with it, and so do its streams' local connections, with a reset. The
same happens on Ctrl-C, on either side: the client or server resets the
connections its streams carried before it exits.

### Limits

| Limit | Value |
|---|---|
| Connections per stream | 32 |
| Streams per session, starting or running | 256 |
| `-R` listeners per session | 64 |
| Unauthenticated connections at once | 256 |
| Connecting to a target | 10 s |
