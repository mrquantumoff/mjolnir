# mjolnir

mjolnir copies large files between two hosts you control. It splits each
file into chunks, encrypts every chunk with an AEAD, and sends them over
several TCP connections at once. Both hosts authenticate with pinned key
pairs, and an interrupted transfer resumes where it stopped.

It also forwards TCP ports, like `ssh -L` and `ssh -R`, over the same
authenticated sessions.

## Install

Prebuilt binaries cover Linux, macOS, and Windows on x86_64 and aarch64.
The install scripts check each release's signature and checksums before
installing; see [docs/RELEASING.md](docs/RELEASING.md).

```sh
# Linux and macOS, into ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/mrquantumoff/mjolnir/master/scripts/install.sh | bash
```

```powershell
# Windows, into %LOCALAPPDATA%\Programs\mjolnir, added to the user PATH
irm https://raw.githubusercontent.com/mrquantumoff/mjolnir/master/scripts/install.ps1 | iex
```

`MJOLNIR_VERSION` picks a tag and `MJOLNIR_INSTALL_DIR` a folder. To build
from source, run `cargo build --release`.

`mjolnir update` replaces the binary with the latest signed release, and
`mjolnir update --check` only reports whether one exists.

## Quick start

Create a key pair on each host. `keygen` writes the private key and prints
the public key:

```sh
mjolnir keygen --out mjolnir.key
```

Swap public keys through a channel you trust. On the receiver:

```sh
mjolnir recv --key mjolnir.key --allow <SENDER_PUBLIC_KEY> --out ./incoming
```

On the sender:

```sh
mjolnir send receiver.example:7777 --key mjolnir.key \
    --peer <RECEIVER_PUBLIC_KEY> big.iso photos/
```

`recv` exits after one transfer; `recv --keep-listening` takes one after
another until stopped. Every command and flag is in
[docs/USAGE.md](docs/USAGE.md) and `mjolnir <command> --help`.

## Tunnels

A `tunnel-server` carries TCP connections for authorized clients, and
allows nothing by default:

```sh
mjolnir tunnel-server --key server.key --allow <CLIENT_PUBLIC_KEY> \
    --permit-open db.internal:5432
```

The client takes ssh-style `-L` and `-R` specs:

```sh
# localhost:15432 here reaches db.internal:5432 from the server.
mjolnir tunnel server.example:7778 --key client.key --peer <SERVER_PUBLIC_KEY> \
    -L 15432:db.internal:5432 --reconnect
```

`--reconnect` sets up a new session whenever one ends, after the first
one succeeds. `-n N` stripes each stream across N connections, and `-W
HOST:PORT` works as an ssh `ProxyCommand`. Permissions and limits are in
[docs/TUNNEL.md](docs/TUNNEL.md).

## Running as a service

On Windows, `mjolnir service` installs, starts, stops, and removes a
Windows service that runs `recv --keep-listening`, `tunnel-server`, or
`tunnel --reconnect` as SYSTEM:

```powershell
mjolnir service install inbox -- recv --keep-listening --key recv.key `
    --authorized senders.txt --out incoming
mjolnir service start inbox
```

It refuses a binary, key, or folder that non-administrators can change. On
Linux, run the same commands from a systemd unit. Both are in
[docs/SERVICE.md](docs/SERVICE.md).

## Security

Keys are pinned in the WireGuard and SSH style: no certificates, no trust
on first use. The handshake is `Noise_IK_25519_ChaChaPoly_SHA256`, so
recorded traffic stays private even if both static keys later leak. Every
chunk is authenticated together with its session, file, and offset. An
authorized sender is trusted with the output folder, so do not receive
into a folder other users can write to. Details are in
[docs/SECURITY.md](docs/SECURITY.md).

## Limits

- No relay or NAT traversal: the sender must reach the receiver directly.
- A receiver takes one transfer at a time.
- Only regular files and directories are sent. Symbolic links are followed.
- Private keys are stored unencrypted, protected by file permissions.
- A source edited in place without changing its size or mtime is caught
  only with `send --hash`.

More in [docs/USAGE.md](docs/USAGE.md#behavior-worth-knowing).

## Performance

On one machine over loopback, one 2 GiB file moves at 850-950 MiB/s, which
is where the disk becomes the limit. Without a disk, transfers reach about
4 GiB/s. Method and full tables are in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## More

- [docs/PROTOCOL.md](docs/PROTOCOL.md): the wire format
- [docs/WEB.md](docs/WEB.md): `mjolnir serve`, a local web UI
- [docs/prior-art.md](docs/prior-art.md): how mjolnir compares with other tools

## License

BSD 2-Clause; see [LICENSE](LICENSE).
