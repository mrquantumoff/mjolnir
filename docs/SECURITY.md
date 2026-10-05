# Security model

Keys are pinned in the WireGuard and SSH style. The sender only talks to the
holder of the receiver key it passed with `--peer`, and the receiver only
accepts senders whose keys it was given. There are no certificates and no
trust on first use. The handshake is `Noise_IK_25519_ChaChaPoly_SHA256` as
implemented by the [snow](https://crates.io/crates/snow) crate; mjolnir does
not implement Noise itself. It does supply the primitives snow runs on, so
the static and ephemeral private keys, the handshake's cipher keys, and the
HMAC buffers are wiped from memory when the handshake ends. Some copies stay
behind. snow keeps the final chaining key and transcript hash in its own
state, and the Diffie-Hellman results and key-derivation temporaries pass
through its stack. That chaining key only derives snow's transport keys,
which mjolnir never uses. The session secret travels under ephemeral
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
not receive into a directory that other users can write to. A Windows
service checks who can change its `--out` folder, or the nearest folder
above it that exists, but not the folders under it. Do not grant other
accounts write access anywhere under a service's `--out`. A subfolder
they can change could be swapped for a junction that redirects the
receiver's writes as SYSTEM. A service's binary, key, authorized-keys
file, log, and output folder may not pass through a junction, symlink,
or mounted-folder link; give their real paths.
