# Web UI

`mjolnir serve` runs a small local web app for starting and watching
transfers. It uses the same key as the command line and runs the same library
code, so a transfer started in the browser is identical to one started with
`mjolnir send` or `mjolnir recv`.

```
mjolnir serve [--listen 127.0.0.1:7878] [--key PATH] [--no-open]
```

It prints a URL like

```
Mjolnir web UI: http://127.0.0.1:7878/#token=3f9c0d6e1a2b4c5d6e7f8091a2b3c4d5
```

and opens it in the default browser unless `--no-open` is given. Without
`--key` it loads the default key file, creating one on first run. The server
runs until you stop it with Ctrl-C; stopping it aborts every transfer it
started.

![A send and its receiver mid-transfer, an idle receiver, a failed send](web-ui/running.png)

## Using it

The header shows your public key with a Copy button. Give it to the other
side: a receiver lists it as an authorized sender, and a sender pins it as
the receiver's key.

**Receive files.** Pick a listen address (default `0.0.0.0:7777`, use port 0
for any free port), an output folder, and the sender keys to admit, one per
line as `key [label]`. Tick "Overwrite existing files" to replace files that
already exist in the output folder. "Verify after transfer" (on by default)
reads every chunk back from disk before finishing and fetches again any that
do not match. "CPU threads" sets how many workers open chunks; leave it
empty for one per core. The receiver binds immediately, so a
port that is already in use is reported on the form. Its card shows the bound
address with a Copy button, to paste into the sender's form. Each receiver
takes one complete transfer, then finishes; a sender that fails the
handshake or drops mid-session does not end it, and it goes back to waiting.
Several receivers can wait on different ports at once.

**Send files.** Enter the receiver's address and public key, add files and
folders with the file browser, and optionally tune the number of connections
(1 to 64, default 8), the chunk size, the cipher, and the CPU threads that
seal chunks (empty means one per core). Recent peers are remembered in the
browser.

![The file browser: folders navigate, checkboxes select files and folders](web-ui/picker.png)

Each transfer card shows its phase, a progress bar, bytes done and total,
throughput and ETA (computed in the browser from successive polls), and the
number of active connections. Running transfers have a Cancel button;
finished ones have Remove. Failed transfers show the error. Finished ones show
a summary: files, bytes, time, average speed, whether every chunk was
verified, and any repaired, duplicate, or resent chunks.

![Finished transfers with their summaries](web-ui/done.png)

The page follows the system light or dark theme and works down to phone
width.

![Dark theme](web-ui/running-dark.png)

<img src="web-ui/mobile.png" alt="Phone width, 375 px" width="375">

## Security model

The server can read any file the user can read and send it to any address,
so every request is treated as hostile until it proves otherwise.

- **Loopback by default.** It binds `127.0.0.1` unless `--listen` says
  otherwise. Any other address prints a loud warning, because anyone who can
  reach the port and learns the token has full control.
- **Per-run access token.** Each run generates a random 128-bit token. It
  travels in the URL fragment (`#token=...`), which browsers never send to
  the server, so it stays out of request lines, logs, and `Referer` headers.
  The page moves it into `sessionStorage`, removes it from the address bar,
  and sends `Authorization: Bearer <token>` on every API call. The server
  compares it in constant time. A missing or wrong token gets 401. The static
  page itself (`/`, `/app.js`, `/app.css`) needs no token and holds no data.
- **DNS-rebinding guard.** A request whose `Host` header is not
  `127.0.0.1:PORT`, `localhost:PORT`, or `[::1]:PORT` gets 403. When bound
  to a specific non-loopback address, that address is also accepted. When
  bound to `0.0.0.0` or `::`, any IP literal with the right port is accepted;
  a rebinding attack needs a DNS name in `Host`, so IP literals are safe.
- **No cross-origin writes.** Every non-GET request must carry
  `Content-Type: application/json`, which a cross-origin page cannot send
  without a CORS preflight, and the server never answers preflights or sends
  CORS headers. If an `Origin` header is present it must be
  `http://<Host>`. Violations get 403.
- **Browser hardening.** The HTML is served with
  `Content-Security-Policy: default-src 'self'; connect-src 'self'; script-src 'self'; ...`,
  `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and
  `Cache-Control: no-store`. Scripts and styles are separate embedded files,
  so no inline script is needed. The page builds the DOM with `textContent`,
  never `innerHTML`, so file names and error text cannot inject markup.
- **Bounded input.** Request bodies are capped at 1 MiB (413 beyond that).
  Every field is parsed and range-checked in the handler before any work
  starts.
- **The private key never leaves the process.** The API returns only the
  public key and the key file's path.

## API

All endpoints live under `/api`, require the token, and speak JSON. Errors
have the shape `{ "error": "message", "field": "name" | null }`, where
`field` names the request field at fault.

| Status | Meaning |
|--------|---------|
| 400 | Invalid input; `field` says which |
| 401 | Missing or wrong token |
| 403 | Bad `Host`, bad `Origin`, or a non-JSON write |
| 404 | No such transfer or endpoint |
| 405 | Wrong method for the endpoint |
| 409 | Removing a transfer that is still running |
| 413 | Body over 1 MiB |

### `GET /api/identity`

```json
{ "public_key": "base64", "key_path": "/home/me/.config/mjolnir/key" }
```

### `GET /api/transfers`

`{ "transfers": [Transfer, ...] }`, newest first.

```json
{
  "id": 2,
  "kind": "send",
  "spec": {
    "addr": "10.0.0.2:7777",
    "peer": "base64",
    "paths": ["/data/run-42"],
    "connections": 8,
    "chunk_size": 1048576,
    "cipher": "Aes256Gcm",
    "threads": 0
  },
  "created_at_ms": 1790000000000,
  "state": "running",
  "error": null,
  "report": null,
  "bound_addr": null,
  "progress": {
    "phase": "transferring",
    "bytes_done": 734003200,
    "bytes_total": 2147483648,
    "chunks_done": 700,
    "chunks_total": 2048,
    "active_connections": 8
  },
  "elapsed_ms": 1840
}
```

- `kind` is `send` or `receive`. A receive `spec` is
  `{ "listen", "authorized": [keys], "out_dir", "force", "verify", "threads" }`.
- `state` is `running`, `done`, `failed`, or `cancelled`. `error` is set
  when failed, `report` when done:
  `{ "files", "bytes", "elapsed_ms", "verified", "chunks_resent", "repaired_chunks", "duplicate_chunks" }`.
  Counts that do not apply to a side are 0.
- `bound_addr` is the receiver's actual listening address, `null` for sends.
- `progress.phase` is `connecting`, `handshaking`, `transferring`,
  `verifying`, `finishing`, `done`, or `failed`. `bytes_total` is 0 until the
  manifest is known. While verifying, `bytes_done` counts bytes read back.
- `elapsed_ms` counts from creation to now, or to the end once finished.

### `POST /api/send`

```json
{
  "addr": "host:port",
  "peer": "base64 receiver key",
  "paths": ["/data/run-42", "/data/notes.txt"],
  "connections": 8,
  "chunk_size": 1048576,
  "cipher": "Aes256Gcm",
  "threads": 0
}
```

`connections` (1 to 64), `chunk_size` (4 KiB to 64 MiB), `cipher`
(`Aes256Gcm` or `ChaCha20Poly1305`), and `threads` (0 to 256, 0 meaning one
per core) are optional with the defaults shown.
`addr` may be a host name; it is resolved when the transfer starts. Every
path must exist. Returns the new Transfer.

### `POST /api/receive`

```json
{
  "listen": "0.0.0.0:7777",
  "authorized": ["base64", "..."],
  "out_dir": "/incoming",
  "force": false,
  "verify": true,
  "threads": 0
}
```

`listen` is an `ip:port`; port 0 picks a free one. `force`, `verify`, and
`threads` are optional with the defaults shown. At least one authorized
key is required, and `out_dir` must be an existing folder. The listener binds
before the response is sent, so a busy port is a 400 on `listen`, and the
returned Transfer carries `bound_addr`.

### `POST /api/transfers/{id}/cancel`

Asks a running transfer to stop and returns it. The state turns `cancelled`
once the transfer's thread has unwound. Cancelling a finished transfer is a
no-op. When the peer cancels instead, the transfer ends as `failed` with the
peer's reason.

### `DELETE /api/transfers/{id}`

Removes a finished transfer from the list. Returns 204, or 409 if it is still
running.

### `GET /api/fs?path=...`

Lists a directory for the file picker. Without `path`, lists the home
directory.

```json
{
  "path": "/home/me",
  "parent": "/home",
  "roots": ["/"],
  "entries": [
    { "name": "data", "path": "/home/me/data", "is_dir": true, "size": null },
    { "name": "notes.txt", "path": "/home/me/notes.txt", "is_dir": false, "size": 812 }
  ]
}
```

Directories come first, then files, each sorted by name. On Windows `roots`
lists the drive letters that exist. An unreadable path is a 400 on `path`.

Names are shown lossily. An entry whose full path is not valid Unicode has
`"path": null`, because JSON cannot name it exactly. The picker shows it
greyed out; select its parent folder instead, since sending a folder walks
the raw names. A send that names such a path directly gets a 400 on `paths`
saying so.

## Code layout

| File | Role |
|------|------|
| `src/web/mod.rs` | `ServeConfig`, `WebServer` (bind, URL, worker threads), `serve` |
| `src/web/http.rs` | Admission checks, static assets, response headers |
| `src/web/api.rs` | Routing, request validation, handlers, response DTOs |
| `src/web/jobs.rs` | The transfer registry and each job's thread |
| `src/web/fs.rs` | Directory listing for the picker |
| `src/web/assets/` | `index.html`, `app.js`, `app.css`, embedded with `include_str!` |

`tests/web.rs` drives the API over real HTTP: the admission checks, input
validation, an end-to-end directory transfer between two jobs of one server,
cancellation, and the file listing.
