//! Tunnel byte layouts: the async Noise framing, the encrypted control
//! channel, the stream connection hello, and stream frames. The layouts are
//! specified in `docs/TUNNEL.md`.

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use zeroize::Zeroizing;

use crate::crypto::{Cipher, CipherState, SessionKeys, TAG_LEN};

/// The Noise prologue of a tunnel session. It differs from a transfer's, so
/// a handshake made for one can never open a session of the other.
pub const PROLOGUE: &[u8] = b"mjolnir tunnel v1";

/// Tunnel control messages. Variant order is the postcard tag.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelMsg {
    /// Client, first message: proves the client is live and picks the
    /// stream cipher.
    Hello {
        cipher: Cipher,
    },
    /// Server's answer to `Hello`.
    Welcome {
        max_conns: u32,
    },
    /// Client: connect to `host:port` for stream `stream` (`-L`).
    Open {
        stream: u32,
        host: String,
        port: u16,
        conns: u32,
    },
    /// Client: listen on `host:port` on the server (`-R`).
    Listen {
        id: u32,
        host: String,
        port: u16,
        conns: u32,
    },
    /// Server: listener `id` is bound to `addr`.
    Listening {
        id: u32,
        addr: String,
    },
    ListenFailed {
        id: u32,
        message: String,
    },
    /// Server: listener `listener` accepted a connection from `from`; it
    /// travels as stream `stream`.
    Incoming {
        listener: u32,
        stream: u32,
        from: String,
    },
    /// Either side: stream `stream` failed to start.
    Close {
        stream: u32,
        message: String,
    },
    /// Either side is ending the session because of this error.
    Error {
        message: String,
    },
}

/// Longest control message, sealed.
const MAX_CONTROL_LEN: usize = 64 << 10;

pub struct CtrlTx<W> {
    writer: W,
    cipher: CipherState,
}

pub struct CtrlRx<R> {
    reader: R,
    cipher: CipherState,
}

/// The keys of a handshaken control connection: the client sends under
/// `k_ctrl_s2r`, the server under `k_ctrl_r2s`.
fn control_keys(keys: &SessionKeys, client: bool) -> (&[u8; 32], &[u8; 32]) {
    if client {
        (&keys.ctrl_s2r, &keys.ctrl_r2s)
    } else {
        (&keys.ctrl_r2s, &keys.ctrl_s2r)
    }
}

/// Wraps a handshaken control connection.
pub fn control<R, W>(
    reader: R,
    writer: W,
    keys: &SessionKeys,
    client: bool,
) -> (CtrlTx<W>, CtrlRx<R>) {
    (
        CtrlTx::new(writer, keys, client),
        CtrlRx::new(reader, keys, client),
    )
}

/// The sealed length of `Hello`: its postcard tag, the cipher's tag, and
/// the AEAD tag.
pub const HELLO_MSG_LEN: usize = 2 + TAG_LEN;

impl<W> CtrlTx<W> {
    pub fn new(writer: W, keys: &SessionKeys, client: bool) -> Self {
        CtrlTx {
            writer,
            cipher: CipherState::new(Cipher::ChaCha20Poly1305, control_keys(keys, client).0),
        }
    }
}

impl<W: AsyncWrite + Unpin> CtrlTx<W> {
    pub async fn send(&mut self, msg: &TunnelMsg) -> Result<()> {
        let mut buf = vec![0u8; 4];
        postcard::to_io(msg, &mut buf)?;
        buf.extend_from_slice(&[0u8; TAG_LEN]);
        let len = buf.len() - 4;
        ensure!(len <= MAX_CONTROL_LEN, "control message is {len} bytes");
        buf[..4].copy_from_slice(&(len as u32).to_be_bytes());
        self.cipher.seal(b"", &mut buf[4..])?;
        self.writer.write_all(&buf).await?;
        Ok(())
    }
}

impl<R> CtrlRx<R> {
    pub fn new(reader: R, keys: &SessionKeys, client: bool) -> Self {
        CtrlRx {
            reader,
            cipher: CipherState::new(Cipher::ChaCha20Poly1305, control_keys(keys, client).1),
        }
    }

    /// Continues the same stream on another reader, say one with a buffer,
    /// keeping the receive state.
    pub fn with_reader<R2>(self, reader: impl FnOnce(R) -> R2) -> CtrlRx<R2> {
        CtrlRx {
            reader: reader(self.reader),
            cipher: self.cipher,
        }
    }
}

impl<R: AsyncRead + Unpin> CtrlRx<R> {
    /// Reads the `Hello` that opens a session. Its length is fixed, so a
    /// peer that only replayed Noise message 1, and so cannot seal
    /// anything, gets at most `HELLO_MSG_LEN` bytes of buffer before it is
    /// dropped, and never a message-sized allocation.
    pub async fn recv_hello(&mut self) -> Result<Cipher> {
        let mut len = [0u8; 4];
        self.reader
            .read_exact(&mut len)
            .await
            .context("closed before Hello")?;
        let len = u32::from_be_bytes(len) as usize;
        ensure!(len == HELLO_MSG_LEN, "bad Hello length {len}");
        let mut buf = [0u8; HELLO_MSG_LEN];
        self.reader
            .read_exact(&mut buf)
            .await
            .context("closed before Hello")?;
        self.cipher
            .open(b"", &mut buf)
            .context("Hello failed to authenticate")?;
        match postcard::from_bytes(&buf[..HELLO_MSG_LEN - TAG_LEN]).context("malformed Hello")? {
            TunnelMsg::Hello { cipher } => Ok(cipher),
            other => bail!("expected Hello, got {other:?}"),
        }
    }

    /// The next message, or `None` if the peer closed the connection
    /// between messages. Not cancellation safe: a message half read when the
    /// future is dropped is lost, and the stream with it.
    pub async fn recv(&mut self) -> Result<Option<TunnelMsg>> {
        let mut len = [0u8; 4];
        if self.reader.read(&mut len[..1]).await? == 0 {
            return Ok(None);
        }
        self.reader
            .read_exact(&mut len[1..])
            .await
            .context("control connection closed mid-message")?;
        let len = u32::from_be_bytes(len) as usize;
        ensure!(
            (TAG_LEN..=MAX_CONTROL_LEN).contains(&len),
            "bad control message length {len}"
        );
        let mut buf = vec![0u8; len];
        self.reader
            .read_exact(&mut buf)
            .await
            .context("control connection closed mid-message")?;
        self.cipher
            .open(b"", &mut buf)
            .context("control message failed to authenticate")?;
        postcard::from_bytes(&buf[..len - TAG_LEN])
            .map(Some)
            .context("malformed control message")
    }
}

pub async fn write_noise(w: &mut (impl AsyncWrite + Unpin), msg: &[u8]) -> Result<()> {
    let len = u16::try_from(msg.len()).expect("Noise messages fit in u16");
    let mut buf = len.to_be_bytes().to_vec();
    buf.extend_from_slice(msg);
    w.write_all(&buf).await?;
    Ok(())
}

pub async fn read_noise(r: &mut (impl AsyncRead + Unpin), max: usize) -> Result<Vec<u8>> {
    let len = usize::from(r.read_u16().await?);
    ensure!(len <= max, "Noise message of {len} bytes is too long");
    let mut msg = vec![0u8; len];
    r.read_exact(&mut msg).await?;
    Ok(msg)
}

/// Which way a stream key seals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    ClientToServer = 0,
    ServerToClient = 1,
}

/// `route = E("tunnel route")[..16]`: names the session in stream hellos.
pub fn route(keys: &SessionKeys) -> [u8; 16] {
    keys.expand(b"tunnel route")[..16].try_into().unwrap()
}

/// `k_stream(s, i, d) = E("tunnel" | s u32 | i u32 | d u8)`.
pub fn stream_key(keys: &SessionKeys, stream: u32, conn: u32, dir: Dir) -> Zeroizing<[u8; 32]> {
    let mut info = [0u8; 15];
    info[..6].copy_from_slice(b"tunnel");
    info[6..10].copy_from_slice(&stream.to_be_bytes());
    info[10..14].copy_from_slice(&conn.to_be_bytes());
    info[14] = dir as u8;
    keys.expand(&info)
}

pub const CHALLENGE_LEN: usize = 32;
pub const HELLO_LEN: usize = 16 + 4 + 4 + 32;
pub const ADMITTED: u8 = 1;

/// A stream connection's hello: `route | stream u32 | conn u32 | HMAC`.
pub fn encode_hello(
    keys: &SessionKeys,
    route: &[u8; 16],
    challenge: &[u8; CHALLENGE_LEN],
    stream: u32,
    conn: u32,
) -> [u8; HELLO_LEN] {
    let mut out = [0u8; HELLO_LEN];
    out[..16].copy_from_slice(route);
    out[16..20].copy_from_slice(&stream.to_be_bytes());
    out[20..24].copy_from_slice(&conn.to_be_bytes());
    out[24..].copy_from_slice(&keys.hello_mac(challenge, stream, conn));
    out
}

/// Splits a hello into `(route, stream, conn, mac)`; the caller finds the
/// session by route and checks the MAC with [`check_hello`].
pub fn decode_hello(hello: &[u8; HELLO_LEN]) -> ([u8; 16], u32, u32, [u8; 32]) {
    (
        hello[..16].try_into().unwrap(),
        u32::from_be_bytes(hello[16..20].try_into().unwrap()),
        u32::from_be_bytes(hello[20..24].try_into().unwrap()),
        hello[24..].try_into().unwrap(),
    )
}

pub fn check_hello(
    keys: &SessionKeys,
    challenge: &[u8; CHALLENGE_LEN],
    stream: u32,
    conn: u32,
    mac: &[u8; 32],
) -> bool {
    keys.verify_hello(challenge, stream, conn, mac)
}

pub const FRAME_HEADER_LEN: usize = 16;
/// Most plaintext bytes in one stream frame.
pub const FRAME_MAX: usize = 64 << 10;

/// What a stream frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Data = 0,
    /// The sender's end of the stream; an empty body.
    Fin = 1,
}

/// Stream frame header: `seq u64 | kind u32 | ct_len u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub seq: u64,
    pub kind: FrameKind,
    pub ct_len: u32,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut h = [0u8; FRAME_HEADER_LEN];
        h[..8].copy_from_slice(&self.seq.to_be_bytes());
        h[8..12].copy_from_slice(&(self.kind as u32).to_be_bytes());
        h[12..].copy_from_slice(&self.ct_len.to_be_bytes());
        h
    }

    /// Parses and bounds-checks a header before its body is read.
    pub fn decode(h: &[u8; FRAME_HEADER_LEN]) -> Result<Self> {
        let seq = u64::from_be_bytes(h[..8].try_into().unwrap());
        let kind = match u32::from_be_bytes(h[8..12].try_into().unwrap()) {
            0 => FrameKind::Data,
            1 => FrameKind::Fin,
            k => return Err(anyhow!("unknown stream frame kind {k}")),
        };
        let ct_len = u32::from_be_bytes(h[12..].try_into().unwrap());
        let plain = (ct_len as usize).checked_sub(TAG_LEN);
        match (kind, plain) {
            (FrameKind::Data, Some(1..=FRAME_MAX)) | (FrameKind::Fin, Some(0)) => {}
            _ => return Err(anyhow!("bad {kind:?} frame length {ct_len}")),
        }
        Ok(FrameHeader { seq, kind, ct_len })
    }
}

/// `session_id | header`: binds a frame to its session and its header.
pub fn frame_aad(session_id: &[u8; 16], header: &[u8; FRAME_HEADER_LEN]) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..16].copy_from_slice(session_id);
    aad[16..].copy_from_slice(header);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_messages_round_trip() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut tx, _) = control(tokio::io::empty(), Vec::new(), &keys, true);
            let msgs = [
                TunnelMsg::Hello {
                    cipher: Cipher::ChaCha20Poly1305,
                },
                TunnelMsg::Open {
                    stream: 7,
                    host: "db".into(),
                    port: 5432,
                    conns: 4,
                },
                TunnelMsg::Close {
                    stream: 7,
                    message: "no".into(),
                },
            ];
            for m in &msgs {
                tx.send(m).await.unwrap();
            }
            let wire = tx.writer.clone();
            let (_, mut rx) = control(&wire[..], tokio::io::sink(), &keys, false);
            for m in &msgs {
                assert_eq!(rx.recv().await.unwrap().as_ref(), Some(m));
            }
            assert_eq!(rx.recv().await.unwrap(), None);
            let (_, mut cut) = control(&wire[..wire.len() - 1], tokio::io::sink(), &keys, false);
            for _ in 0..msgs.len() - 1 {
                cut.recv().await.unwrap();
            }
            assert!(cut.recv().await.is_err());
            // The client's own receive key is the other direction.
            let (_, mut wrong) = control(&wire[..], tokio::io::sink(), &keys, true);
            assert!(wrong.recv().await.is_err());
        });
    }

    #[test]
    fn hello_seals_to_its_fixed_length_for_every_cipher() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
                let mut tx = CtrlTx::new(Vec::new(), &keys, true);
                tx.send(&TunnelMsg::Hello { cipher }).await.unwrap();
                assert_eq!(tx.writer.len(), 4 + HELLO_MSG_LEN);
                let mut rx = CtrlRx::new(&tx.writer[..], &keys, false);
                assert_eq!(rx.recv_hello().await.unwrap(), cipher);
            }
            let mut tx = CtrlTx::new(Vec::new(), &keys, true);
            tx.send(&TunnelMsg::Welcome { max_conns: 1 }).await.unwrap();
            let mut rx = CtrlRx::new(&tx.writer[..], &keys, false);
            assert!(rx.recv_hello().await.is_err());
            let mut tx = CtrlTx::new(Vec::new(), &keys, true);
            tx.send(&TunnelMsg::Close {
                stream: 1,
                message: String::new(),
            })
            .await
            .unwrap();
            let mut rx = CtrlRx::new(&tx.writer[..], &keys, false);
            let err = rx.recv_hello().await.unwrap_err().to_string();
            assert!(err.contains("bad Hello length"), "{err}");
        });
    }

    #[test]
    fn control_message_tags_are_stable() {
        let tag = |m: &TunnelMsg| postcard::to_allocvec(m).unwrap()[0];
        assert_eq!(
            tag(&TunnelMsg::Hello {
                cipher: Cipher::Aes256Gcm
            }),
            0
        );
        assert_eq!(tag(&TunnelMsg::Welcome { max_conns: 1 }), 1);
        assert_eq!(
            tag(&TunnelMsg::Incoming {
                listener: 0,
                stream: 0,
                from: String::new()
            }),
            6
        );
        assert_eq!(
            tag(&TunnelMsg::Error {
                message: String::new()
            }),
            8
        );
    }

    #[test]
    fn frame_header_bounds() {
        let data = FrameHeader {
            seq: 9,
            kind: FrameKind::Data,
            ct_len: (FRAME_MAX + TAG_LEN) as u32,
        };
        assert_eq!(FrameHeader::decode(&data.encode()).unwrap(), data);
        let fin = FrameHeader {
            seq: 10,
            kind: FrameKind::Fin,
            ct_len: TAG_LEN as u32,
        };
        assert_eq!(FrameHeader::decode(&fin.encode()).unwrap(), fin);
        for bad in [
            FrameHeader {
                ct_len: data.ct_len + 1,
                ..data
            },
            FrameHeader {
                ct_len: TAG_LEN as u32,
                ..data
            },
            FrameHeader { ct_len: 3, ..data },
            FrameHeader {
                ct_len: TAG_LEN as u32 + 1,
                ..fin
            },
        ] {
            assert!(FrameHeader::decode(&bad.encode()).is_err(), "{bad:?}");
        }
        let mut unknown = fin.encode();
        unknown[11] = 2;
        assert!(FrameHeader::decode(&unknown).is_err());
    }

    #[test]
    fn stream_keys_are_distinct_and_hellos_bind_their_fields() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        let k = |s, i, d| stream_key(&keys, s, i, d);
        assert_ne!(k(1, 0, Dir::ClientToServer), k(1, 0, Dir::ServerToClient));
        assert_ne!(k(1, 0, Dir::ClientToServer), k(0, 1, Dir::ClientToServer));
        assert_ne!(route(&keys)[..], keys.session_id[..]);
        let challenge = [4u8; CHALLENGE_LEN];
        let hello = encode_hello(&keys, &route(&keys), &challenge, 5, 2);
        let (r, s, i, mac) = decode_hello(&hello);
        assert_eq!((r, s, i), (route(&keys), 5, 2));
        assert!(check_hello(&keys, &challenge, 5, 2, &mac));
        assert!(!check_hello(&keys, &challenge, 5, 3, &mac));
        assert!(!check_hello(&keys, &[5u8; CHALLENGE_LEN], 5, 2, &mac));
    }
}
