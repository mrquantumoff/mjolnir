//! Byte layouts: connection preamble, encrypted control channel, data
//! connection hello, and data frames.

use std::io::{BufReader, Read, Write};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::crypto::{Cipher, CipherState, FrameKey, SessionKeys, TAG_LEN};
use crate::filemap::FileMap;
use crate::manifest::{ChunkId, END_FILE_ID, OfferFile};

pub const MAGIC: &[u8; 4] = b"MJLN";
pub const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnKind {
    Control = 0,
    Data = 1,
}

pub fn write_preamble(w: &mut impl Write, kind: ConnKind) -> Result<()> {
    let mut p = [0u8; 6];
    p[..4].copy_from_slice(MAGIC);
    p[4] = VERSION;
    p[5] = kind as u8;
    w.write_all(&p)?;
    Ok(())
}

pub fn read_preamble(r: &mut impl Read) -> Result<ConnKind> {
    let mut p = [0u8; 6];
    r.read_exact(&mut p)?;
    ensure!(&p[..4] == MAGIC, "not a mjolnir connection");
    ensure!(p[4] == VERSION, "unsupported protocol version {}", p[4]);
    match p[5] {
        0 => Ok(ConnKind::Control),
        1 => Ok(ConnKind::Data),
        k => bail!("unknown connection kind {k}"),
    }
}

/// Control messages. Variant order is the postcard tag; see PROTOCOL.md.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg {
    Offer {
        chunk_size: u32,
        cipher: Cipher,
        files: Vec<OfferFile>,
    },
    Have {
        bitmaps: Vec<Vec<u8>>,
    },
    RoundStart {
        round: u32,
    },
    RoundEnd {
        round: u32,
        connections: u32,
    },
    Delivered,
    Digests {
        file: u32,
        first: u64,
        /// Concatenated 16-byte chunk digests for chunks `first..`.
        #[serde(with = "serde_bytes")]
        digests: Vec<u8>,
    },
    Finalize {
        hash: bool,
        map: FileMap,
    },
    Finished {
        verified: bool,
        hashed: bool,
        warnings: Vec<String>,
    },
    Error {
        message: String,
    },
    Cancel,
    /// The receiver is reading chunks back; progress reporting only.
    Verifying,
}

pub const MAX_CONTROL_LEN: usize = 64 << 20;
/// A control message body is read at most this much at a time.
const READ_STEP: usize = 1 << 20;
/// Most digests one `Digests` message carries.
pub const DIGESTS_PER_MSG: usize = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// Sending half of the control channel.
pub struct ControlTx<W> {
    writer: W,
    cipher: CipherState,
}

/// Receiving half of the control channel.
pub struct ControlRx<R> {
    reader: BufReader<R>,
    cipher: CipherState,
}

/// Wraps the two directions of a handshaken control connection.
pub fn control_channel<R: Read, W: Write>(
    reader: R,
    writer: W,
    keys: &SessionKeys,
    role: Role,
) -> (ControlTx<W>, ControlRx<R>) {
    let (tx_key, rx_key) = match role {
        Role::Sender => (&keys.ctrl_s2r, &keys.ctrl_r2s),
        Role::Receiver => (&keys.ctrl_r2s, &keys.ctrl_s2r),
    };
    (
        ControlTx {
            writer,
            cipher: CipherState::new(Cipher::ChaCha20Poly1305, tx_key),
        },
        ControlRx {
            reader: BufReader::new(reader),
            cipher: CipherState::new(Cipher::ChaCha20Poly1305, rx_key),
        },
    )
}

impl<W: Write> ControlTx<W> {
    pub fn send(&mut self, msg: &Msg) -> Result<()> {
        let mut buf = postcard::to_allocvec(msg)?;
        buf.extend_from_slice(&[0u8; TAG_LEN]);
        ensure!(
            buf.len() <= MAX_CONTROL_LEN,
            "control message is {} bytes, over the 64 MiB limit",
            buf.len()
        );
        self.cipher.seal(b"", &mut buf)?;
        let mut framed = Vec::with_capacity(4 + buf.len());
        framed.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        framed.extend_from_slice(&buf);
        self.writer.write_all(&framed)?;
        Ok(())
    }
}

impl<R: Read> ControlRx<R> {
    /// The underlying reader; bytes already buffered are dropped.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Splits off the reader and the receive state, to continue the same
    /// stream with [`ControlRx::resume`]. Fails if bytes past the last
    /// message are already buffered, since they would be lost.
    pub fn into_parts(self) -> Result<(R, CipherState)> {
        ensure!(
            self.reader.buffer().is_empty(),
            "unexpected bytes after the control message"
        );
        Ok((self.reader.into_inner(), self.cipher))
    }

    /// Continues a stream split with [`ControlRx::into_parts`].
    pub fn resume(reader: R, cipher: CipherState) -> Self {
        ControlRx {
            reader: BufReader::new(reader),
            cipher,
        }
    }

    pub fn recv(&mut self) -> Result<Msg> {
        let mut len = [0u8; 4];
        self.reader
            .read_exact(&mut len)
            .context("control connection closed")?;
        let len = u32::from_be_bytes(len) as usize;
        ensure!(
            (TAG_LEN..=MAX_CONTROL_LEN).contains(&len),
            "bad control message length {len}"
        );
        // Grow the buffer as bytes arrive, so a peer that announces 64 MiB
        // and sends nothing commits no memory for it.
        let mut buf = Vec::new();
        while buf.len() < len {
            let filled = buf.len();
            buf.resize(len.min(filled + READ_STEP), 0);
            self.reader
                .read_exact(&mut buf[filled..])
                .context("control connection closed mid-message")?;
        }
        self.cipher
            .open(b"", &mut buf)
            .context("control message failed to authenticate")?;
        postcard::from_bytes(&buf[..len - TAG_LEN]).context("malformed control message")
    }
}

pub const CHALLENGE_LEN: usize = 32;
pub const HELLO_LEN: usize = 4 + 4 + 32;

/// The data connection hello: `round u32 | conn u32 | HMAC`.
pub fn encode_hello(keys: &SessionKeys, challenge: &[u8; 32], round: u32, conn: u32) -> [u8; 40] {
    let mut out = [0u8; HELLO_LEN];
    out[..4].copy_from_slice(&round.to_be_bytes());
    out[4..8].copy_from_slice(&conn.to_be_bytes());
    out[8..].copy_from_slice(&keys.hello_mac(challenge, round, conn));
    out
}

/// Returns `(round, conn)` if the MAC is valid for this challenge.
pub fn check_hello(
    keys: &SessionKeys,
    challenge: &[u8; 32],
    hello: &[u8; HELLO_LEN],
) -> Option<(u32, u32)> {
    let round = u32::from_be_bytes(hello[..4].try_into().unwrap());
    let conn = u32::from_be_bytes(hello[4..8].try_into().unwrap());
    keys.verify_hello(challenge, round, conn, &hello[8..])
        .then_some((round, conn))
}

pub const ADMITTED: u8 = 1;
pub const REJECTED: u8 = 0;

pub const HEADER_LEN: usize = 16;

/// Data frame header: `file_id u32 | chunk_index u64 | ct_len u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub file_id: u32,
    pub chunk_index: u64,
    pub ct_len: u32,
}

impl FrameHeader {
    pub fn end() -> Self {
        FrameHeader {
            file_id: END_FILE_ID,
            chunk_index: 0,
            ct_len: TAG_LEN as u32,
        }
    }

    pub fn is_end(&self) -> bool {
        self.file_id == END_FILE_ID
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..4].copy_from_slice(&self.file_id.to_be_bytes());
        h[4..12].copy_from_slice(&self.chunk_index.to_be_bytes());
        h[12..].copy_from_slice(&self.ct_len.to_be_bytes());
        h
    }

    pub fn decode(h: &[u8; HEADER_LEN]) -> Self {
        FrameHeader {
            file_id: u32::from_be_bytes(h[..4].try_into().unwrap()),
            chunk_index: u64::from_be_bytes(h[4..12].try_into().unwrap()),
            ct_len: u32::from_be_bytes(h[12..].try_into().unwrap()),
        }
    }
}

fn frame_aad(session_id: &[u8; 16], header: &[u8; HEADER_LEN]) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..16].copy_from_slice(session_id);
    aad[16..].copy_from_slice(header);
    aad
}

/// Seals a connection's frame number `k` in place. `frame` is laid out as
/// `[header space: 16][plaintext][tag space: 16]` and is exactly that long;
/// afterwards the whole slice is the wire frame.
pub fn seal_frame(
    key: &FrameKey,
    k: u64,
    session_id: &[u8; 16],
    header: FrameHeader,
    frame: &mut [u8],
) -> Result<()> {
    debug_assert_eq!(frame.len(), HEADER_LEN + header.ct_len as usize);
    let (h, body) = frame.split_at_mut(HEADER_LEN);
    let encoded = header.encode();
    h.copy_from_slice(&encoded);
    key.seal(k, &frame_aad(session_id, &encoded), body)
}

/// Opens the body (`ct_len` bytes) of a connection's frame number `k` in
/// place; the plaintext is `body[..ct_len - 16]`.
pub fn open_frame(
    key: &FrameKey,
    k: u64,
    session_id: &[u8; 16],
    header: &[u8; HEADER_LEN],
    body: &mut [u8],
) -> Result<()> {
    key.open(k, &frame_aad(session_id, header), body)
}

/// The header of the frame that carries `chunk`, `len` plaintext bytes long.
pub fn chunk_header(chunk: ChunkId, len: u32) -> FrameHeader {
    FrameHeader {
        file_id: chunk.file,
        chunk_index: chunk.index,
        ct_len: len + TAG_LEN as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: [u8; 16] = [3u8; 16];

    fn sealed(cipher: Cipher, chunk: ChunkId, data: &[u8]) -> Vec<u8> {
        let key = FrameKey::new(cipher, &[7u8; 32]);
        let header = chunk_header(chunk, data.len() as u32);
        let mut frame = vec![0u8; HEADER_LEN + header.ct_len as usize];
        frame[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
        seal_frame(&key, 0, &SID, header, &mut frame).unwrap();
        frame
    }

    fn open(cipher: Cipher, frame: &[u8]) -> Result<Vec<u8>> {
        let key = FrameKey::new(cipher, &[7u8; 32]);
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let mut body = frame[HEADER_LEN..].to_vec();
        open_frame(&key, 0, &SID, &header, &mut body)?;
        body.truncate(body.len() - TAG_LEN);
        Ok(body)
    }

    const CHUNK: ChunkId = ChunkId { file: 2, index: 5 };

    #[test]
    fn frame_roundtrip() {
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let frame = sealed(cipher, CHUNK, b"chunk bytes");
            assert_eq!(open(cipher, &frame).unwrap(), b"chunk bytes");
            let h = FrameHeader::decode(frame[..HEADER_LEN].try_into().unwrap());
            assert_eq!((h.file_id, h.chunk_index, h.ct_len), (2, 5, 11 + 16));
        }
    }

    #[test]
    fn frame_tamper_ciphertext_byte() {
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let mut frame = sealed(cipher, CHUNK, b"chunk bytes");
            frame[HEADER_LEN + 3] ^= 1;
            assert!(open(cipher, &frame).is_err());
            let mut frame = sealed(cipher, CHUNK, b"chunk bytes");
            *frame.last_mut().unwrap() ^= 0x80;
            assert!(open(cipher, &frame).is_err());
        }
    }

    #[test]
    fn frame_tamper_header_byte() {
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            for i in 0..HEADER_LEN {
                let mut frame = sealed(cipher, CHUNK, b"chunk bytes");
                frame[i] ^= 1;
                assert!(open(cipher, &frame).is_err(), "header byte {i}");
            }
        }
    }

    #[test]
    fn frame_swapped_chunk_index_fails() {
        let frame = sealed(Cipher::Aes256Gcm, CHUNK, b"chunk bytes");
        let mut moved = frame.clone();
        let mut h = FrameHeader::decode(moved[..HEADER_LEN].try_into().unwrap());
        h.chunk_index = 6;
        moved[..HEADER_LEN].copy_from_slice(&h.encode());
        assert!(open(Cipher::Aes256Gcm, &moved).is_err());
        let other = sealed(
            Cipher::Aes256Gcm,
            ChunkId { file: 2, index: 6 },
            b"chunk bytes",
        );
        let mut spliced = other[..HEADER_LEN].to_vec();
        spliced.extend_from_slice(&frame[HEADER_LEN..]);
        assert!(open(Cipher::Aes256Gcm, &spliced).is_err());
    }

    #[test]
    fn frame_from_other_session_fails() {
        let frame = sealed(Cipher::Aes256Gcm, CHUNK, b"chunk bytes");
        let key = FrameKey::new(Cipher::Aes256Gcm, &[7u8; 32]);
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let mut body = frame[HEADER_LEN..].to_vec();
        assert!(open_frame(&key, 0, &[4u8; 16], &header, &mut body).is_err());
    }

    #[test]
    fn preamble_roundtrip_and_rejects() {
        let mut buf = Vec::new();
        write_preamble(&mut buf, ConnKind::Data).unwrap();
        assert_eq!(buf, b"MJLN\x01\x01");
        assert_eq!(read_preamble(&mut &buf[..]).unwrap(), ConnKind::Data);
        assert!(read_preamble(&mut &b"MJLN\x02\x00"[..]).is_err());
        assert!(read_preamble(&mut &b"HTTP/1"[..]).is_err());
    }

    /// Feeds a fixed prefix, then reports how much the reader was asked for.
    struct Truncated {
        data: Vec<u8>,
        largest_read: usize,
    }

    impl Read for Truncated {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.largest_read = self.largest_read.max(buf.len());
            let n = buf.len().min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data.drain(..n);
            Ok(n)
        }
    }

    #[test]
    fn a_huge_announced_control_message_is_read_in_steps() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        let mut data = (MAX_CONTROL_LEN as u32).to_be_bytes().to_vec();
        data.extend_from_slice(&[0u8; 100]);
        let reader = Truncated {
            data,
            largest_read: 0,
        };
        let (_, mut rx) = control_channel(reader, Vec::new(), &keys, Role::Receiver);
        let err = rx.recv().unwrap_err();
        assert!(format!("{err:#}").contains("mid-message"), "{err:#}");
        assert!(rx.into_inner().largest_read <= READ_STEP + 16);
    }

    #[test]
    fn control_messages_round_trip_across_read_steps() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        let big = Msg::Have {
            bitmaps: vec![vec![0xA5; 3 * READ_STEP + 5]],
        };
        let (mut tx, _) = control_channel(&[][..], Vec::new(), &keys, Role::Sender);
        tx.send(&big).unwrap();
        let (_, mut rx) = control_channel(&tx.writer[..], Vec::new(), &keys, Role::Receiver);
        assert_eq!(rx.recv().unwrap(), big);
    }

    #[test]
    fn control_message_tags_are_stable() {
        let tag = |m: &Msg| postcard::to_allocvec(m).unwrap()[0];
        assert_eq!(tag(&Msg::Have { bitmaps: vec![] }), 1);
        assert_eq!(tag(&Msg::RoundStart { round: 0 }), 2);
        assert_eq!(tag(&Msg::Delivered), 4);
        assert_eq!(
            tag(&Msg::Finished {
                verified: true,
                hashed: false,
                warnings: vec![]
            }),
            7
        );
        assert_eq!(tag(&Msg::Cancel), 9);
        assert_eq!(tag(&Msg::Verifying), 10);
    }
}
