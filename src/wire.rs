//! Byte layouts: connection preamble, encrypted control channel, data
//! connection hello, and data frames.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::crypto::{Cipher, CipherState, SessionKeys, TAG_LEN};
use crate::manifest::{ChunkId, END_FILE_ID, OfferFile};

pub const MAGIC: &[u8; 4] = b"GRYN";
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
    ensure!(&p[..4] == MAGIC, "not a gorynych connection");
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
    Finished,
    Error {
        message: String,
    },
    Cancel,
}

pub const MAX_CONTROL_LEN: usize = 64 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// Sending half of the control channel.
pub struct ControlTx {
    stream: TcpStream,
    cipher: CipherState,
}

/// Receiving half of the control channel.
pub struct ControlRx {
    reader: BufReader<TcpStream>,
    cipher: CipherState,
}

/// Splits a handshaken control connection into its two directions.
pub fn control_channel(
    stream: TcpStream,
    keys: &SessionKeys,
    role: Role,
) -> Result<(ControlTx, ControlRx)> {
    let (tx_key, rx_key) = match role {
        Role::Sender => (&keys.ctrl_s2r, &keys.ctrl_r2s),
        Role::Receiver => (&keys.ctrl_r2s, &keys.ctrl_s2r),
    };
    let reader = BufReader::new(stream.try_clone()?);
    Ok((
        ControlTx {
            stream,
            cipher: CipherState::new(Cipher::ChaCha20Poly1305, tx_key),
        },
        ControlRx {
            reader,
            cipher: CipherState::new(Cipher::ChaCha20Poly1305, rx_key),
        },
    ))
}

impl ControlTx {
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
        self.stream.write_all(&framed)?;
        Ok(())
    }
}

impl ControlRx {
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
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
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

/// Seals a frame in place. `frame` is laid out as
/// `[header space: 16][plaintext][tag space: 16]` and is exactly that long;
/// afterwards the whole slice is the wire frame.
pub fn seal_frame(
    cipher: &mut CipherState,
    session_id: &[u8; 16],
    header: FrameHeader,
    frame: &mut [u8],
) -> Result<()> {
    debug_assert_eq!(frame.len(), HEADER_LEN + header.ct_len as usize);
    let (h, body) = frame.split_at_mut(HEADER_LEN);
    let encoded = header.encode();
    h.copy_from_slice(&encoded);
    cipher.seal(&frame_aad(session_id, &encoded), body)
}

/// Opens a frame body (`ct_len` bytes) in place; the plaintext is
/// `body[..ct_len - 16]`.
pub fn open_frame(
    cipher: &mut CipherState,
    session_id: &[u8; 16],
    header: &[u8; HEADER_LEN],
    body: &mut [u8],
) -> Result<()> {
    cipher.open(&frame_aad(session_id, header), body)
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
        let mut tx = CipherState::new(cipher, &[7u8; 32]);
        let header = chunk_header(chunk, data.len() as u32);
        let mut frame = vec![0u8; HEADER_LEN + header.ct_len as usize];
        frame[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
        seal_frame(&mut tx, &SID, header, &mut frame).unwrap();
        frame
    }

    fn open(cipher: Cipher, frame: &[u8]) -> Result<Vec<u8>> {
        let mut rx = CipherState::new(cipher, &[7u8; 32]);
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let mut body = frame[HEADER_LEN..].to_vec();
        open_frame(&mut rx, &SID, &header, &mut body)?;
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
        let mut rx = CipherState::new(Cipher::Aes256Gcm, &[7u8; 32]);
        let header: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
        let mut body = frame[HEADER_LEN..].to_vec();
        assert!(open_frame(&mut rx, &[4u8; 16], &header, &mut body).is_err());
    }

    #[test]
    fn preamble_roundtrip_and_rejects() {
        let mut buf = Vec::new();
        write_preamble(&mut buf, ConnKind::Data).unwrap();
        assert_eq!(buf, b"GRYN\x01\x01");
        assert_eq!(read_preamble(&mut &buf[..]).unwrap(), ConnKind::Data);
        assert!(read_preamble(&mut &b"GRYN\x02\x00"[..]).is_err());
        assert!(read_preamble(&mut &b"HTTP/1"[..]).is_err());
    }

    #[test]
    fn control_message_tags_are_stable() {
        let tag = |m: &Msg| postcard::to_allocvec(m).unwrap()[0];
        assert_eq!(tag(&Msg::Have { bitmaps: vec![] }), 1);
        assert_eq!(tag(&Msg::RoundStart { round: 0 }), 2);
        assert_eq!(tag(&Msg::Finished), 4);
        assert_eq!(tag(&Msg::Cancel), 6);
    }
}
