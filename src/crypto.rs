//! Noise IK handshake, the key schedule, and the AEAD wrapper used for both
//! control messages and data chunks.

use std::io::{Read, Write};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{PrivateKey, PublicKey};

const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"mjolnir v1";
const NOISE_MAX: usize = 65535;
/// IK message 1 with an empty payload: `e` (32), encrypted `s` (32 + 16),
/// and the empty payload's tag (16).
const IK_MSG1_LEN: usize = 96;

pub const TAG_LEN: usize = 16;
/// Bytes of BLAKE3 kept per chunk.
pub const DIGEST_LEN: usize = 16;

/// A chunk's digest: BLAKE3 of its plaintext, truncated to 16 bytes.
pub fn chunk_digest(plaintext: &[u8]) -> [u8; DIGEST_LEN] {
    blake3::hash(plaintext).as_bytes()[..DIGEST_LEN]
        .try_into()
        .unwrap()
}

/// Builds a file's `file_hash = BLAKE3(chunk_size u32 | chunk digests)`.
pub struct FileHasher(blake3::Hasher);

impl FileHasher {
    pub fn new(chunk_size: u32) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(&chunk_size.to_be_bytes());
        FileHasher(h)
    }

    /// Feeds digests in chunk order.
    pub fn update(&mut self, digests: &[u8]) {
        self.0.update(digests);
    }

    pub fn hex(&self) -> String {
        self.0.finalize().to_hex().to_string()
    }
}

/// The message the sender shows when the receiver closed during the handshake.
pub const REJECTED: &str = "the receiver rejected the handshake (this sender's key is not authorized, \
     or --peer is not the receiver's public key)";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Cipher {
    #[default]
    #[value(name = "aes256gcm")]
    Aes256Gcm,
    #[value(name = "chacha20poly1305")]
    ChaCha20Poly1305,
}

enum AnyAead {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// An AEAD key whose nonce for message `counter` is `0u32 | counter u64`.
/// It holds no state, so one key can seal or open many messages of a
/// stream at once, in any order, from many threads.
pub struct FrameKey(AnyAead);

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

impl FrameKey {
    pub fn new(cipher: Cipher, key: &[u8; 32]) -> Self {
        FrameKey(match cipher {
            Cipher::Aes256Gcm => AnyAead::Aes(Box::new(Aes256Gcm::new(key.into()))),
            Cipher::ChaCha20Poly1305 => {
                AnyAead::ChaCha(Box::new(ChaCha20Poly1305::new(key.into())))
            }
        })
    }

    /// `buf` is plaintext followed by `TAG_LEN` spare bytes. Encrypts in
    /// place as message `counter` and writes the tag into the spare bytes.
    pub fn seal(&self, counter: u64, aad: &[u8], buf: &mut [u8]) -> Result<()> {
        let nonce = nonce(counter);
        let (body, tag_out) = buf.split_at_mut(buf.len() - TAG_LEN);
        let tag = match &self.0 {
            AnyAead::Aes(a) => a.encrypt_in_place_detached(&nonce.into(), aad, body),
            AnyAead::ChaCha(a) => a.encrypt_in_place_detached(&nonce.into(), aad, body),
        }
        .map_err(|_| anyhow!("encryption failed"))?;
        tag_out.copy_from_slice(&tag);
        Ok(())
    }

    /// `buf` is ciphertext followed by the tag of message `counter`. On
    /// success the plaintext is `buf[..buf.len() - TAG_LEN]`.
    pub fn open(&self, counter: u64, aad: &[u8], buf: &mut [u8]) -> Result<()> {
        ensure!(buf.len() >= TAG_LEN, "ciphertext shorter than the tag");
        let nonce = nonce(counter);
        let (body, tag) = buf.split_at_mut(buf.len() - TAG_LEN);
        let tag = (&*tag).into();
        match &self.0 {
            AnyAead::Aes(a) => a.decrypt_in_place_detached(&nonce.into(), aad, body, tag),
            AnyAead::ChaCha(a) => a.decrypt_in_place_detached(&nonce.into(), aad, body, tag),
        }
        .map_err(|_| anyhow!("authentication failed"))
    }
}

/// One direction of an in-order AEAD stream: a key and a counter that starts
/// at 0 and increments per message.
pub struct CipherState {
    key: FrameKey,
    counter: u64,
}

impl CipherState {
    pub fn new(cipher: Cipher, key: &[u8; 32]) -> Self {
        CipherState {
            key: FrameKey::new(cipher, key),
            counter: 0,
        }
    }

    fn next(&mut self) -> u64 {
        let counter = self.counter;
        self.counter = counter.checked_add(1).expect("nonce counter exhausted");
        counter
    }

    pub fn seal(&mut self, aad: &[u8], buf: &mut [u8]) -> Result<()> {
        let counter = self.next();
        self.key.seal(counter, aad, buf)
    }

    pub fn open(&mut self, aad: &[u8], buf: &mut [u8]) -> Result<()> {
        let counter = self.next();
        self.key.open(counter, aad, buf)
    }
}

/// Everything both peers derive from `master` and the handshake hash. The
/// keys are zeroed when it is dropped.
pub struct SessionKeys {
    pub ctrl_s2r: [u8; 32],
    pub ctrl_r2s: [u8; 32],
    pub hello: [u8; 32],
    pub session_id: [u8; 16],
    /// HKDF-Extract output, kept as bytes so it can be zeroed.
    prk: [u8; 32],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.ctrl_s2r.zeroize();
        self.ctrl_r2s.zeroize();
        self.hello.zeroize();
        self.prk.zeroize();
    }
}

impl SessionKeys {
    pub fn derive(handshake_hash: &[u8], master: &[u8; 32]) -> Self {
        let (mut prk, _) = Hkdf::<Sha256>::extract(Some(handshake_hash), master);
        let mut keys = SessionKeys {
            ctrl_s2r: [0; 32],
            ctrl_r2s: [0; 32],
            hello: [0; 32],
            session_id: [0; 16],
            prk: prk.into(),
        };
        prk.as_mut_slice().zeroize();
        keys.ctrl_s2r = *keys.okm(b"ctrl s2r");
        keys.ctrl_r2s = *keys.okm(b"ctrl r2s");
        keys.hello = *keys.okm(b"hello");
        let sid = keys.okm(b"session id");
        keys.session_id.copy_from_slice(&sid[..16]);
        keys
    }

    fn okm(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut okm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::from_prk(&self.prk)
            .expect("the PRK is one hash long")
            .expand(info, &mut *okm)
            .expect("32 bytes is a valid HKDF length");
        okm
    }

    /// `k_data(round, conn) = E("data" | round u32 | conn u32)`.
    pub fn data_key(&self, round: u32, conn: u32) -> Zeroizing<[u8; 32]> {
        let mut info = [0u8; 12];
        info[..4].copy_from_slice(b"data");
        info[4..8].copy_from_slice(&round.to_be_bytes());
        info[8..].copy_from_slice(&conn.to_be_bytes());
        self.okm(&info)
    }

    fn hello_hmac(&self, challenge: &[u8; 32], round: u32, conn: u32) -> Hmac<Sha256> {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.hello).expect("any key length works");
        mac.update(challenge);
        mac.update(&round.to_be_bytes());
        mac.update(&conn.to_be_bytes());
        mac
    }

    pub fn hello_mac(&self, challenge: &[u8; 32], round: u32, conn: u32) -> [u8; 32] {
        self.hello_hmac(challenge, round, conn)
            .finalize()
            .into_bytes()
            .into()
    }

    /// Constant-time check of a data connection's hello MAC.
    pub fn verify_hello(&self, challenge: &[u8; 32], round: u32, conn: u32, mac: &[u8]) -> bool {
        self.hello_hmac(challenge, round, conn)
            .verify_slice(mac)
            .is_ok()
    }
}

fn builder() -> snow::Builder<'static> {
    snow::Builder::new(NOISE_PARAMS.parse().expect("valid Noise params"))
}

fn write_noise(w: &mut impl Write, msg: &[u8]) -> Result<()> {
    let len = u16::try_from(msg.len()).expect("Noise messages fit in u16");
    w.write_all(&len.to_be_bytes())?;
    w.write_all(msg)?;
    w.flush()?;
    Ok(())
}

fn read_noise(r: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let len = usize::from(u16::from_be_bytes(len));
    ensure!(len <= max, "Noise message of {len} bytes is too long");
    let mut msg = vec![0u8; len];
    r.read_exact(&mut msg)?;
    Ok(msg)
}

/// Sender side. Returns the session keys once the receiver has proven it
/// holds `remote`'s private key.
pub fn handshake_initiator(
    stream: &mut (impl Read + Write),
    local: &PrivateKey,
    remote: &PublicKey,
) -> Result<SessionKeys> {
    let mut hs = builder()
        .local_private_key(local.as_bytes())?
        .remote_public_key(&remote.0)?
        .prologue(PROLOGUE)?
        .build_initiator()?;
    // Message 2's payload, the master secret, is decrypted into `buf`.
    let mut buf = Zeroizing::new(vec![0u8; NOISE_MAX]);
    let n = hs.write_message(&[], &mut buf)?;
    write_noise(stream, &buf[..n]).context("sending Noise message 1")?;
    let msg = read_noise(stream, NOISE_MAX).map_err(|_| anyhow!(REJECTED))?;
    let n = hs
        .read_message(&msg, &mut buf)
        .context("Noise message 2 did not authenticate")?;
    ensure!(n == 32, "Noise message 2 payload is {n} bytes, expected 32");
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&buf[..32]);
    Ok(SessionKeys::derive(hs.get_handshake_hash(), &master))
}

/// Receiver side. Reads message 1, checks the sender's static key against
/// `authorized`, and only then replies. On rejection nothing is sent.
pub fn handshake_responder(
    stream: &mut (impl Read + Write),
    local: &PrivateKey,
    authorized: &[PublicKey],
) -> Result<(SessionKeys, PublicKey)> {
    let mut hs = builder()
        .local_private_key(local.as_bytes())?
        .prologue(PROLOGUE)?
        .build_responder()?;
    let msg = read_noise(stream, IK_MSG1_LEN).context("reading Noise message 1")?;
    let mut buf = vec![0u8; NOISE_MAX];
    let n = hs.read_message(&msg, &mut buf).map_err(|_| {
        anyhow!(
            "Noise message 1 did not decrypt: the sender did not pin this receiver's public key"
        )
    })?;
    let remote = hs
        .get_remote_static()
        .context("Noise message 1 carried no static key")?;
    let peer = PublicKey(remote.try_into()?);
    if !authorized.contains(&peer) {
        bail!("sender key {peer} is not authorized");
    }
    ensure!(n == 0, "Noise message 1 payload must be empty");
    let mut master = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *master).map_err(|e| anyhow!("OS random number generator: {e}"))?;
    let n = hs.write_message(&*master, &mut buf)?;
    write_noise(stream, &buf[..n]).context("sending Noise message 2")?;
    Ok((SessionKeys::derive(hs.get_handshake_hash(), &master), peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    type Responder = Result<(SessionKeys, PublicKey)>;

    fn run_handshake(
        sender: PrivateKey,
        pinned: PublicKey,
        receiver: PrivateKey,
        authorized: Vec<PublicKey>,
    ) -> (Result<SessionKeys>, Responder) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            handshake_responder(&mut s, &receiver, &authorized)
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let client = handshake_initiator(&mut c, &sender, &pinned);
        (client, server.join().unwrap())
    }

    #[test]
    fn handshake_agrees_on_keys() {
        let (s, r) = (PrivateKey::generate(), PrivateKey::generate());
        let (spub, rpub) = (s.public_key(), r.public_key());
        let (client, server) = run_handshake(s, rpub, r, vec![spub]);
        let (client, (server, peer)) = (client.unwrap(), server.unwrap());
        assert_eq!(peer, spub);
        assert_eq!(client.ctrl_s2r, server.ctrl_s2r);
        assert_eq!(client.ctrl_r2s, server.ctrl_r2s);
        assert_eq!(client.hello, server.hello);
        assert_eq!(client.session_id, server.session_id);
        assert_eq!(client.data_key(3, 7), server.data_key(3, 7));
        assert_ne!(client.ctrl_s2r, client.ctrl_r2s);
        assert_ne!(client.data_key(0, 1), client.data_key(1, 0));
    }

    #[test]
    fn unauthorized_sender_is_named() {
        let (s, r) = (PrivateKey::generate(), PrivateKey::generate());
        let spub = s.public_key();
        let rpub = r.public_key();
        let other = PrivateKey::generate().public_key();
        let (client, server) = run_handshake(s, rpub, r, vec![other]);
        assert_eq!(client.err().unwrap().to_string(), REJECTED);
        let err = server.err().unwrap().to_string();
        assert!(err.contains(&spub.to_string()), "{err}");
    }

    #[test]
    fn wrong_pinned_key_fails_to_decrypt() {
        let (s, r) = (PrivateKey::generate(), PrivateKey::generate());
        let spub = s.public_key();
        let wrong = PrivateKey::generate().public_key();
        let (client, server) = run_handshake(s, wrong, r, vec![spub]);
        assert_eq!(client.err().unwrap().to_string(), REJECTED);
        assert!(
            server
                .err()
                .unwrap()
                .to_string()
                .contains("did not decrypt")
        );
    }

    /// The schedule must stay `HKDF(salt = handshake hash, ikm = master)`
    /// expanded per label, or peers on different builds disagree.
    #[test]
    fn derive_matches_one_shot_hkdf() {
        let (hh, master) = ([1u8; 32], [2u8; 32]);
        let keys = SessionKeys::derive(&hh, &master);
        let hkdf = Hkdf::<Sha256>::new(Some(&hh), &master);
        let expand = |info: &[u8]| {
            let mut okm = [0u8; 32];
            hkdf.expand(info, &mut okm).unwrap();
            okm
        };
        assert_eq!(keys.ctrl_s2r, expand(b"ctrl s2r"));
        assert_eq!(keys.ctrl_r2s, expand(b"ctrl r2s"));
        assert_eq!(keys.hello, expand(b"hello"));
        assert_eq!(keys.session_id, expand(b"session id")[..16]);
        let mut info = *b"data\0\0\0\x03\0\0\0\x07";
        assert_eq!(*keys.data_key(3, 7), expand(&info));
        info[7] = 4;
        assert_ne!(*keys.data_key(3, 7), expand(&info));
    }

    #[test]
    fn hello_mac_binds_challenge_round_and_conn() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        let ch = [9u8; 32];
        let mac = keys.hello_mac(&ch, 1, 2);
        assert!(keys.verify_hello(&ch, 1, 2, &mac));
        assert!(!keys.verify_hello(&ch, 1, 3, &mac));
        assert!(!keys.verify_hello(&ch, 2, 2, &mac));
        assert!(!keys.verify_hello(&[8u8; 32], 1, 2, &mac));
    }

    #[test]
    fn seal_open_roundtrip_both_ciphers() {
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let key = [5u8; 32];
            let (mut tx, mut rx) = (
                CipherState::new(cipher, &key),
                CipherState::new(cipher, &key),
            );
            for msg in [&b"first"[..], b"", b"third message"] {
                let mut buf = msg.to_vec();
                buf.extend_from_slice(&[0; TAG_LEN]);
                tx.seal(b"aad", &mut buf).unwrap();
                rx.open(b"aad", &mut buf).unwrap();
                assert_eq!(&buf[..msg.len()], msg);
            }
        }
    }

    #[test]
    fn frame_k_does_not_open_as_k_plus_one() {
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let key = FrameKey::new(cipher, &[6u8; 32]);
            let mut buf = vec![3u8; 100 + TAG_LEN];
            key.seal(41, b"aad", &mut buf).unwrap();
            let mut wrong = buf.clone();
            assert!(key.open(42, b"aad", &mut wrong).is_err());
            assert!(key.open(40, b"aad", &mut buf.clone()).is_err());
            key.open(41, b"aad", &mut buf).unwrap();
            assert_eq!(&buf[..100], &[3u8; 100][..]);
        }
    }

    #[test]
    fn open_rejects_out_of_order_nonce() {
        let key = [5u8; 32];
        let mut tx = CipherState::new(Cipher::Aes256Gcm, &key);
        let mut rx = CipherState::new(Cipher::Aes256Gcm, &key);
        let mut a = vec![0u8; 4 + TAG_LEN];
        let mut b = vec![1u8; 4 + TAG_LEN];
        tx.seal(b"", &mut a).unwrap();
        tx.seal(b"", &mut b).unwrap();
        assert!(rx.open(b"", &mut b).is_err());
    }
}
