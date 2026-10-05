//! The primitives snow runs `Noise_IK_25519_ChaChaPoly_SHA256` with. snow's
//! own resolver frees the static and ephemeral private keys, the handshake
//! cipher keys, and its HMAC buffers without wiping them; these wipe every
//! one when dropped.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::{Digest, Sha256};
use snow::Error;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::CryptoResolver;
use snow::types::{Cipher, Dh, Hash, Random};
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HASH_LEN: usize = 32;
const BLOCK_LEN: usize = 64;

/// Resolves only the primitives in `NOISE_PARAMS`.
pub struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(OsRng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::<X25519>::default()),
            _ => None,
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match choice {
            HashChoice::SHA256 => Some(Box::<Sha256Hash>::default()),
            _ => None,
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match choice {
            CipherChoice::ChaChaPoly => Some(Box::<ChaChaPoly>::default()),
            _ => None,
        }
    }
}

struct OsRng;

impl Random for OsRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(dest).map_err(|_| Error::Rng)
    }
}

#[derive(Default)]
struct X25519 {
    private: Zeroizing<[u8; KEY_LEN]>,
    public: [u8; KEY_LEN],
}

impl X25519 {
    fn derive_public(&mut self) {
        self.public = MontgomeryPoint::mul_base_clamped(*self.private).to_bytes();
    }
}

impl Dh for X25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        KEY_LEN
    }

    fn priv_len(&self) -> usize {
        KEY_LEN
    }

    fn set(&mut self, privkey: &[u8]) {
        self.private.copy_from_slice(&privkey[..KEY_LEN]);
        self.derive_public();
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error> {
        rng.try_fill_bytes(&mut *self.private)?;
        self.derive_public();
        Ok(())
    }

    fn pubkey(&self) -> &[u8] {
        &self.public
    }

    fn privkey(&self) -> &[u8] {
        &*self.private
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let mut point = MontgomeryPoint([0; KEY_LEN]);
        point.0.copy_from_slice(&pubkey[..KEY_LEN]);
        let shared = Zeroizing::new(point.mul_clamped(*self.private).to_bytes());
        out[..KEY_LEN].copy_from_slice(&*shared);
        Ok(())
    }
}

/// `ChaCha20Poly1305` wipes its key when dropped, so replacing it on `set`
/// wipes the previous key too.
struct ChaChaPoly(ChaCha20Poly1305);

impl Default for ChaChaPoly {
    fn default() -> Self {
        ChaChaPoly(ChaCha20Poly1305::new(&[0; KEY_LEN].into()))
    }
}

/// Noise's nonce: 32 zero bits, then the counter little-endian.
fn noise_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

impl Cipher for ChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; KEY_LEN]) {
        self.0 = ChaCha20Poly1305::new(key.into());
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let (body, rest) = out.split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        let tag = self
            .0
            .encrypt_in_place_detached(&noise_nonce(nonce).into(), authtext, body)
            .expect("Noise messages are far below ChaCha20's length limit");
        rest[..TAG_LEN].copy_from_slice(&tag);
        plaintext.len() + TAG_LEN
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let len = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::Decrypt)?;
        let (body, tag) = ciphertext.split_at(len);
        out[..len].copy_from_slice(body);
        self.0
            .decrypt_in_place_detached(
                &noise_nonce(nonce).into(),
                authtext,
                &mut out[..len],
                tag.into(),
            )
            .map_err(|_| Error::Decrypt)?;
        Ok(len)
    }
}

/// SHA-256 whose HMAC and HKDF keep their key-derived buffers in
/// `Zeroizing`, and whose hasher, which has absorbed those buffers, is
/// wiped on reset and drop.
#[derive(Default)]
struct Sha256Hash(Sha256);

impl Sha256Hash {
    /// Leaves an all-zero hasher, which must be replaced before it is used.
    fn wipe(&mut self) {
        // sha2 0.10's hasher has no Zeroize, and a fresh hasher assigned
        // over it is a plain store the compiler may drop as dead.
        // zeroize_flat_type writes every byte, padding included, with
        // volatile stores. It requires plain data with no Drop, which the
        // hasher is.
        unsafe { zeroize::zeroize_flat_type(&mut self.0) }
    }
}

impl Drop for Sha256Hash {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Hash for Sha256Hash {
    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn block_len(&self) -> usize {
        BLOCK_LEN
    }

    fn hash_len(&self) -> usize {
        HASH_LEN
    }

    fn reset(&mut self) {
        self.wipe();
        self.0 = Sha256::default();
    }

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.0.finalize_into_reset((&mut out[..HASH_LEN]).into());
    }

    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= BLOCK_LEN, "HMAC key longer than a block");
        let mut ipad = Zeroizing::new([0x36u8; BLOCK_LEN]);
        let mut opad = Zeroizing::new([0x5cu8; BLOCK_LEN]);
        for (i, k) in key.iter().enumerate() {
            ipad[i] ^= k;
            opad[i] ^= k;
        }
        let mut inner = Zeroizing::new([0u8; HASH_LEN]);
        self.reset();
        self.input(&*ipad);
        self.input(data);
        self.result(&mut *inner);
        self.reset();
        self.input(&*opad);
        self.input(&*inner);
        self.result(out);
    }

    fn hkdf(
        &mut self,
        chaining_key: &[u8],
        input_key_material: &[u8],
        outputs: usize,
        out1: &mut [u8],
        out2: &mut [u8],
        out3: &mut [u8],
    ) {
        let mut temp_key = Zeroizing::new([0u8; HASH_LEN]);
        self.hmac(chaining_key, input_key_material, &mut *temp_key);
        self.hmac(&*temp_key, &[1], out1);
        if outputs == 1 {
            return;
        }
        let mut input = Zeroizing::new([0u8; HASH_LEN + 1]);
        input[..HASH_LEN].copy_from_slice(&out1[..HASH_LEN]);
        input[HASH_LEN] = 2;
        self.hmac(&*temp_key, &*input, out2);
        if outputs == 2 {
            return;
        }
        input[..HASH_LEN].copy_from_slice(&out2[..HASH_LEN]);
        input[HASH_LEN] = 3;
        self.hmac(&*temp_key, &*input, out3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use snow::resolvers::{BoxedCryptoResolver, DefaultResolver};
    use std::mem::MaybeUninit;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The bytes `value` leaves where it lay once dropped.
    ///
    /// # Safety
    /// Every byte of `T` must be initialized after its drop: `T` has no
    /// padding, or its drop writes every byte.
    unsafe fn left_after_drop<T>(value: T) -> Vec<u8> {
        let mut slot = MaybeUninit::new(value);
        unsafe {
            slot.assume_init_drop();
            std::slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size_of::<T>()).to_vec()
        }
    }

    fn handshake(initiator: BoxedCryptoResolver, responder: BoxedCryptoResolver) {
        let (ikey, rkey) = (PrivateKey::generate(), PrivateKey::generate());
        let builder = |resolver| {
            snow::Builder::with_resolver(super::super::NOISE_PARAMS.parse().unwrap(), resolver)
                .prologue(super::super::PROLOGUE)
                .unwrap()
        };
        let mut i = builder(initiator)
            .local_private_key(ikey.as_bytes())
            .unwrap()
            .remote_public_key(&rkey.public_key().0)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut r = builder(responder)
            .local_private_key(rkey.as_bytes())
            .unwrap()
            .build_responder()
            .unwrap();
        let (mut msg, mut payload) = ([0u8; 1024], [0u8; 1024]);
        let n = i.write_message(b"first", &mut msg).unwrap();
        let n = r.read_message(&msg[..n], &mut payload).unwrap();
        assert_eq!(&payload[..n], b"first");
        assert_eq!(r.get_remote_static().unwrap(), ikey.public_key().0);
        let n = r.write_message(b"second", &mut msg).unwrap();
        let n = i.read_message(&msg[..n], &mut payload).unwrap();
        assert_eq!(&payload[..n], b"second");
        assert!(i.is_handshake_finished() && r.is_handshake_finished());
        assert_eq!(i.get_handshake_hash(), r.get_handshake_hash());
    }

    #[test]
    fn handshakes_with_snows_own_resolver_both_ways() {
        handshake(Box::new(Resolver), Box::new(DefaultResolver));
        handshake(Box::new(DefaultResolver), Box::new(Resolver));
    }

    #[test]
    fn x25519_matches_rfc_7748() {
        let a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let a_pub = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let b_pub = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let k = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        for (private, public, peer) in [(&a, &a_pub, &b_pub), (&b, &b_pub, &a_pub)] {
            let mut dh = X25519::default();
            dh.set(private);
            assert_eq!(dh.pubkey(), public);
            let mut shared = [0u8; KEY_LEN];
            dh.dh(peer, &mut shared).unwrap();
            assert_eq!(shared[..], k);
        }
    }

    /// RFC 8439 A.5. Its nonce, 32 zero bits then 01 02 .. 08, is Noise's
    /// layout for the counter 0x0807060504030201.
    #[test]
    fn chachapoly_matches_rfc_8439_with_noise_nonces() {
        let key = unhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        let aad = unhex("f33388860000000000004e91");
        let sealed = unhex(concat!(
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43ee",
            "a09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b9481",
            "14ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0",
            "f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e",
            "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa7699",
            "1955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130",
            "305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
            "eead9d67890cbb22392336fea1851f38",
        ));
        let counter = 0x0807_0605_0403_0201;
        let mut cipher = ChaChaPoly::default();
        cipher.set(key.as_slice().try_into().unwrap());
        let mut plain = vec![0u8; sealed.len() - TAG_LEN];
        let n = cipher.decrypt(counter, &aad, &sealed, &mut plain).unwrap();
        assert_eq!(n, plain.len());
        assert!(plain.starts_with(b"Internet-Drafts are draft documents"));
        let mut out = vec![0u8; sealed.len()];
        assert_eq!(
            cipher.encrypt(counter, &aad, &plain, &mut out),
            sealed.len()
        );
        assert_eq!(out, sealed);
        assert!(
            cipher
                .decrypt(counter + 1, &aad, &sealed, &mut plain)
                .is_err()
        );
    }

    #[test]
    fn hmac_and_hkdf_match_rfc_2104_and_5869() {
        let (ck, ikm) = ([3u8; HASH_LEN], [4u8; 40]);
        let mut h = Sha256Hash::default();
        let mut mac = [0u8; HASH_LEN];
        h.hmac(&ck, &ikm, &mut mac);
        let want = <Hmac<Sha256> as Mac>::new_from_slice(&ck)
            .unwrap()
            .chain_update(ikm)
            .finalize()
            .into_bytes();
        assert_eq!(mac[..], want[..]);

        // Noise's HKDF is RFC 5869's with the chaining key as salt and no info.
        let mut want = [0u8; 3 * HASH_LEN];
        Hkdf::<Sha256>::new(Some(&ck), &ikm)
            .expand(&[], &mut want)
            .unwrap();
        let mut outs = [[0u8; 64]; 3];
        let [o1, o2, o3] = &mut outs;
        h.hkdf(&ck, &ikm, 3, o1, o2, o3);
        for (out, want) in outs.iter().zip(want.chunks(HASH_LEN)) {
            assert_eq!(&out[..HASH_LEN], want);
        }
    }

    #[test]
    fn x25519_private_key_is_wiped_on_drop() {
        let mut dh = X25519::default();
        dh.set(&[0xa5; KEY_LEN]);
        let public = dh.pubkey().to_vec();
        let left = unsafe { left_after_drop(dh) };
        let zeros = [0u8; KEY_LEN];
        assert!(left == [&public[..], &zeros].concat() || left == [&zeros, &public[..]].concat());
    }

    #[test]
    fn cipher_key_is_wiped_on_drop() {
        let mut cipher = ChaChaPoly::default();
        cipher.set(&[0xa5; KEY_LEN]);
        let left = unsafe { left_after_drop(cipher) };
        assert!(left.iter().all(|&b| b == 0), "{left:?}");
    }

    #[test]
    fn hasher_is_wiped_on_reset_and_drop() {
        let mut h = Sha256Hash::default();
        h.input(&[0xa5; 100]);
        h.wipe();
        let bytes = unsafe {
            std::slice::from_raw_parts((&raw const h.0).cast::<u8>(), size_of::<Sha256>())
        };
        assert!(bytes.iter().all(|&b| b == 0), "{bytes:?}");
        h.reset();
        h.input(&[0xa5; 100]);
        let left = unsafe { left_after_drop(h) };
        assert!(left.iter().all(|&b| b == 0), "{left:?}");
    }
}
