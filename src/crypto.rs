use core::fmt;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// A minimal secret container that zeroizes its contents on drop.
///
/// This is intentionally small and avoids exposing secrets via `Debug`.
#[derive(Clone)]
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn to_key_sha1(&self) -> [u8; 20] {
        normalize_key_sha1(self.expose())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) type HmacSha1 = Hmac<Sha1>;

/// Normalize a secret (password/Kg) into a fixed 20-byte key for SHA1-based RAKP.
///
/// IPMI implementations commonly treat the user key as a fixed-size array where
/// the provided secret is truncated and the remainder is zero-padded.
pub(crate) fn normalize_key_sha1(secret: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    let n = secret.len().min(out.len());
    out[..n].copy_from_slice(&secret[..n]);
    out
}

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub(crate) fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; 20]> {
    let mut mac =
        <HmacSha1 as Mac>::new_from_slice(key).map_err(|_| Error::Crypto("invalid HMAC key"))?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[..]);
    Ok(out)
}

pub(crate) fn hmac_sha1_truncated_12(key: &[u8], data: &[u8]) -> Result<[u8; 12]> {
    let full = hmac_sha1(key, data)?;
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    Ok(out)
}

pub(crate) fn derive_k1_k2_sha1(sik: &[u8; 20]) -> Result<([u8; 20], [u8; 20])> {
    // IPMI spec derives additional keying material using constant strings.
    // We follow the spec's example length (20 bytes for SHA1).
    let const1 = [0x01u8; 20];
    let const2 = [0x02u8; 20];

    let k1 = hmac_sha1(sik, &const1)?;
    let k2 = hmac_sha1(sik, &const2)?;
    Ok((k1, k2))
}

pub(crate) fn derive_aes_key_from_k2(k2: &[u8; 20]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&k2[..16]);
    out
}

/// AES-128-CBC encryption without padding.
///
/// The caller must ensure `plaintext.len()` is a multiple of 16.
#[allow(dead_code)]
pub(crate) fn aes128_cbc_encrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if !plaintext.len().is_multiple_of(16) {
        return Err(Error::Crypto(
            "AES-CBC plaintext length must be a multiple of 16",
        ));
    }

    let cipher = Aes128::new_from_slice(key).map_err(|_| Error::Crypto("invalid AES-128 key"))?;

    let mut out = Vec::with_capacity(plaintext.len());
    let mut prev = *iv;

    for block in plaintext.chunks(16) {
        let mut xored = [0u8; 16];
        for i in 0..16 {
            xored[i] = block[i] ^ prev[i];
        }

        let mut ga = GenericArray::clone_from_slice(&xored);
        cipher.encrypt_block(&mut ga);

        let mut ct = [0u8; 16];
        ct.copy_from_slice(&ga);
        out.extend_from_slice(&ct);
        prev = ct;
    }

    Ok(out)
}

/// AES-128-CBC decryption without padding.
///
/// The caller must ensure `ciphertext.len()` is a multiple of 16.
pub(crate) fn aes128_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(Error::Crypto(
            "AES-CBC ciphertext length must be a multiple of 16",
        ));
    }

    let cipher = Aes128::new_from_slice(key).map_err(|_| Error::Crypto("invalid AES-128 key"))?;

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;

    for block in ciphertext.chunks(16) {
        let mut ga = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut ga);

        let mut pt = [0u8; 16];
        pt.copy_from_slice(&ga);
        for i in 0..16 {
            pt[i] ^= prev[i];
        }

        out.extend_from_slice(&pt);

        let mut next_prev = [0u8; 16];
        next_prev.copy_from_slice(block);
        prev = next_prev;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha1_vectors() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";

        let mac = hmac_sha1(key, msg).expect("hmac");
        assert_eq!(
            mac,
            [
                0xDE, 0x7C, 0x9B, 0x85, 0xB8, 0xB7, 0x8A, 0xA6, 0xBC, 0x8A, 0x7A, 0x36, 0xF7, 0x0A,
                0x90, 0x70, 0x1C, 0x9D, 0xB4, 0xD9,
            ]
        );

        let mac12 = hmac_sha1_truncated_12(key, msg).expect("hmac12");
        assert_eq!(
            mac12,
            [
                0xDE, 0x7C, 0x9B, 0x85, 0xB8, 0xB7, 0x8A, 0xA6, 0xBC, 0x8A, 0x7A, 0x36,
            ]
        );
    }

    #[test]
    fn key_derivation_vectors() {
        let mut sik = [0u8; 20];
        for (i, b) in sik.iter_mut().enumerate() {
            *b = i as u8;
        }

        let (k1, k2) = derive_k1_k2_sha1(&sik).expect("derive");

        assert_eq!(
            k1,
            [
                0x34, 0xE5, 0x1C, 0x57, 0x1C, 0x5C, 0x39, 0x24, 0x60, 0xE6, 0x77, 0x5D, 0xD5, 0xEC,
                0xFA, 0x79, 0xF4, 0xA7, 0xF5, 0x05,
            ]
        );

        assert_eq!(
            k2,
            [
                0xC1, 0x30, 0x76, 0xED, 0x19, 0x57, 0xA5, 0x9E, 0x8C, 0x7A, 0xBB, 0x24, 0x60, 0xD2,
                0x2C, 0x1A, 0x15, 0x9D, 0xE6, 0x0A,
            ]
        );

        let aes_key = derive_aes_key_from_k2(&k2);
        assert_eq!(
            aes_key,
            [
                0xC1, 0x30, 0x76, 0xED, 0x19, 0x57, 0xA5, 0x9E, 0x8C, 0x7A, 0xBB, 0x24, 0x60, 0xD2,
                0x2C, 0x1A,
            ]
        );
    }

    #[test]
    fn aes128_cbc_vectors() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let iv: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        let plaintext = b"0123456789abcdef";

        let ciphertext = aes128_cbc_encrypt(&key, &iv, plaintext).expect("encrypt");
        assert_eq!(
            ciphertext,
            [
                0xEB, 0x9E, 0x5B, 0xA4, 0x1B, 0x90, 0x2D, 0xB8, 0x25, 0x29, 0x82, 0xAA, 0x1A, 0x23,
                0xF4, 0xBE,
            ]
        );

        let decrypted = aes128_cbc_decrypt(&key, &iv, &ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes128_cbc_rejects_non_block_multiple() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let err = aes128_cbc_encrypt(&key, &iv, b"not16").unwrap_err();
        match err {
            Error::Crypto(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
