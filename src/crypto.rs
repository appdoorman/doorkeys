//! Key management and authenticated encryption.
//!
//! Key hierarchy:
//! - The master key (env) derives the control database key and wraps each tenant's data key.
//! - Each tenant has a random data key (DEK). From it we derive the key of the tenant's
//!   SQLCipher database file and a separate key for field-level secrets (SCIM tokens,
//!   service account keys). Destroying the wrapped DEK makes all tenant data unreadable.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; 32]);

pub type MasterKey = Key;

impl Key {
    pub fn from_base64(s: &str) -> Result<Self> {
        let mut bytes = STANDARD.decode(s.trim()).map_err(|_| anyhow!("key is not valid base64"))?;
        if bytes.len() != 32 {
            bytes.zeroize();
            bail!("key must be exactly 32 bytes");
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(k))
    }

    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// The raw key, for an API that takes key bytes (an Ed25519 seed).
    pub fn bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Derives an independent sub-key for a purpose (HMAC-SHA256 as a PRF).
    pub fn derive(&self, label: &str) -> Key {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("hmac accepts any key length");
        // A fixed label, from the project's first name. Changing it would change every derived key.
        mac.update(b"scimbridge/v1/");
        mac.update(label.as_bytes());
        let mut k = [0u8; 32];
        k.copy_from_slice(&mac.finalize().into_bytes());
        Key(k)
    }

    /// Value for `PRAGMA key` that hands SQLCipher a raw 256-bit key (no passphrase KDF).
    pub fn sqlcipher_pragma(&self) -> String {
        format!("\"x'{}'\"", hex::encode(self.0))
    }

    /// Encrypts with AES-256-GCM. `aad` binds the ciphertext to its context (tenant, row,
    /// purpose) so it cannot be copied to another place and still decrypt.
    pub fn seal(&self, plaintext: &[u8], aad: &str) -> String {
        let cipher = Aes256Gcm::new_from_slice(&self.0).expect("32-byte key");
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
            .expect("aes-gcm encryption cannot fail for valid input");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        format!("v1.{}", STANDARD.encode(out))
    }

    pub fn open(&self, sealed: &str, aad: &str) -> Result<Vec<u8>> {
        let raw = sealed.strip_prefix("v1.").ok_or_else(|| anyhow!("unknown ciphertext version"))?;
        let data = STANDARD.decode(raw).map_err(|_| anyhow!("corrupt ciphertext"))?;
        if data.len() < 12 + 16 {
            bail!("corrupt ciphertext");
        }
        let cipher = Aes256Gcm::new_from_slice(&self.0).expect("32-byte key");
        cipher
            .decrypt(Nonce::from_slice(&data[..12]), Payload { msg: &data[12..], aad: aad.as_bytes() })
            .map_err(|_| anyhow!("decryption failed"))
    }

    pub fn open_string(&self, sealed: &str, aad: &str) -> Result<String> {
        Ok(String::from_utf8(self.open(sealed, aad)?)?)
    }

    pub fn wrap(&self, key: &Key, aad: &str) -> String {
        self.seal(&key.0, aad)
    }

    pub fn unwrap_key(&self, wrapped: &str, aad: &str) -> Result<Key> {
        let mut bytes = self.open(wrapped, aad)?;
        if bytes.len() != 32 {
            bytes.zeroize();
            bail!("wrapped key has wrong length");
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Key(k))
    }
}

/// URL-safe random token with `bytes` bytes of entropy.
pub fn random_token(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_aad_binding() {
        let k = Key::generate();
        let s = k.seal(b"token-123", "app:1:secret");
        assert_eq!(k.open(&s, "app:1:secret").unwrap(), b"token-123");
        assert!(k.open(&s, "app:2:secret").is_err());
        assert!(Key::generate().open(&s, "app:1:secret").is_err());
    }

    #[test]
    fn wrap_and_derive() {
        let master = Key::generate();
        let dek = Key::generate();
        let w = master.wrap(&dek, "tenant:abc");
        let back = master.unwrap_key(&w, "tenant:abc").unwrap();
        assert_eq!(back.0, dek.0);
        assert_ne!(dek.derive("db").0, dek.derive("fields").0);
    }
}
