//! Hidden categories: a separate set of entries sealed under its own password.
//!
//! Each box is Argon2id(category password) -> XChaCha20-Poly1305, stored inside the (already
//! encrypted) vault payload. Nothing in the UI lists them: a box only opens when its password
//! is typed. Someone who knows the master password still cannot read it.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroizing, ZeroizeOnDrop};

use crate::vault::{Entry, KdfParams, VaultError};

const AAD: &[u8] = b"securevault hidden box v1";

pub const KDF: KdfParams = KdfParams::DEFAULT;
pub const MIN_PASSWORD_CHARS: usize = 12;

#[derive(Clone, Serialize, Deserialize)]
pub struct HiddenBox {
    id: u64,
    kdf: KdfParams,
    salt: [u8; 16],
    nonce: [u8; 24],
    ct: Vec<u8>,
}

impl HiddenBox {
    pub fn is(&self, id: u64) -> bool {
        self.id == id
    }
}

#[derive(Serialize, Deserialize)]
struct Content {
    name: String,
    entries: Vec<Entry>,
}

/// An opened hidden category; holds the derived key so it can be re-sealed without the password.
#[derive(ZeroizeOnDrop)]
pub struct OpenBox {
    #[zeroize(skip)]
    pub id: u64,
    pub name: String,
    pub entries: Vec<Entry>,
    key: Zeroizing<[u8; 32]>,
    #[zeroize(skip)]
    salt: [u8; 16],
    #[zeroize(skip)]
    kdf: KdfParams,
}

fn derive(password: &str, salt: &[u8; 16], kdf: KdfParams) -> Option<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32)).ok()?;
    let mut k = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(password.as_bytes(), salt, &mut *k).ok()?;
    Some(k)
}

fn aad(id: u64, salt: &[u8; 16], kdf: KdfParams) -> Vec<u8> {
    let mut a = AAD.to_vec();
    a.extend_from_slice(&id.to_le_bytes());
    a.extend_from_slice(salt);
    a.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    a.extend_from_slice(&kdf.t_cost.to_le_bytes());
    a.extend_from_slice(&kdf.p_cost.to_le_bytes());
    a
}

impl OpenBox {
    pub fn create(name: &str, password: &str, kdf: KdfParams) -> Result<Self, VaultError> {
        if password.chars().count() < MIN_PASSWORD_CHARS {
            return Err(VaultError::Format("hidden category password too short"));
        }
        let mut salt = [0u8; 16];
        let mut id = [0u8; 8];
        getrandom::fill(&mut salt).map_err(|_| VaultError::Random)?;
        getrandom::fill(&mut id).map_err(|_| VaultError::Random)?;
        let key = derive(password, &salt, kdf).ok_or(VaultError::Kdf)?;
        Ok(Self { id: u64::from_le_bytes(id), name: name.to_owned(), entries: Vec::new(), key, salt, kdf })
    }

    /// Try `password` against one box. `None` means wrong password (or tampering).
    pub fn open(b: &HiddenBox, password: &str) -> Option<Self> {
        b.kdf.validate().ok()?;
        let key = derive(password, &b.salt, b.kdf)?;
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new((&*key).into())
                .decrypt((&b.nonce).into(), Payload { msg: &b.ct, aad: &aad(b.id, &b.salt, b.kdf) })
                .ok()?,
        );
        let c: Content = serde_json::from_slice(&plain).ok()?;
        Some(Self { id: b.id, name: c.name, entries: c.entries, key, salt: b.salt, kdf: b.kdf })
    }

    /// Re-encrypt with a fresh nonce.
    pub fn seal(&self) -> Result<HiddenBox, VaultError> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&Content { name: self.name.clone(), entries: self.entries.clone() })
                .map_err(|_| VaultError::Format("serialize"))?,
        );
        let ct = XChaCha20Poly1305::new((&*self.key).into())
            .encrypt((&nonce).into(), Payload { msg: &plain, aad: &aad(self.id, &self.salt, self.kdf) })
            .map_err(|_| VaultError::Decrypt)?;
        Ok(HiddenBox { id: self.id, kdf: self.kdf, salt: self.salt, nonce, ct })
    }
}

/// Insert or replace a sealed box by id.
pub fn upsert(list: &mut Vec<HiddenBox>, b: HiddenBox) {
    match list.iter_mut().find(|x| x.id == b.id) {
        Some(slot) => *slot = b,
        None => list.push(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_cost_kib: 8, t_cost: 1, p_cost: 1 };
    const PW: &str = "category-password-1";

    #[test]
    fn open_only_with_right_password_and_roundtrip() {
        let mut b = OpenBox::create("Perso", PW, FAST).unwrap();
        let mut e = Entry::blank();
        e.site = "secret.example".into();
        b.entries.push(e);
        let sealed = b.seal().unwrap();

        assert!(OpenBox::open(&sealed, "wrong-password-xx").is_none());
        let o = OpenBox::open(&sealed, PW).unwrap();
        assert_eq!(o.name, "Perso");
        assert_eq!(o.entries[0].site, "secret.example");
        assert_eq!(o.id, b.id);
    }

    #[test]
    fn tamper_and_short_password() {
        assert!(OpenBox::create("x", "short", FAST).is_err());
        let b = OpenBox::create("x", PW, FAST).unwrap();
        let mut sealed = b.seal().unwrap();
        let last = sealed.ct.len() - 1;
        sealed.ct[last] ^= 1;
        assert!(OpenBox::open(&sealed, PW).is_none());
    }

    #[test]
    fn upsert_replaces_by_id() {
        let b = OpenBox::create("x", PW, FAST).unwrap();
        let mut list = vec![];
        upsert(&mut list, b.seal().unwrap());
        upsert(&mut list, b.seal().unwrap());
        assert_eq!(list.len(), 1);
    }
}
