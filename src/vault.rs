//! Encrypted vault: Argon2id + secret key -> HKDF -> XChaCha20-Poly1305.
//!
//! File layout: header (57 bytes, authenticated as AAD) || ciphertext+tag.
//! header = magic(4) | version(1) | m_cost KiB(4) | t_cost(4) | p_cost(4) | salt(16) | nonce(24)

use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hidden::HiddenBox;
use crate::lock::EntryLock;

const MAGIC: &[u8; 4] = b"SVLT";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const HKDF_INFO: &[u8] = b"securevault v1 vault key";
pub(crate) const MAX_M_COST_KIB: u32 = 512 * 1024;
pub(crate) const MAX_T_COST: u32 = 8;
pub(crate) const MAX_P_COST: u32 = 4;

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    /// Wrong password, wrong secret key, or tampered file (indistinguishable by design).
    Decrypt,
    Format(&'static str),
    Kdf,
    Random,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Decrypt => f.write_str("decryption failed (wrong password/secret key or corrupted file)"),
            Self::Format(m) => write!(f, "invalid vault file: {m}"),
            Self::Kdf => f.write_str("key derivation failed"),
            Self::Random => f.write_str("system RNG failure"),
        }
    }
}

impl VaultError {
    /// Stable diagnostic code shown to the user (catalogue in src/errcode.rs).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "SV-E14",
            Self::Decrypt => "SV-E10",
            Self::Format(_) => "SV-E11",
            Self::Kdf => "SV-E12",
            Self::Random => "SV-E13",
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const DEFAULT: Self = Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 1 };

    /// Reject downgraded (weak) or DoS-sized parameters read from an untrusted header. The ceiling
    /// is the app's "Maximum" level with some margin, so a crafted file cannot freeze the app.
    pub(crate) fn validate(&self) -> Result<(), VaultError> {
        #[cfg(not(test))]
        if self.m_cost_kib < 32 * 1024 || self.t_cost < 2 {
            return Err(VaultError::Format("kdf parameters too weak"));
        }
        if self.m_cost_kib > MAX_M_COST_KIB || self.t_cost > MAX_T_COST || !(1..=MAX_P_COST).contains(&self.p_cost) {
            return Err(VaultError::Format("kdf parameters out of range"));
        }
        Ok(())
    }
}

/// 256-bit key stored apart from the vault; a stolen vault alone is not enough to attack.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn generate() -> Result<Self, VaultError> {
        let mut k = [0u8; KEY_LEN];
        getrandom::fill(&mut k).map_err(|_| VaultError::Random)?;
        Ok(Self(k))
    }

    /// "No secret key": all zeros. Protection then rests on the master password alone.
    pub fn empty() -> Self {
        Self([0u8; KEY_LEN])
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let mut raw = Zeroizing::new(fs::read(path)?);
        if raw.len() != KEY_LEN {
            return Err(VaultError::Format("secret key file must be 32 bytes"));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Self(k))
    }

    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        write_atomic(path, &self.0)
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0)
    }

    pub(crate) fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub site: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    #[serde(default)]
    pub codes: Vec<Code>,
    #[serde(default)]
    pub category: String,
    /// Optional PIN / code gate (verifier only, no secret material).
    #[serde(default)]
    #[zeroize(skip)]
    pub lock: Option<EntryLock>,
    /// Unix time of the last password change (0 = unknown, e.g. imported).
    #[serde(default)]
    pub updated: u64,
    /// WebAuthn credentials created by websites for this account.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<crate::passkey::Passkey>,
}

impl Entry {
    pub fn blank() -> Self {
        Self {
            site: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
            codes: Vec::new(),
            category: String::new(),
            lock: None,
            updated: 0,
            passkeys: Vec::new(),
        }
    }
}

/// A validation code attached to an entry: a live TOTP (`secret` = base32 key or otpauth URL)
/// or a static code such as a recovery code (`secret` = the code itself).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Code {
    pub label: String,
    pub note: String,
    pub secret: String,
    pub totp: bool,
}

/// Per-profile preferences, stored inside the encrypted payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub auto_lock_secs: u64,
    pub clipboard_secs: u64,
    /// Unix timestamps of each migration package exported from this vault.
    pub transfer_log: Vec<u64>,
    /// Ask for the master password before every passkey use (else an open vault is enough).
    pub passkey_password: bool,
    /// Secret code another person types in their own profile to link it with this one.
    pub link_id: String,
    /// Opt-in: check passwords against Have I Been Pwned (k-anonymity). Off by default.
    pub hibp: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_lock_secs: 120, clipboard_secs: 15, transfer_log: Vec::new(), passkey_password: false, link_id: String::new(), hibp: false }
    }
}

#[derive(Serialize, Deserialize)]
struct VaultData {
    entries: Vec<Entry>,
    #[serde(default)]
    settings: Settings,
    #[serde(default)]
    unlock_totp: Option<Zeroizing<String>>,
    #[serde(default)]
    hidden: Vec<HiddenBox>,
    #[serde(default)]
    last_totp_step: u64,
}

struct Header {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[..4].copy_from_slice(MAGIC);
        b[4] = VERSION;
        b[5..9].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        b[9..13].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        b[13..17].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        b[17..17 + SALT_LEN].copy_from_slice(&self.salt);
        b[17 + SALT_LEN..].copy_from_slice(&self.nonce);
        b
    }

    fn decode(b: &[u8]) -> Result<Self, VaultError> {
        if b.len() < HEADER_LEN + 16 {
            return Err(VaultError::Format("file too short"));
        }
        if &b[..4] != MAGIC {
            return Err(VaultError::Format("bad magic"));
        }
        if b[4] != VERSION {
            return Err(VaultError::Format("unsupported version"));
        }
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let kdf = KdfParams { m_cost_kib: u32_at(5), t_cost: u32_at(9), p_cost: u32_at(13) };
        kdf.validate()?;
        Ok(Self {
            kdf,
            salt: b[17..17 + SALT_LEN].try_into().unwrap(),
            nonce: b[17 + SALT_LEN..HEADER_LEN].try_into().unwrap(),
        })
    }
}

fn derive_key(
    password: &str,
    secret: &SecretKey,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(KEY_LEN)).map_err(|_| VaultError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *stretched)
        .map_err(|_| VaultError::Kdf)?;

    // Mix in the secret key: IKM = argon2id output, HKDF salt = secret key.
    let hk = Hkdf::<Sha256>::new(Some(&secret.0), &*stretched);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO, &mut *key).map_err(|_| VaultError::Kdf)?;
    Ok(key)
}

fn random<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| VaultError::Random)?;
    Ok(b)
}

/// Whether `path` is a Vylt vault file (magic and version), checked before shredding it.
pub fn is_vault_file(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 5];
    fs::File::open(path).and_then(|mut f| f.read_exact(&mut head)).is_ok() && &head[..4] == MAGIC && head[4] == VERSION
}

/// Whether `path` has the shape of a secret-key file (exactly 32 bytes).
pub fn is_key_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() == KEY_LEN as u64)
}

/// Write to a temp file with a random name, fsync, then replace the target in one step (and,
/// on Windows, with write-through so the rename itself reaches the disk).
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let tag: String = random::<6>()?.iter().map(|b| format!("{b:02x}")).collect();
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{tag}.tmp"));
    let tmp = PathBuf::from(tmp);
    let mut f = File::create(&tmp)?;
    let written = f.write_all(data).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|_| replace(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
    let w = |p: &Path| p.as_os_str().encode_wide().chain([0]).collect::<Vec<u16>>();
    let (a, b) = (w(from), w(to));
    if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}

/// An unlocked vault. Dropping it (or calling `lock`) wipes the key and entries from memory.
pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    pub entries: Vec<Entry>,
    pub settings: Settings,
    /// Base32 key of the TOTP required at unlock (app-level gate, see `Vault::open` callers).
    pub unlock_totp: Option<Zeroizing<String>>,
    /// Sealed hidden categories. Opaque without each category's own password.
    pub hidden: Vec<HiddenBox>,
    /// Last TOTP time step accepted at unlock: a code is never accepted twice.
    pub last_totp_step: u64,
}

impl Vault {
    pub fn create(path: &Path, password: &str, secret: &SecretKey, kdf: KdfParams) -> Result<Self, VaultError> {
        kdf.validate()?;
        if path.exists() {
            return Err(VaultError::Format("vault already exists"));
        }
        let salt = random::<SALT_LEN>()?;
        let key = derive_key(password, secret, &salt, kdf)?;
        let v = Self {
            path: path.to_owned(),
            key,
            salt,
            kdf,
            entries: Vec::new(),
            settings: Settings::default(),
            unlock_totp: None,
            hidden: Vec::new(),
            last_totp_step: 0,
        };
        v.save()?;
        Ok(v)
    }

    pub fn open(path: &Path, password: &str, secret: &SecretKey) -> Result<Self, VaultError> {
        let blob = fs::read(path)?;
        let header = Header::decode(&blob)?;
        let key = derive_key(password, secret, &header.salt, header.kdf)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    (&header.nonce).into(),
                    Payload { msg: &blob[HEADER_LEN..], aad: &blob[..HEADER_LEN] },
                )
                .map_err(|_| VaultError::Decrypt)?,
        );
        let payload: VaultData = serde_json::from_slice(&plain).map_err(|_| VaultError::Format("corrupt payload"))?;
        Ok(Self {
            path: path.to_owned(),
            key,
            salt: header.salt,
            kdf: header.kdf,
            entries: payload.entries,
            settings: payload.settings,
            unlock_totp: payload.unlock_totp,
            hidden: payload.hidden,
            last_totp_step: payload.last_totp_step,
        })
    }

    /// Re-encrypt with a fresh nonce and atomically replace the file.
    pub fn save(&self) -> Result<(), VaultError> {
        let header = Header { kdf: self.kdf, salt: self.salt, nonce: random::<NONCE_LEN>()? };
        let aad = header.encode();
        let plain = Zeroizing::new(
            serde_json::to_vec(&VaultData {
                entries: self.entries.clone(),
                settings: self.settings.clone(),
                unlock_totp: self.unlock_totp.clone(),
                hidden: self.hidden.clone(),
                last_totp_step: self.last_totp_step,
            })
            .map_err(|_| VaultError::Format("serialize"))?,
        );
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ct = cipher
            .encrypt((&header.nonce).into(), Payload { msg: &plain, aad: &aad })
            .map_err(|_| VaultError::Decrypt)?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ct);
        write_atomic(&self.path, &out)
    }

    /// New salt + new key from the new password; caller must `save()` afterwards.
    pub fn change_password(&mut self, new_password: &str, secret: &SecretKey) -> Result<(), VaultError> {
        let salt = random::<SALT_LEN>()?;
        self.key = derive_key(new_password, secret, &salt, self.kdf)?;
        self.salt = salt;
        self.save()
    }

    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }

    /// Takes effect at the next `change_password` (which re-derives the key).
    pub fn set_kdf(&mut self, kdf: KdfParams) -> Result<(), VaultError> {
        kdf.validate()?;
        self.kdf = kdf;
        Ok(())
    }

    pub fn lock(self) {
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_cost_kib: 8, t_cost: 1, p_cost: 1 };

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vylt-test-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    fn entry() -> Entry {
        let mut e = Entry::blank();
        e.site = "example.com".into();
        e.username = "me".into();
        e.password = "hunter2".into();
        e
    }

    #[test]
    fn roundtrip() {
        let p = tmp("roundtrip");
        let sk = SecretKey::generate().unwrap();
        let mut v = Vault::create(&p, "master", &sk, FAST).unwrap();
        v.entries.push(entry());
        v.save().unwrap();
        let v2 = Vault::open(&p, "master", &sk).unwrap();
        assert_eq!(v2.entries.len(), 1);
        assert_eq!(v2.entries[0].password, "hunter2");
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn wrong_password_or_secret_key_fails() {
        let p = tmp("wrong");
        let sk = SecretKey::generate().unwrap();
        Vault::create(&p, "master", &sk, FAST).unwrap();
        assert!(matches!(Vault::open(&p, "nope", &sk), Err(VaultError::Decrypt)));
        let other = SecretKey::generate().unwrap();
        assert!(matches!(Vault::open(&p, "master", &other), Err(VaultError::Decrypt)));
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn tampering_is_detected() {
        let p = tmp("tamper");
        let sk = SecretKey::generate().unwrap();
        let mut v = Vault::create(&p, "master", &sk, FAST).unwrap();
        v.entries.push(entry());
        v.save().unwrap();
        let orig = fs::read(&p).unwrap();
        // flip one bit in the header (salt), the ciphertext, and the tag
        for idx in [20, HEADER_LEN + 1, orig.len() - 1] {
            let mut b = orig.clone();
            b[idx] ^= 1;
            fs::write(&p, &b).unwrap();
            assert!(Vault::open(&p, "master", &sk).is_err(), "tamper at {idx} not detected");
        }
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn vault_without_secret_key_opens_only_with_the_empty_key() {
        let p = tmp("nokey");
        let empty = SecretKey::empty();
        assert!(empty.is_empty());
        assert!(!SecretKey::generate().unwrap().is_empty());
        Vault::create(&p, "master", &empty, FAST).unwrap();
        assert!(Vault::open(&p, "master", &empty).is_ok());
        assert!(matches!(Vault::open(&p, "master", &SecretKey::generate().unwrap()), Err(VaultError::Decrypt)));
        assert!(matches!(Vault::open(&p, "wrong", &empty), Err(VaultError::Decrypt)));
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn nonce_changes_every_save() {
        let p = tmp("nonce");
        let sk = SecretKey::generate().unwrap();
        let v = Vault::create(&p, "master", &sk, FAST).unwrap();
        let a = fs::read(&p).unwrap();
        v.save().unwrap();
        let b = fs::read(&p).unwrap();
        assert_ne!(a[17 + SALT_LEN..HEADER_LEN], b[17 + SALT_LEN..HEADER_LEN]);
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn change_password() {
        let p = tmp("chpw");
        let sk = SecretKey::generate().unwrap();
        let mut v = Vault::create(&p, "old", &sk, FAST).unwrap();
        v.entries.push(entry());
        v.change_password("new", &sk).unwrap();
        assert!(Vault::open(&p, "old", &sk).is_err());
        assert_eq!(Vault::open(&p, "new", &sk).unwrap().entries.len(), 1);
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn codes_settings_and_unlock_totp_roundtrip() {
        let p = tmp("codes");
        let sk = SecretKey::generate().unwrap();
        let mut v = Vault::create(&p, "master", &sk, FAST).unwrap();
        let mut e = entry();
        e.codes.push(Code { label: "GitHub".into(), note: "perso".into(), secret: "JBSWY3DPEHPK3PXP".into(), totp: true });
        e.codes.push(Code { label: "Secours".into(), note: "numero 1".into(), secret: "1234-5678".into(), totp: false });
        v.entries.push(e);
        v.settings.auto_lock_secs = 600;
        v.unlock_totp = Some(Zeroizing::new("ABCDEFGH".into()));
        v.save().unwrap();
        let v2 = Vault::open(&p, "master", &sk).unwrap();
        assert_eq!(v2.entries[0].codes.len(), 2);
        assert_eq!(v2.entries[0].codes[1].note, "numero 1");
        assert_eq!(v2.settings.auto_lock_secs, 600);
        assert_eq!(v2.unlock_totp.as_ref().map(|s| s.as_str()), Some("ABCDEFGH"));
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn old_payload_without_new_fields_still_opens() {
        let d: VaultData =
            serde_json::from_str(r#"{"entries":[{"site":"a","username":"b","password":"c","notes":""}]}"#).unwrap();
        assert_eq!(d.entries.len(), 1);
        assert!(d.entries[0].codes.is_empty());
        assert_eq!(d.settings.auto_lock_secs, 120);
        assert!(d.unlock_totp.is_none());
    }

    #[test]
    fn oversized_params_rejected() {
        let bad = KdfParams { m_cost_kib: u32::MAX, t_cost: 1, p_cost: 1 };
        assert!(bad.validate().is_err());
        for bad in [
            KdfParams { m_cost_kib: 1024 * 1024, t_cost: 3, p_cost: 1 },
            KdfParams { m_cost_kib: 64 * 1024, t_cost: 20, p_cost: 1 },
            KdfParams { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 8 },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(KdfParams { m_cost_kib: 512 * 1024, t_cost: 5, p_cost: 1 }.validate().is_ok(), "the Maximum level stays valid");
    }
}
