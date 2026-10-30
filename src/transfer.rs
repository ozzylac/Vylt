//! Encrypted migration package (`.svtransfer`): vault file + secret key + profile name,
//! sealed with a separate transfer passphrase (Argon2id -> XChaCha20-Poly1305).
//!
//! File layout: header (57 bytes, authenticated as AAD) || ciphertext+tag.
//! header = magic(4) | version(1) | m_cost KiB(4) | t_cost(4) | p_cost(4) | salt(16) | nonce(24)

use std::fs;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vault::{write_atomic, KdfParams, SecretKey, VaultError};

const MAGIC: &[u8; 4] = b"SVTR";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN + NONCE_LEN;
const KEY_LEN: usize = 32;

pub const KDF: KdfParams = KdfParams { m_cost_kib: 256 * 1024, t_cost: 4, p_cost: 1 };
pub const MIN_PASSPHRASE_CHARS: usize = 20;

pub struct Package {
    pub profile_name: String,
    pub vault: Vec<u8>,
    pub key: SecretKey,
}

fn derive(passphrase: &str, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(KEY_LEN)).map_err(|_| VaultError::Kdf)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
        .map_err(|_| VaultError::Kdf)?;
    Ok(out)
}

fn header(kdf: KdfParams, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[4] = VERSION;
    h[5..9].copy_from_slice(&kdf.m_cost_kib.to_le_bytes());
    h[9..13].copy_from_slice(&kdf.t_cost.to_le_bytes());
    h[13..17].copy_from_slice(&kdf.p_cost.to_le_bytes());
    h[17..17 + SALT_LEN].copy_from_slice(salt);
    h[17 + SALT_LEN..].copy_from_slice(nonce);
    h
}

fn frame(name: &str, vault: &[u8], key: &SecretKey) -> Zeroizing<Vec<u8>> {
    let mut p = Zeroizing::new(Vec::with_capacity(8 + name.len() + vault.len() + KEY_LEN));
    p.extend_from_slice(&(name.len() as u32).to_le_bytes());
    p.extend_from_slice(name.as_bytes());
    p.extend_from_slice(&(vault.len() as u32).to_le_bytes());
    p.extend_from_slice(vault);
    p.extend_from_slice(&*key.to_bytes());
    p
}

fn unframe(p: &[u8]) -> Option<Package> {
    fn take<'a>(buf: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        (buf.len() >= n).then(|| {
            let (a, b) = buf.split_at(n);
            *buf = b;
            a
        })
    }
    let mut r = p;
    let n = u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?) as usize;
    let name = String::from_utf8(take(&mut r, n)?.to_vec()).ok()?;
    let v = u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?) as usize;
    let vault = take(&mut r, v)?.to_vec();
    let key: [u8; KEY_LEN] = take(&mut r, KEY_LEN)?.try_into().ok()?;
    (r.is_empty() && vault.starts_with(b"SVLT")).then(|| Package { profile_name: name, vault, key: SecretKey::from_bytes(key) })
}

/// Short SHA-256 fingerprint of a file, to compare after copying it to the new PC.
pub fn fingerprint(path: &Path) -> Result<String, VaultError> {
    let h = Sha256::digest(fs::read(path)?);
    Ok(h[..8].chunks(2).map(|c| format!("{:02X}{:02X}", c[0], c[1])).collect::<Vec<_>>().join("-"))
}

/// Seal the vault file + secret key into `out`, then re-read and verify it. Refuses to overwrite.
pub fn export(
    vault_path: &Path,
    key: &SecretKey,
    profile_name: &str,
    passphrase: &str,
    kdf: KdfParams,
    out: &Path,
) -> Result<String, VaultError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(VaultError::Format("transfer passphrase too short"));
    }
    if out.exists() {
        return Err(VaultError::Format("destination already exists"));
    }
    let vault = fs::read(vault_path)?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| VaultError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
    let aad = header(kdf, &salt, &nonce);
    let k = derive(passphrase, &salt, kdf)?;
    let ct = XChaCha20Poly1305::new((&*k).into())
        .encrypt((&nonce).into(), Payload { msg: &frame(profile_name, &vault, key), aad: &aad })
        .map_err(|_| VaultError::Decrypt)?;
    let mut blob = Vec::with_capacity(HEADER_LEN + ct.len());
    blob.extend_from_slice(&aad);
    blob.extend_from_slice(&ct);
    write_atomic(out, &blob)?;

    // Verify the written file really decrypts to what we meant to export.
    let ok = read(out, passphrase).is_ok_and(|p| p.vault == vault && p.profile_name == profile_name);
    if !ok {
        let _ = fs::remove_file(out);
        return Err(VaultError::Format("verification of the exported file failed"));
    }
    fingerprint(out)
}

pub fn read(path: &Path, passphrase: &str) -> Result<Package, VaultError> {
    let blob = fs::read(path)?;
    if blob.len() < HEADER_LEN + 16 || &blob[..4] != MAGIC {
        return Err(VaultError::Format("not a transfer file"));
    }
    if blob[4] != VERSION {
        return Err(VaultError::Format("unsupported version"));
    }
    let u32_at = |i: usize| u32::from_le_bytes(blob[i..i + 4].try_into().unwrap());
    let kdf = KdfParams { m_cost_kib: u32_at(5), t_cost: u32_at(9), p_cost: u32_at(13) };
    // Untrusted header: refuse weak (downgrade) or absurd parameters.
    #[cfg(not(test))]
    if kdf.m_cost_kib < 128 * 1024 || kdf.t_cost < 3 {
        return Err(VaultError::Format("kdf parameters too weak"));
    }
    if kdf.m_cost_kib > crate::vault::MAX_M_COST_KIB || kdf.t_cost > crate::vault::MAX_T_COST || !(1..=crate::vault::MAX_P_COST).contains(&kdf.p_cost) {
        return Err(VaultError::Format("kdf parameters out of range"));
    }
    let salt: [u8; SALT_LEN] = blob[17..17 + SALT_LEN].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = blob[17 + SALT_LEN..HEADER_LEN].try_into().unwrap();
    let k = derive(passphrase, &salt, kdf)?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new((&*k).into())
            .decrypt((&nonce).into(), Payload { msg: &blob[HEADER_LEN..], aad: &blob[..HEADER_LEN] })
            .map_err(|_| VaultError::Decrypt)?,
    );
    unframe(&plain).ok_or(VaultError::Format("corrupt transfer payload"))
}

/// Write the vault and key to their destinations; never overwrites existing files.
pub fn install(pkg: &Package, vault_dest: &Path, key_dest: &Path) -> Result<(), VaultError> {
    let has_key = !pkg.key.is_empty();
    if vault_dest.exists() || (has_key && key_dest.exists()) {
        return Err(VaultError::Format("destination already exists"));
    }
    let dests: &[&Path] = if has_key { &[vault_dest, key_dest] } else { &[vault_dest] };
    for p in dests {
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir)?;
        }
    }
    write_atomic(vault_dest, &pkg.vault)?;
    if has_key {
        pkg.key.save(key_dest)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    const FAST: KdfParams = KdfParams { m_cost_kib: 8, t_cost: 1, p_cost: 1 };
    const PASS: &str = "correct horse battery staple 42";

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vylt-xfer-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn make_vault(d: &Path) -> (std::path::PathBuf, SecretKey) {
        let sk = SecretKey::generate().unwrap();
        let vp = d.join("vault.svault");
        let mut v = Vault::create(&vp, "master", &sk, FAST).unwrap();
        let mut e = crate::vault::Entry::blank();
        e.site = "example.com".into();
        v.entries.push(e);
        v.save().unwrap();
        (vp, sk)
    }

    #[test]
    fn full_migration_roundtrip() {
        let d = dir("roundtrip");
        let (vp, sk) = make_vault(&d);
        let out = d.join("t.svtransfer");
        let fp = export(&vp, &sk, "alice", PASS, FAST, &out).unwrap();
        assert_eq!(fp.len(), 19);

        // "new PC": fresh folder, import, then open with the ORIGINAL master password.
        let d2 = dir("newpc");
        let pkg = read(&out, PASS).unwrap();
        assert_eq!(pkg.profile_name, "alice");
        install(&pkg, &d2.join("v.svault"), &d2.join("k.key")).unwrap();
        let sk2 = SecretKey::load(&d2.join("k.key")).unwrap();
        let v = Vault::open(&d2.join("v.svault"), "master", &sk2).unwrap();
        assert_eq!(v.entries[0].site, "example.com");
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&d2);
    }

    #[test]
    fn profile_without_secret_key_migrates_without_a_key_file() {
        let d = dir("nokey");
        let sk = SecretKey::empty();
        let vp = d.join("vault.svault");
        Vault::create(&vp, "master", &sk, FAST).unwrap();
        let out = d.join("t.svtransfer");
        export(&vp, &sk, "bob", PASS, FAST, &out).unwrap();
        let pkg = read(&out, PASS).unwrap();
        assert!(pkg.key.is_empty());
        let d2 = dir("nokey-new");
        install(&pkg, &d2.join("v.svault"), &d2.join("k.key")).unwrap();
        assert!(!d2.join("k.key").exists(), "no key file must be written");
        assert!(Vault::open(&d2.join("v.svault"), "master", &SecretKey::empty()).is_ok());
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&d2);
    }

    #[test]
    fn wrong_passphrase_and_tamper_fail() {
        let d = dir("tamper");
        let (vp, sk) = make_vault(&d);
        let out = d.join("t.svtransfer");
        export(&vp, &sk, "alice", PASS, FAST, &out).unwrap();
        assert!(matches!(read(&out, "another passphrase that is long"), Err(VaultError::Decrypt)));
        let orig = fs::read(&out).unwrap();
        for idx in [20, HEADER_LEN + 3, orig.len() - 1] {
            let mut b = orig.clone();
            b[idx] ^= 1;
            fs::write(&out, &b).unwrap();
            assert!(read(&out, PASS).is_err(), "tamper at {idx} not detected");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn strict_refusals() {
        let d = dir("strict");
        let (vp, sk) = make_vault(&d);
        let out = d.join("t.svtransfer");
        assert!(export(&vp, &sk, "a", "too short", FAST, &out).is_err());
        export(&vp, &sk, "a", PASS, FAST, &out).unwrap();
        assert!(export(&vp, &sk, "a", PASS, FAST, &out).is_err(), "must not overwrite");
        let pkg = read(&out, PASS).unwrap();
        install(&pkg, &d.join("x.svault"), &d.join("x.key")).unwrap();
        assert!(install(&pkg, &d.join("x.svault"), &d.join("y.key")).is_err(), "must not overwrite vault");
        let _ = fs::remove_dir_all(&d);
    }
}
