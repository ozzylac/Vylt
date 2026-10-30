//! Duress mode: a second master password that opens a harmless decoy vault.
//!
//! The decoy lives next to the real vault under an innocuous name and uses the same secret key.
//! It protects against coercion in front of the screen. It is NOT plausible deniability against
//! someone who inspects the disk: the second file is visible.

use std::path::{Path, PathBuf};

use crate::vault::{KdfParams, SecretKey, Vault, VaultError};

pub fn decoy_path(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name("vault.cache")
}

pub fn has_decoy(vault_path: &Path) -> bool {
    decoy_path(vault_path).exists()
}

pub struct Opened {
    pub vault: Vault,
    pub is_decoy: bool,
}

/// Open the real vault; if the password is not its master password, try the decoy.
/// Wrong-password errors from both attempts collapse into a single `Decrypt`.
/// When a decoy exists both vaults are always tried, so the time taken does not tell which
/// password was typed.
pub fn open_either(vault_path: &Path, password: &str, secret: &SecretKey) -> Result<Opened, VaultError> {
    let real = Vault::open(vault_path, password, secret);
    if !has_decoy(vault_path) {
        return real.map(|vault| Opened { vault, is_decoy: false });
    }
    let fake = Vault::open(&decoy_path(vault_path), password, secret);
    match (real, fake) {
        (Ok(vault), _) => Ok(Opened { vault, is_decoy: false }),
        (Err(VaultError::Decrypt), Ok(vault)) => Ok(Opened { vault, is_decoy: true }),
        (Err(e), _) => Err(e),
    }
}

/// Create the decoy vault. `duress_password` must differ from the real master password,
/// which the caller proves by passing the already-open real vault's check below.
pub fn create_decoy(
    vault_path: &Path,
    duress_password: &str,
    real_password: &str,
    secret: &SecretKey,
    kdf: KdfParams,
) -> Result<Vault, VaultError> {
    if duress_password == real_password {
        return Err(VaultError::Format("duress password must differ from the master password"));
    }
    let real = Vault::open(vault_path, real_password, secret)?;
    let mut v = Vault::create(&decoy_path(vault_path), duress_password, secret, kdf)?;
    // Same unlock 2FA as the real vault: a missing 2FA step would give the decoy away.
    v.unlock_totp = real.unlock_totp.clone();
    v.save()?;
    Ok(v)
}

pub fn remove_decoy(vault_path: &Path) -> Result<(), VaultError> {
    match std::fs::remove_file(decoy_path(vault_path)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_cost_kib: 8, t_cost: 1, p_cost: 1 };

    #[test]
    fn master_opens_real_duress_opens_decoy_wrong_opens_nothing() {
        let d = std::env::temp_dir().join(format!("vylt-decoy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let vp = d.join("vault.svault");
        let sk = SecretKey::generate().unwrap();

        let mut real = Vault::create(&vp, "real-master", &sk, FAST).unwrap();
        let mut e = crate::vault::Entry::blank();
        e.site = "bank".into();
        real.entries.push(e);
        real.save().unwrap();

        assert!(create_decoy(&vp, "real-master", "real-master", &sk, FAST).is_err());
        let mut fake = create_decoy(&vp, "duress-pw", "real-master", &sk, FAST).unwrap();
        let mut f = crate::vault::Entry::blank();
        f.site = "forum".into();
        fake.entries.push(f);
        fake.save().unwrap();

        let a = open_either(&vp, "real-master", &sk).unwrap();
        assert!(!a.is_decoy);
        assert_eq!(a.vault.entries[0].site, "bank");

        let b = open_either(&vp, "duress-pw", &sk).unwrap();
        assert!(b.is_decoy);
        assert_eq!(b.vault.entries[0].site, "forum");

        assert!(matches!(open_either(&vp, "nope", &sk), Err(VaultError::Decrypt)));

        // The decoy inherits the unlock 2FA of the real vault at creation.
        remove_decoy(&vp).unwrap();
        real.unlock_totp = Some(zeroize::Zeroizing::new("JBSWY3DPEHPK3PXP".into()));
        real.save().unwrap();
        create_decoy(&vp, "duress-pw", "real-master", &sk, FAST).unwrap();
        let c = open_either(&vp, "duress-pw", &sk).unwrap();
        assert!(c.is_decoy && c.vault.unlock_totp.as_deref().map(|s| s.as_str()) == Some("JBSWY3DPEHPK3PXP"));
        assert!(create_decoy(&vp, "other", "wrong-master", &sk, FAST).is_err(), "the real password is checked");

        remove_decoy(&vp).unwrap();
        assert!(matches!(open_either(&vp, "duress-pw", &sk), Err(VaultError::Decrypt)));
        let _ = std::fs::remove_dir_all(&d);
    }
}
