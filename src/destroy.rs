//! Irreversible erase passwords.
//!
//! * A per-profile destruction password erases that profile when typed at sign-in.
//! * A global key, set identically by two different profiles, erases every profile.
//!
//! Only salted Argon2id verifiers are stored (in the app config, outside the vaults, since they
//! must be checked before any vault can be opened). Erasing overwrites files with zeros, then
//! removes them; on SSDs the controller may keep old blocks, so this is best effort.

use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use crate::decoy;
use crate::import::shred;

pub const MIN_CHARS: usize = 12;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verifier {
    salt: [u8; 16],
    hash: [u8; 32],
}

fn digest(secret: &str, salt: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
    let params = Params::new(32 * 1024, 2, 1, Some(32)).ok()?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(secret.as_bytes(), salt, &mut *out).ok()?;
    Some(out)
}

impl Verifier {
    pub fn new(secret: &str) -> Result<Self, &'static str> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|_| "rng")?;
        let hash = digest(secret, &salt).ok_or("kdf")?;
        Ok(Self { salt, hash: *hash })
    }

    /// Constant-time comparison of the derived verifier.
    pub fn check(&self, input: &str) -> bool {
        if input.is_empty() {
            return false;
        }
        let Some(h) = digest(input, &self.salt) else { return false };
        h.iter().zip(self.hash.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
    }
}

/// A profile's destruction password: long enough, and never the master password itself.
pub fn check_destruct_password(candidate: &str, master: &str) -> Result<(), &'static str> {
    if candidate.chars().count() < MIN_CHARS {
        return Err("too short");
    }
    if candidate == master {
        return Err("same as master");
    }
    Ok(())
}

/// The shared key: at least 12 ASCII letters/digits, with at least one of each.
pub fn check_global_key(key: &str) -> Result<(), &'static str> {
    let ok = key.chars().count() >= MIN_CHARS
        && key.chars().all(|c| c.is_ascii_alphanumeric())
        && key.chars().any(|c| c.is_ascii_alphabetic())
        && key.chars().any(|c| c.is_ascii_digit());
    if ok { Ok(()) } else { Err("invalid key") }
}

/// First half of the two-person activation: which profile entered the key, and the key's verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pending {
    /// Stable id (folder) of the profile that entered the key first — not its display name.
    pub profile: String,
    pub verifier: Verifier,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Arm {
    /// First profile recorded; a different profile must now enter the same key.
    Waiting,
    /// Second, different profile entered the same key: the global erase is active.
    Armed,
    /// A second profile entered a different key; nothing changed.
    Mismatch,
    /// The same profile tried to confirm its own key; nothing changed.
    SameProfile,
}

/// Two-person arming. `global` becomes `Some` only when two different profiles gave the same key.
pub fn arm(
    global: &mut Option<Verifier>,
    pending: &mut Option<Pending>,
    profile: &str,
    key: &str,
) -> Result<Arm, &'static str> {
    check_global_key(key)?;
    match pending {
        None => {
            *pending = Some(Pending { profile: profile.to_owned(), verifier: Verifier::new(key)? });
            Ok(Arm::Waiting)
        }
        Some(p) if p.profile == profile => Ok(Arm::SameProfile),
        Some(p) if p.verifier.check(key) => {
            *global = Some(p.verifier.clone());
            *pending = None;
            Ok(Arm::Armed)
        }
        Some(_) => Ok(Arm::Mismatch),
    }
}

/// What happens right after a destruction password erased a profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actions {
    pub show_message: bool,
    pub title: String,
    pub body: String,
    pub run: bool,
    /// Program started directly (no shell), with `args` split like a command line.
    pub program: String,
    pub args: String,
    pub close_app: bool,
}

/// `Actions` sealed with a key derived from the destruction password: unreadable and
/// tamper-evident without it, so editing config.json cannot inject a command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedActions {
    salt: [u8; 16],
    nonce: [u8; 24],
    ct: Vec<u8>,
}

const ACTIONS_AAD: &[u8] = b"vylt destruction actions v1";

pub fn seal_actions(a: &Actions, password: &str) -> Result<SealedActions, &'static str> {
    let (mut salt, mut nonce) = ([0u8; 16], [0u8; 24]);
    getrandom::fill(&mut salt).map_err(|_| "rng")?;
    getrandom::fill(&mut nonce).map_err(|_| "rng")?;
    let key = digest(password, &salt).ok_or("kdf")?;
    let plain = Zeroizing::new(serde_json::to_vec(a).map_err(|_| "serialize")?);
    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt((&nonce).into(), Payload { msg: &plain, aad: ACTIONS_AAD })
        .map_err(|_| "encrypt")?;
    Ok(SealedActions { salt, nonce, ct })
}

/// `None` for a wrong password or a modified blob.
pub fn open_actions(s: &SealedActions, password: &str) -> Option<Actions> {
    let key = digest(password, &s.salt)?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into()).decrypt((&s.nonce).into(), Payload { msg: &s.ct, aad: ACTIONS_AAD }).ok()?,
    );
    serde_json::from_slice(&plain).ok()
}

/// Split a command line into arguments: whitespace separates, double quotes group.
pub fn split_args(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// Files that make up one profile.
pub struct Targets<'a> {
    pub vault: &'a Path,
    pub key: Option<&'a Path>,
}

/// Overwrite and remove the decoy vault, the vault and the secret key. Returns how many files went.
/// Only files that really are Vylt files are touched: paths come from config.json, which
/// anyone with access to the disk (or to a portable USB drive) could have edited.
pub fn wipe_profile(t: &Targets) -> usize {
    let mut files: Vec<PathBuf> = [decoy::decoy_path(t.vault), t.vault.to_path_buf()].into_iter().filter(|f| crate::vault::is_vault_file(f)).collect();
    if let Some(k) = t.key.filter(|k| crate::vault::is_key_file(k)) {
        files.push(k.to_path_buf());
    }
    let mut n = 0;
    for f in files {
        if shred(&f).is_ok() {
            n += 1;
        }
    }
    if let Some(dir) = t.vault.parent() {
        let _ = fs::remove_dir(dir); // only succeeds when empty
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "Alpha2026Bravo77";

    #[test]
    fn actions_seal_roundtrip_and_tamper() {
        let a = Actions { show_message: true, title: "T".into(), body: "B".into(), run: true, program: "C:/x.exe".into(), args: "--a".into(), close_app: true };
        let sealed = seal_actions(&a, KEY).unwrap();
        assert_eq!(open_actions(&sealed, KEY), Some(a.clone()));
        assert_eq!(open_actions(&sealed, "Alpha2026Bravo78"), None);
        let mut bad = sealed.clone();
        bad.ct[0] ^= 1;
        assert_eq!(open_actions(&bad, KEY), None, "a modified blob is rejected");
        // the program path does not appear in clear
        let json = serde_json::to_string(&sealed).unwrap();
        assert!(!json.contains("x.exe"));
    }

    #[test]
    fn split_args_handles_quotes() {
        assert_eq!(split_args(r#"--profil "mon profil" -v"#), vec!["--profil", "mon profil", "-v"]);
        assert_eq!(split_args("  a   b "), vec!["a", "b"]);
        assert_eq!(split_args(r#""" x"#), vec!["", "x"]);
        assert!(split_args("").is_empty());
    }

    #[test]
    fn verifier_accepts_only_the_exact_secret() {
        let v = Verifier::new(KEY).unwrap();
        assert!(v.check(KEY));
        assert!(!v.check("Alpha2026Bravo78"));
        assert!(!v.check(""));
    }

    #[test]
    fn password_rules() {
        assert!(check_destruct_password("a-long-destruct-pw", "master-pw-123456").is_ok());
        assert!(check_destruct_password("short", "master").is_err());
        assert!(check_destruct_password("same-as-the-master", "same-as-the-master").is_err());
        assert!(check_global_key(KEY).is_ok());
        assert!(check_global_key("onlyletterskey").is_err()); // no digit
        assert!(check_global_key("1234567890123").is_err()); // no letter
        assert!(check_global_key("Short1").is_err());
        assert!(check_global_key("Alpha2026 Bravo77").is_err()); // not alphanumeric
    }

    #[test]
    fn two_different_profiles_must_enter_the_same_key() {
        let (mut global, mut pending) = (None, None);
        assert_eq!(arm(&mut global, &mut pending, "alice", KEY), Ok(Arm::Waiting));
        assert!(global.is_none() && pending.is_some());

        // The same profile cannot confirm itself.
        assert_eq!(arm(&mut global, &mut pending, "alice", KEY), Ok(Arm::SameProfile));
        assert!(global.is_none());

        // A different profile with another key does not arm it.
        assert_eq!(arm(&mut global, &mut pending, "bob", "Charlie2026Delta1"), Ok(Arm::Mismatch));
        assert!(global.is_none() && pending.is_some());

        // The same key from a different profile arms it.
        assert_eq!(arm(&mut global, &mut pending, "bob", KEY), Ok(Arm::Armed));
        assert!(global.as_ref().unwrap().check(KEY));
        assert!(pending.is_none());
    }

    #[test]
    fn arming_rejects_weak_keys() {
        let (mut global, mut pending) = (None, None);
        assert!(arm(&mut global, &mut pending, "alice", "weak").is_err());
        assert!(pending.is_none());
    }

    #[test]
    fn wipe_profile_removes_every_file_and_the_empty_folder() {
        let d = std::env::temp_dir().join(format!("vylt-wipe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let pdir = d.join("p");
        fs::create_dir_all(&pdir).unwrap();
        let (vault, key) = (pdir.join("vault.svault"), pdir.join("secret.key"));
        let fake = |n: usize| [b"SVLT\x01".as_slice(), &vec![7u8; n]].concat();
        fs::write(&vault, fake(5000)).unwrap();
        fs::write(decoy::decoy_path(&vault), fake(100)).unwrap();
        fs::write(&key, [9u8; 32]).unwrap();
        let outside = d.join("keep.txt");
        fs::write(&outside, b"unrelated").unwrap();

        let n = wipe_profile(&Targets { vault: &vault, key: Some(&key) });
        assert_eq!(n, 3);
        assert!(!vault.exists() && !key.exists() && !decoy::decoy_path(&vault).exists());
        assert!(!pdir.exists(), "empty profile folder is removed");
        assert!(outside.exists(), "unrelated files are never touched");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn wipe_without_key_and_missing_files_is_safe() {
        let d = std::env::temp_dir().join(format!("vylt-wipe2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let vault = d.join("vault.svault");
        assert_eq!(wipe_profile(&Targets { vault: &vault, key: None }), 0);
        assert!(!d.exists(), "the empty folder is removed even when there was nothing to erase");
        fs::create_dir_all(&d).unwrap();
        fs::write(&vault, b"SVLT\x01x").unwrap();
        assert_eq!(wipe_profile(&Targets { vault: &vault, key: None }), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn wipe_refuses_files_that_are_not_vylt_files() {
        // config.json can be edited by anyone with disk access: a profile pointing at a document
        // must not get that document shredded.
        let d = std::env::temp_dir().join(format!("vylt-wipe3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let (doc, cache, notes) = (d.join("report.docx"), d.join("vault.cache"), d.join("notes.txt"));
        fs::write(&doc, b"PK\x03\x04 a document").unwrap();
        fs::write(&cache, b"some other program's cache").unwrap();
        fs::write(&notes, vec![1u8; 33]).unwrap();
        assert_eq!(wipe_profile(&Targets { vault: &doc, key: Some(&notes) }), 0);
        assert!(doc.exists() && cache.exists() && notes.exists());
        let _ = fs::remove_dir_all(&d);
    }
}
