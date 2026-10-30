//! Per-entry code gate (4-digit PIN, 6-digit PIN or alphanumeric code).
//!
//! Only a salted Argon2id verifier is stored. This is an in-session gate (shoulder-surfing,
//! unattended unlocked PC); the entry data itself lives in the already-unlocked vault.
//! For cryptographic separation use a hidden category (see `hidden`).

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockKind {
    Pin4,
    Pin6,
    Pin8,
    Alpha,
}

impl LockKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pin4 => "Code PIN \u{e0} 4 chiffres",
            Self::Pin6 => "Code PIN \u{e0} 6 chiffres",
            Self::Pin8 => "Code PIN \u{e0} 8 chiffres",
            Self::Alpha => "Code alphanum\u{e9}rique (6 \u{e0} 32 caract\u{e8}res)",
        }
    }

    /// Why `code` is not acceptable for this kind, if it isn't.
    pub fn check_format(self, code: &str) -> Result<(), &'static str> {
        let n = code.chars().count();
        match self {
            Self::Pin4 if n == 4 && code.chars().all(|c| c.is_ascii_digit()) => Ok(()),
            Self::Pin4 => Err("4 chiffres exactement."),
            Self::Pin6 if n == 6 && code.chars().all(|c| c.is_ascii_digit()) => Ok(()),
            Self::Pin6 => Err("6 chiffres exactement."),
            Self::Pin8 if n == 8 && code.chars().all(|c| c.is_ascii_digit()) => Ok(()),
            Self::Pin8 => Err("8 chiffres exactement."),
            Self::Alpha if (6..=32).contains(&n) && code.chars().all(|c| c.is_ascii_alphanumeric()) => Ok(()),
            Self::Alpha => Err("6 \u{e0} 32 lettres ou chiffres."),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntryLock {
    pub kind: LockKind,
    salt: [u8; 16],
    hash: [u8; 32],
    /// Wrong codes in a row, kept in the vault: closing the keypad or restarting does not reset it.
    #[serde(default)]
    pub fails: u32,
    #[serde(default)]
    pub retry_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Attempt {
    Ok,
    Wrong,
    /// Too many wrong codes: seconds left before the next try.
    Wait(u64),
}

const FREE_TRIES: u32 = 3;
const MAX_DELAY_SECS: u64 = 15 * 60;

fn digest(code: &str, salt: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
    let params = Params::new(19 * 1024, 2, 1, Some(32)).ok()?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(code.as_bytes(), salt, &mut *out).ok()?;
    Some(out)
}

impl EntryLock {
    pub fn new(kind: LockKind, code: &str) -> Result<Self, &'static str> {
        kind.check_format(code)?;
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|_| "RNG indisponible")?;
        let hash = digest(code, &salt).ok_or("d\u{e9}rivation impossible")?;
        Ok(Self { kind, salt, hash: *hash, fails: 0, retry_at: 0 })
    }

    /// Constant-time comparison of the derived verifier.
    pub fn check(&self, code: &str) -> bool {
        let Some(h) = digest(code, &self.salt) else { return false };
        h.iter().zip(self.hash.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }

    /// Counted check: after 3 wrong codes in a row, 30 s before the next try, doubling up to
    /// 15 min. The caller saves the vault afterwards so the count survives a restart.
    pub fn attempt(&mut self, code: &str, now: u64) -> Attempt {
        if now < self.retry_at {
            return Attempt::Wait(self.retry_at - now);
        }
        if self.check(code) {
            self.fails = 0;
            self.retry_at = 0;
            return Attempt::Ok;
        }
        self.fails = self.fails.saturating_add(1);
        if self.fails >= FREE_TRIES {
            self.retry_at = now + (30u64 << (self.fails - FREE_TRIES).min(10)).min(MAX_DELAY_SECS);
        }
        Attempt::Wrong
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_rules() {
        assert!(LockKind::Pin4.check_format("1234").is_ok());
        assert!(LockKind::Pin4.check_format("123").is_err());
        assert!(LockKind::Pin4.check_format("12a4").is_err());
        assert!(LockKind::Pin6.check_format("123456").is_ok());
        assert!(LockKind::Pin6.check_format("1234567").is_err());
        assert!(LockKind::Pin8.check_format("12345678").is_ok());
        assert!(LockKind::Pin8.check_format("123456").is_err());
        assert!(LockKind::Pin8.check_format("1234567a").is_err());
        assert!(LockKind::Alpha.check_format("abcDEF12").is_ok());
        assert!(LockKind::Alpha.check_format("abc").is_err());
        assert!(LockKind::Alpha.check_format("abc def!").is_err());
    }

    #[test]
    fn check_accepts_only_right_code() {
        let l = EntryLock::new(LockKind::Pin6, "424242").unwrap();
        assert!(l.check("424242"));
        assert!(!l.check("424243"));
        assert!(!l.check(""));
        assert!(EntryLock::new(LockKind::Pin4, "12").is_err());
    }

    #[test]
    fn wrong_codes_add_a_delay_that_reopening_does_not_reset() {
        let mut l = EntryLock::new(LockKind::Pin6, "424242").unwrap();
        let t = 1_000_000;
        assert_eq!(l.attempt("000000", t), Attempt::Wrong);
        assert_eq!(l.attempt("000001", t), Attempt::Wrong);
        assert_eq!(l.attempt("000002", t), Attempt::Wrong);
        assert_eq!(l.attempt("424242", t + 1), Attempt::Wait(29), "even the right code waits");
        // Saved and reloaded (as when the vault is reopened): the count is still there.
        let mut l: EntryLock = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(l.attempt("000003", t + 30), Attempt::Wrong);
        assert_eq!(l.retry_at, t + 30 + 60, "the delay doubles");
        assert_eq!(l.attempt("424242", t + 90), Attempt::Ok);
        assert_eq!((l.fails, l.retry_at), (0, 0));
        let old: EntryLock = serde_json::from_str(r#"{"kind":"Pin6","salt":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#).unwrap();
        assert_eq!(old.fails, 0);
    }
}
