//! Password health report: weak, reused and old passwords.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::vault::Entry;

pub const OLD_AFTER_SECS: u64 = 365 * 24 * 3600;

/// Below this score a password is treated as weak. zxcvbn's scores: 0 too guessable, 1 very
/// guessable, 2 somewhat guessable, 3 safely unguessable, 4 very unguessable.
pub const WEAK_SCORE: u8 = 3;

/// Real strength estimate (0..=4) via zxcvbn: it accounts for repeats ("aaaa…"), sequences
/// ("azerty", "1234"), common words, dates and l33t — not just length and alphabet size. Empty is
/// 0, and very long inputs are capped (they already max out) to keep the estimate quick.
pub fn score(p: &str) -> u8 {
    if p.is_empty() {
        return 0;
    }
    let capped: String = p.chars().take(64).collect();
    u8::from(zxcvbn::zxcvbn(&capped, &[]).score())
}

/// A password whose estimated strength is below `WEAK_SCORE`.
pub fn is_weak(p: &str) -> bool {
    score(p) < WEAK_SCORE
}

#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub weak: Vec<usize>,
    /// Groups of entries sharing the same password (each group has 2+ indexes).
    pub reused: Vec<Vec<usize>>,
    pub old: Vec<usize>,
    pub empty: Vec<usize>,
    /// 0..=100, share of entries without any issue.
    pub score: u8,
}

pub fn analyze(entries: &[Entry], now: u64) -> Report {
    let mut r = Report::default();
    let mut by_hash: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        if e.password.is_empty() {
            r.empty.push(i);
            continue;
        }
        if is_weak(&e.password) {
            r.weak.push(i);
        }
        if e.updated != 0 && now.saturating_sub(e.updated) > OLD_AFTER_SECS {
            r.old.push(i);
        }
        by_hash.entry(Sha256::digest(e.password.as_bytes()).into()).or_default().push(i);
    }
    r.reused = by_hash.into_values().filter(|g| g.len() > 1).collect();
    r.reused.sort();

    let mut bad: Vec<usize> = r.weak.iter().chain(&r.old).chain(&r.empty).chain(r.reused.iter().flatten()).copied().collect();
    bad.sort_unstable();
    bad.dedup();
    r.score = if entries.is_empty() { 100 } else { (100 - bad.len() * 100 / entries.len()) as u8 };
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(site: &str, pw: &str, updated: u64) -> Entry {
        let mut x = Entry::blank();
        x.site = site.into();
        x.password = pw.into();
        x.updated = updated;
        x
    }

    #[test]
    fn finds_weak_reused_old_and_empty() {
        let now = 10 * OLD_AFTER_SECS;
        let list = vec![
            e("a", "abc123", now),                              // weak
            e("b", "Str0ng!Passw0rd#2026xyz", now),             // fine
            e("c", "Str0ng!Passw0rd#2026xyz", now),             // reused with b
            e("d", "Another#Long-Unique9Pass", 1),              // old
            e("e", "", now),                                    // empty
            e("f", "Unknown#Age-Very9Long!pw", 0),              // unknown age: not old
        ];
        let r = analyze(&list, now);
        assert_eq!(r.weak, vec![0]);
        assert_eq!(r.reused, vec![vec![1, 2]]);
        assert_eq!(r.old, vec![3]);
        assert_eq!(r.empty, vec![4]);
        assert_eq!(r.score, 17); // a, b, c, d, e flagged out of 6 -> 100 - 83
    }

    #[test]
    fn empty_vault_is_perfect() {
        assert_eq!(analyze(&[], 0).score, 100);
    }

    #[test]
    fn score_sees_through_repeats_and_patterns() {
        // The whole point: a long run of one character is NOT strong.
        assert!(is_weak(&"a".repeat(150)), "150 identical chars must be weak");
        assert!(is_weak("azertyuiop"), "keyboard sequence is weak");
        assert!(is_weak("Password123"), "a common word with digits is weak");
        assert_eq!(score(""), 0);
        // A genuinely unpredictable passphrase scores high.
        assert!(!is_weak("Str0ng!Passw0rd#2026xyz"));
        assert!(score("7h!Kq2$wVdLm9@zF") >= WEAK_SCORE);
    }
}
