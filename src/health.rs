//! Password health report: weak, reused and old passwords.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::vault::Entry;

pub const WEAK_BITS: f32 = 45.0;
pub const OLD_AFTER_SECS: u64 = 365 * 24 * 3600;

const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";

/// Rough entropy estimate in bits (length * log2(alphabet size)); ignores dictionary patterns.
pub fn bits(p: &str) -> f32 {
    let mut pool = 0u32;
    if p.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if p.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if p.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if p.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += SYMBOLS.len() as u32 + 8;
    }
    if pool == 0 { 0.0 } else { p.chars().count() as f32 * (pool as f32).log2() }
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
        if bits(&e.password) < WEAK_BITS {
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
    fn bits_grow_with_length_and_alphabet() {
        assert!(bits("aaaa") < bits("aaaaaaaa"));
        assert!(bits("aaaaaaaa") < bits("aAaAaAa1"));
        assert_eq!(bits(""), 0.0);
    }
}
