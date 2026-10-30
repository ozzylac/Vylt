//! Password generator: uniform sampling (rejection) from the OS CSPRNG.

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

fn below(n: usize) -> usize {
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("OS RNG unavailable");
        let v = u32::from_le_bytes(b);
        if v < zone {
            return (v % n) as usize;
        }
    }
}

/// At least one char of each enabled class, shuffled (Fisher-Yates).
pub fn password(len: usize, symbols: bool) -> String {
    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if symbols {
        classes.push(SYMBOLS);
    }
    let all: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();
    let mut out: Vec<u8> = classes.iter().map(|c| c[below(c.len())]).collect();
    while out.len() < len.max(classes.len()) {
        out.push(all[below(all.len())]);
    }
    for i in (1..out.len()).rev() {
        out.swap(i, below(i + 1));
    }
    String::from_utf8(out).expect("ascii")
}

pub use vylt::health::bits;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_length_and_all_classes() {
        for _ in 0..200 {
            let p = password(16, true);
            assert_eq!(p.len(), 16);
            assert!(p.bytes().any(|b| LOWER.contains(&b)));
            assert!(p.bytes().any(|b| UPPER.contains(&b)));
            assert!(p.bytes().any(|b| DIGITS.contains(&b)));
            assert!(p.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }
}
