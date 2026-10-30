//! TOTP helpers (RFC 6238) on top of `totp-rs`, plus QR rendering and decoding.

use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Builder, Secret, Totp};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Accepts an `otpauth://` URL or a bare base32 key (spaces/dashes tolerated). Parameters that
/// authenticator apps never use (period 0, 10+ digits…) are refused: they would crash `generate`.
pub fn parse(input: &str) -> Option<Totp> {
    let s = input.trim();
    if s.starts_with("otpauth://") {
        return Totp::from_url_unchecked(s).ok().filter(|t| (6..=8).contains(&t.digits()) && (5..=300).contains(&t.step()));
    }
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_uppercase();
    let secret = Secret::try_from_base32(clean).ok()?;
    Some(Builder::new().with_secret(secret).build_noncompliant())
}

pub struct Live {
    pub code: String,
    pub ttl: u64,
    pub period: u64,
}

pub fn live(input: &str) -> Option<Live> {
    let t = parse(input)?;
    let tok = t.generate(now()).to_string();
    let period = t.step();
    Some(Live { code: tok, ttl: period - now() % period, period })
}

/// Label suggested by an otpauth URL (issuer / account), if any.
pub fn suggested_label(input: &str) -> Option<String> {
    let t = parse(input)?;
    let (i, a) = (t.issuer().unwrap_or(""), t.account_name());
    match (i.is_empty(), a.is_empty()) {
        (true, true) => None,
        (false, true) => Some(i.to_owned()),
        (true, false) => Some(a.to_owned()),
        (false, false) => Some(format!("{i} ({a})")),
    }
}

/// Fresh 160-bit key for the unlock 2FA, base32-encoded.
pub fn new_unlock_key() -> String {
    let mut b = [0u8; 20];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    let s = Secret::from(b.to_vec()).to_base32();
    b.fill(0);
    s
}

/// Provisioning URI scanned by Google/Microsoft Authenticator, Authy, 2FAS, Aegis, etc.
pub fn provisioning_uri(key_b32: &str, account: &str) -> Option<String> {
    let secret = Secret::try_from_base32(key_b32).ok()?;
    let account: String = account.chars().filter(|c| *c != ':').collect();
    Builder::new()
        .with_secret(secret)
        .with_issuer(Some("Vylt"))
        .with_account_name(if account.is_empty() { "profil".to_owned() } else { account })
        .build_noncompliant()
        .to_url()
        .ok()
}

/// Accepts the previous/current/next 30 s window (clock drift).
pub fn verify(key_b32: &str, code: &str) -> bool {
    verify_step(key_b32, code).is_some()
}

/// Like `verify`, returning the matched time step so that callers can refuse a replayed code.
pub fn verify_step(key_b32: &str, code: &str) -> Option<u64> {
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    parse(key_b32)?.check(&code, now())
}

/// QR modules as (width, dark flags), row-major.
pub fn qr_matrix(data: &str) -> Option<(usize, Vec<bool>)> {
    let qr = qrcode::QrCode::new(data.as_bytes()).ok()?;
    let w = qr.width();
    Some((w, qr.to_colors().into_iter().map(|c| c == qrcode::Color::Dark).collect()))
}

/// Decode the first QR code found in an RGBA image (e.g. a screenshot from the clipboard).
pub fn decode_qr_rgba(w: usize, h: usize, rgba: &[u8]) -> Option<String> {
    // A zero dimension made `w * h * 4 == 0`, so the old guard passed and rqrr then indexed OOB.
    if w == 0 || h == 0 || rgba.len() < w.saturating_mul(h).saturating_mul(4) {
        return None;
    }
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
        let i = (y * w + x) * 4;
        ((rgba[i] as u32 * 299 + rgba[i + 1] as u32 * 587 + rgba[i + 2] as u32 * 114) / 1000) as u8
    });
    img.detect_grids().into_iter().find_map(|g| g.decode().ok().map(|(_, c)| c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_dimension_qr_image_is_rejected_not_panicked() {
        assert!(decode_qr_rgba(0, 4, &[]).is_none());
        assert!(decode_qr_rgba(4, 0, &[]).is_none());
        assert!(decode_qr_rgba(0, 0, &[]).is_none());
        assert!(decode_qr_rgba(2, 2, &[0u8; 3]).is_none(), "too few bytes");
    }

    // RFC 6238 test vector (SHA-1, secret "12345678901234567890", T=59 -> 94287082; last 6 digits 287082).
    #[test]
    fn rfc6238_vector() {
        let b32 = Secret::from(b"12345678901234567890".to_vec()).to_base32();
        let t = parse(&b32).unwrap();
        assert_eq!(t.generate(59).to_string(), "287082");
    }

    #[test]
    fn unlock_roundtrip_and_uri() {
        let k = new_unlock_key();
        let uri = provisioning_uri(&k, "alice").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        let t = parse(&uri).unwrap();
        let code = t.generate(now()).to_string();
        assert!(verify(&k, &code));
        assert!(!verify(&k, "000000") || code == "000000");
    }

    #[test]
    fn qr_roundtrip() {
        let uri = provisioning_uri(&new_unlock_key(), "bob").unwrap();
        let (w, dark) = qr_matrix(&uri).unwrap();
        let scale = 6;
        let q = 4;
        let side = (w + 2 * q) * scale;
        let mut rgba = vec![255u8; side * side * 4];
        for y in 0..w {
            for x in 0..w {
                if dark[y * w + x] {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let i = (((y + q) * scale + dy) * side + (x + q) * scale + dx) * 4;
                            rgba[i..i + 3].fill(0);
                        }
                    }
                }
            }
        }
        assert_eq!(decode_qr_rgba(side, side, &rgba).as_deref(), Some(uri.as_str()));
    }

    #[test]
    fn crafted_otpauth_parameters_are_refused() {
        for bad in [
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=255",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=100000",
        ] {
            assert!(parse(bad).is_none(), "{bad}");
            assert!(live(bad).is_none() && !verify(bad, "123456"), "{bad}");
        }
        assert!(live("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8&period=60").is_some_and(|l| l.code.len() == 8 && l.period == 60));
    }
}
