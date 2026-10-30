//! WebAuthn passkeys stored in the vault: ES256 (P-256) credentials, "none" attestation.
//! The private key never leaves this process; callers get authenticator data and signatures.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Identifies Vylt as the authenticator model (random, fixed).
pub const AAGUID: [u8; 16] = [0x5e, 0x1c, 0x9a, 0x47, 0x0b, 0xd2, 0x4f, 0x6e, 0x93, 0x81, 0x2c, 0x75, 0xe4, 0x0a, 0xb8, 0x3d];
/// COSE algorithm identifier of ES256.
pub const ES256: i64 = -7;

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
/// Backup eligible / backed up: the vault can be transferred to another PC.
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

#[derive(Debug)]
pub enum PasskeyError {
    Rng,
    Key,
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PasskeyError::Rng => "random generator unavailable",
            PasskeyError::Key => "invalid passkey private key",
        })
    }
}

impl PasskeyError {
    /// Stable diagnostic code shown to the user (catalogue in src/errcode.rs).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Rng => "SV-E31",
            Self::Key => "SV-E30",
        }
    }
}

impl std::error::Error for PasskeyError {}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Passkey {
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: String,
    pub user_name: String,
    #[serde(default)]
    pub user_display: String,
    #[serde(with = "b64")]
    pub user_handle: Vec<u8>,
    #[serde(with = "b64")]
    pub credential_id: Vec<u8>,
    /// P-256 private scalar.
    #[serde(with = "b64")]
    private_key: Vec<u8>,
    pub created: u64,
    #[serde(default)]
    pub last_used: u64,
}

impl Passkey {
    pub fn generate(rp_id: &str, rp_name: &str, user_name: &str, user_display: &str, user_handle: &[u8], now: u64) -> Result<Self, PasskeyError> {
        let mut credential_id = vec![0u8; 32];
        getrandom::fill(&mut credential_id).map_err(|_| PasskeyError::Rng)?;
        let private_key = loop {
            let mut k = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut *k).map_err(|_| PasskeyError::Rng)?;
            if SigningKey::from_slice(&*k).is_ok() {
                break k.to_vec();
            }
        };
        Ok(Self {
            rp_id: rp_id.to_owned(),
            rp_name: rp_name.to_owned(),
            user_name: user_name.to_owned(),
            user_display: user_display.to_owned(),
            user_handle: user_handle.to_vec(),
            credential_id,
            private_key,
            created: now,
            last_used: 0,
        })
    }

    fn signing_key(&self) -> Result<SigningKey, PasskeyError> {
        SigningKey::from_slice(&self.private_key).map_err(|_| PasskeyError::Key)
    }

    /// Uncompressed public point (x, y).
    fn point(&self) -> Result<([u8; 32], [u8; 32]), PasskeyError> {
        let sk = self.signing_key()?;
        let p = sk.verifying_key().to_sec1_point(false);
        let b = p.as_bytes();
        if b.len() != 65 {
            return Err(PasskeyError::Key);
        }
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        x.copy_from_slice(&b[1..33]);
        y.copy_from_slice(&b[33..65]);
        Ok((x, y))
    }

    /// COSE_Key of the public key (EC2, ES256, P-256), CTAP2 canonical order.
    pub fn public_cose(&self) -> Result<Vec<u8>, PasskeyError> {
        let (x, y) = self.point()?;
        let mut c = Vec::with_capacity(77);
        cbor_head(&mut c, 5, 5);
        cbor_int(&mut c, 1);
        cbor_int(&mut c, 2); // kty: EC2
        cbor_int(&mut c, 3);
        cbor_int(&mut c, ES256);
        cbor_int(&mut c, -1);
        cbor_int(&mut c, 1); // crv: P-256
        cbor_int(&mut c, -2);
        cbor_bytes(&mut c, &x);
        cbor_int(&mut c, -3);
        cbor_bytes(&mut c, &y);
        Ok(c)
    }

    /// SubjectPublicKeyInfo DER (what `AuthenticatorAttestationResponse.getPublicKey()` returns).
    pub fn public_spki(&self) -> Result<Vec<u8>, PasskeyError> {
        let sk = self.signing_key()?;
        Ok(sk.verifying_key().to_public_key_der().map_err(|_| PasskeyError::Key)?.as_bytes().to_vec())
    }

    /// Authenticator data for a registration (with attested credential data).
    pub fn registration_auth_data(&self, uv: bool) -> Result<Vec<u8>, PasskeyError> {
        let mut d = auth_data_head(&self.rp_id, flags(uv) | FLAG_AT);
        d.extend_from_slice(&AAGUID);
        d.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        d.extend_from_slice(&self.credential_id);
        d.extend_from_slice(&self.public_cose()?);
        Ok(d)
    }

    pub fn assertion_auth_data(&self, uv: bool) -> Vec<u8> {
        auth_data_head(&self.rp_id, flags(uv))
    }

    /// ECDSA-SHA256 signature (DER) over `auth_data || client_data_hash`.
    pub fn sign(&self, auth_data: &[u8], client_data_hash: &[u8]) -> Result<Vec<u8>, PasskeyError> {
        let sk = self.signing_key()?;
        let mut msg = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(client_data_hash);
        let sig: DerSignature = sk.sign(&msg);
        Ok(sig.as_bytes().to_vec())
    }
}

fn flags(uv: bool) -> u8 {
    FLAG_UP | FLAG_BE | FLAG_BS | if uv { FLAG_UV } else { 0 }
}

/// rpIdHash || flags || signCount (always 0: the vault may exist in several places).
fn auth_data_head(rp_id: &str, flags: u8) -> Vec<u8> {
    let mut d = Vec::with_capacity(37 + 120);
    d.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    d.push(flags);
    d.extend_from_slice(&0u32.to_be_bytes());
    d
}

/// `{"fmt": "none", "attStmt": {}, "authData": …}`, canonical key order.
pub fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(auth_data.len() + 32);
    cbor_head(&mut c, 5, 3);
    cbor_text(&mut c, "fmt");
    cbor_text(&mut c, "none");
    cbor_text(&mut c, "attStmt");
    cbor_head(&mut c, 5, 0);
    cbor_text(&mut c, "authData");
    cbor_bytes(&mut c, auth_data);
    c
}

/// CTAP2 `authenticatorGetInfo` describing Vylt (given to Windows when registering).
pub fn authenticator_info() -> Vec<u8> {
    let mut c = Vec::with_capacity(96);
    cbor_head(&mut c, 5, 5);
    cbor_int(&mut c, 1);
    cbor_head(&mut c, 4, 2);
    cbor_text(&mut c, "FIDO_2_0");
    cbor_text(&mut c, "FIDO_2_1");
    cbor_int(&mut c, 3);
    cbor_bytes(&mut c, &AAGUID);
    cbor_int(&mut c, 4);
    cbor_head(&mut c, 5, 3);
    for k in ["rk", "up", "uv"] {
        cbor_text(&mut c, k);
        c.push(0xf5); // true
    }
    cbor_int(&mut c, 9);
    cbor_head(&mut c, 4, 2);
    cbor_text(&mut c, "internal");
    cbor_text(&mut c, "hybrid");
    cbor_int(&mut c, 10);
    cbor_head(&mut c, 4, 1);
    cbor_head(&mut c, 5, 2);
    cbor_text(&mut c, "alg");
    cbor_int(&mut c, ES256);
    cbor_text(&mut c, "type");
    cbor_text(&mut c, "public-key");
    c
}

/// The browser-side `clientDataJSON` for `ty` = "webauthn.create" / "webauthn.get".
pub fn client_data_json(ty: &str, challenge: &[u8], origin: &str, cross_origin: bool) -> String {
    serde_json::json!({ "type": ty, "challenge": b64::encode(challenge), "origin": origin, "crossOrigin": cross_origin }).to_string()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Host of an `https://` origin (or `http://localhost`), lowercase, without port.
pub fn origin_host(origin: &str) -> Option<String> {
    let (secure, rest) = if let Some(r) = origin.strip_prefix("https://") {
        (true, r)
    } else {
        (false, origin.strip_prefix("http://")?)
    };
    let host = rest.split(['/', '?', '#']).next()?;
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() || (!secure && host != "localhost") {
        return None;
    }
    Some(host)
}

/// WebAuthn rule: the RP ID is the origin's host or one of its parent domains (never a bare
/// top-level label, never an IP address, and only for HTTPS or localhost).
pub fn rp_id_allowed(rp_id: &str, origin: &str) -> bool {
    let Some(host) = origin_host(origin) else { return false };
    let rp = rp_id.to_ascii_lowercase();
    if rp.is_empty() || rp.starts_with('.') || rp.ends_with('.') {
        return false;
    }
    if host == "localhost" {
        return rp == "localhost";
    }
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return false;
    }
    if !rp.contains('.') {
        return false;
    }
    host == rp || host.ends_with(&format!(".{rp}"))
}

// ---- minimal CBOR encoding (definite lengths, CTAP2 canonical) ---------------------------------

fn cbor_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xFF => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xFFFF => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

fn cbor_int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 { cbor_head(out, 0, v as u64) } else { cbor_head(out, 1, (-1 - v) as u64) }
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Base64url without padding (WebAuthn's encoding), also used to store byte fields.
pub mod b64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            for i in 0..=chunk.len() {
                s.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        s
    }

    /// Accepts base64url and standard base64, with or without padding.
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(s.len() * 3 / 4);
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in s.bytes().filter(|&c| c != b'=') {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' | b'+' => 62,
                b'_' | b'/' => 63,
                _ => return None,
            } as u32;
            acc = acc << 6 | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Some(out)
    }

    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(v))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        decode(&s).ok_or_else(|| serde::de::Error::custom("invalid base64"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey;

    fn key() -> Passkey {
        Passkey::generate("example.com", "Example", "alice@example.com", "Alice", b"user-123", 1_800_000_000).unwrap()
    }

    #[test]
    fn base64url_roundtrip_and_known_values() {
        assert_eq!(b64::encode(b""), "");
        assert_eq!(b64::encode(b"f"), "Zg");
        assert_eq!(b64::encode(b"foob"), "Zm9vYg");
        assert_eq!(b64::encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64::decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(b64::decode("+/8=").unwrap(), vec![0xfb, 0xff]);
        assert!(b64::decode("a*b").is_none());
        for n in 0..70u8 {
            let v: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64::decode(&b64::encode(&v)).unwrap(), v);
        }
    }

    #[test]
    fn registration_data_has_the_webauthn_layout() {
        let k = key();
        let ad = k.registration_auth_data(true).unwrap();
        assert_eq!(&ad[..32], &Sha256::digest(b"example.com")[..]);
        assert_eq!(ad[32], FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
        assert_eq!(&ad[33..37], &[0, 0, 0, 0]);
        assert_eq!(&ad[37..53], &AAGUID);
        assert_eq!(u16::from_be_bytes([ad[53], ad[54]]) as usize, 32);
        assert_eq!(&ad[55..87], &k.credential_id[..]);
        let cose = &ad[87..];
        assert_eq!(cose.len(), 77);
        assert_eq!(&cose[..10], &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        let att = attestation_object(&ad);
        assert_eq!(&att[..5], &[0xa3, 0x63, b'f', b'm', b't']);
        assert!(att.ends_with(&ad));
    }

    #[test]
    fn assertion_signature_verifies_with_the_published_public_key() {
        let k = key();
        let cdj = client_data_json("webauthn.get", b"challenge-bytes", "https://login.example.com", false);
        let hash = sha256(cdj.as_bytes());
        let ad = k.assertion_auth_data(false);
        assert_eq!(ad.len(), 37);
        assert_eq!(ad[32], FLAG_UP | FLAG_BE | FLAG_BS);
        let sig = k.sign(&ad, &hash).unwrap();

        let vk = VerifyingKey::from_public_key_der(&k.public_spki().unwrap()).unwrap();
        let mut msg = ad.clone();
        msg.extend_from_slice(&hash);
        let der = DerSignature::try_from(sig.as_slice()).unwrap();
        assert!(vk.verify(&msg, &der).is_ok());
        msg[0] ^= 1;
        assert!(vk.verify(&msg, &der).is_err());
    }

    #[test]
    fn stored_form_roundtrips_and_keeps_signing() {
        let k = key();
        let json = serde_json::to_string(&k).unwrap();
        let back: Passkey = serde_json::from_str(&json).unwrap();
        assert_eq!(back.credential_id, k.credential_id);
        assert_eq!(back.public_cose().unwrap(), k.public_cose().unwrap());
    }

    #[test]
    fn authenticator_info_is_canonical_cbor() {
        let i = authenticator_info();
        assert_eq!(&i[..3], &[0xa5, 0x01, 0x82]);
        let at = i.windows(16).position(|w| w == AAGUID).unwrap();
        assert_eq!(&i[at - 2..at], &[0x03, 0x50], "key 3, 16-byte string");
        assert_eq!(&i[3..12], b"hFIDO_2_0");
        assert!(i.ends_with(b"dtypejpublic-key"));
    }

    #[test]
    fn rp_id_rules() {
        assert!(rp_id_allowed("example.com", "https://example.com"));
        assert!(rp_id_allowed("example.com", "https://login.example.com:8443/path"));
        assert!(rp_id_allowed("login.example.com", "https://login.example.com"));
        assert!(rp_id_allowed("localhost", "http://localhost:3000"));
        assert!(!rp_id_allowed("example.com", "http://example.com"), "plain HTTP");
        assert!(!rp_id_allowed("example.com", "https://notexample.com"));
        assert!(!rp_id_allowed("other.com", "https://example.com"));
        assert!(!rp_id_allowed("com", "https://example.com"), "bare top-level label");
        assert!(!rp_id_allowed("login.example.com", "https://example.com"), "child of the origin");
        assert!(!rp_id_allowed("1.2.3.4", "https://1.2.3.4"));
        assert!(!rp_id_allowed("example.com", "chrome-extension://abc"));
    }

    #[test]
    fn client_data_is_json_with_b64url_challenge() {
        let v: serde_json::Value = serde_json::from_str(&client_data_json("webauthn.create", &[0xfb, 0xff], "https://a.example", false)).unwrap();
        assert_eq!(v["type"], "webauthn.create");
        assert_eq!(v["challenge"], "-_8");
        assert_eq!(v["origin"], "https://a.example");
        assert_eq!(v["crossOrigin"], false);
    }
}
