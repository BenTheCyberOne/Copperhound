//! Two-factor sign-in for local accounts: TOTP (RFC 6238; HMAC-SHA1, 30 s
//! steps, 6 digits, ±1 step of clock skew, a code is accepted once) plus
//! one-time recovery codes (stored as SHA-256 hashes).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
pub const RECOVERY_CODES: usize = 10;

/// Per-account two-factor state (in `users.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Mfa {
    /// Base32 secret.
    pub secret: String,
    /// Confirmed with a valid code; until then the secret is only pending.
    pub enabled: bool,
    /// SHA-256 (hex) of unused recovery codes.
    #[serde(default)]
    pub recovery: Vec<String>,
    /// Last accepted time step (codes at or before it are refused).
    #[serde(default)]
    pub last_step: u64,
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = B32.iter().position(|&b| b as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// New 160-bit secret, base32.
pub fn new_secret() -> String {
    let mut b = [0u8; 20];
    getrandom::getrandom(&mut b).expect("system RNG");
    base32_encode(&b)
}

/// The code for one time step.
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = <Hmac<Sha1>>::new_from_slice(secret).expect("any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// The step a valid `code` belongs to (now ±1), refusing steps at or before `last_step`.
pub fn verify(secret_b32: &str, code: &str, unix_now: u64, last_step: u64) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let secret = base32_decode(secret_b32)?;
    let now = unix_now / STEP_SECS;
    [now.saturating_sub(1), now, now + 1].into_iter().filter(|&s| s > last_step).find(|&s| code_at(&secret, s) == want)
}

pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>().replace('+', "%20");
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        enc(issuer)
    )
}

/// QR code of `text` as an SVG document.
pub fn qr_svg(text: &str) -> String {
    match qrcode::QrCode::new(text.as_bytes()) {
        Ok(q) => q.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(true).build(),
        Err(_) => String::new(),
    }
}

/// `n` recovery codes (`xxxx-xxxx-xxxx`) and their hashes.
pub fn recovery_codes(n: usize) -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).expect("system RNG");
        let s = base32_encode(&b).to_ascii_lowercase();
        plain.push(format!("{}-{}-{}", &s[0..4], &s[4..8], &s[8..12]));
    }
    let hashed = plain.iter().map(|c| hash_recovery(c)).collect();
    (plain, hashed)
}

pub fn hash_recovery(code: &str) -> String {
    let norm: String = code.trim().to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    Sha256::digest(norm.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B (SHA-1 seed "12345678901234567890"), last 6 digits.
    #[test]
    fn rfc6238_vectors() {
        let seed = b"12345678901234567890";
        for (t, want) in [(59u64, 287082u32), (1111111109, 81804), (1111111111, 50471), (1234567890, 5924), (2000000000, 279037)] {
            assert_eq!(code_at(seed, t / STEP_SECS), want, "t={t}");
        }
        let b32 = base32_encode(seed);
        assert_eq!(b32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&b32).unwrap(), seed);
        assert_eq!(verify(&b32, "287082", 59, 0), Some(1));
        assert_eq!(verify(&b32, "287082", 59, 1), None, "replay of the same step");
        assert_eq!(verify(&b32, "287082", 59 + 30, 0), Some(1), "one step of skew");
        assert_eq!(verify(&b32, "287082", 59 + 90, 0), None, "too old");
        assert_eq!(verify(&b32, "28708", 59, 0), None);
    }

    #[test]
    fn recovery() {
        let (plain, hashed) = recovery_codes(3);
        assert_eq!(plain.len(), 3);
        assert_eq!(hash_recovery(&plain[0].to_ascii_uppercase()), hashed[0]);
        assert!(otpauth_uri("CopperHound", "admin", "ABC").starts_with("otpauth://totp/CopperHound:admin?secret=ABC"));
        assert!(qr_svg("otpauth://totp/x").contains("<svg"));
    }
}
