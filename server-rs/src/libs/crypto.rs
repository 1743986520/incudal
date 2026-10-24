//! AES-256-GCM sensitive-data encryption, wire-compatible with
//! lib/security.ts encryptSensitiveData/decryptSensitiveData:
//! format `iv:tag:ciphertext` in hex, IV = 16 bytes (non-standard but what
//! Node's createCipheriv accepts), tag = 16 bytes, key = sha256(secret).

use aes::Aes256;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{AesGcm, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// aes-256-gcm with the TS server's 16-byte IV length.
type Aes256Gcm16 = AesGcm<Aes256, U16>;

const IV_LEN: usize = 16;
const TAG_LEN: usize = 16;

pub fn derive_key(secret: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    key.copy_from_slice(&Sha256::digest(secret.as_bytes()));
    key
}

pub fn encrypt_sensitive_data(key: &[u8; 32], plaintext: &str) -> String {
    let cipher = Aes256Gcm16::new(key.into());
    let mut iv = [0u8; IV_LEN];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::<U16>::from_slice(&iv);
    let sealed = cipher
        .encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad: &[] })
        .expect("aes-gcm encryption cannot fail with valid key/nonce");
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    format!(
        "{}:{}:{}",
        hex::encode(iv),
        hex::encode(tag),
        hex::encode(ciphertext)
    )
}

pub fn is_encrypted(data: &str) -> bool {
    let parts: Vec<&str> = data.split(':').collect();
    if parts.len() != 3 {
        return false;
    }
    let (iv_hex, tag_hex, ct_hex) = (parts[0], parts[1], parts[2]);
    if iv_hex.is_empty() || tag_hex.is_empty() || ct_hex.is_empty() {
        return false;
    }
    if iv_hex.len() != IV_LEN * 2 || tag_hex.len() != TAG_LEN * 2 {
        return false;
    }
    iv_hex.bytes().chain(tag_hex.bytes()).chain(ct_hex.bytes()).all(|b| b.is_ascii_hexdigit())
}

/// Decrypts `iv:tag:ciphertext`; historical plaintext values are returned as-is.
/// Fail-closed on tampering (mirrors P2-16): returns Err instead of ciphertext.
pub fn decrypt_sensitive_data(key: &[u8; 32], data: &str) -> Result<String, ()> {
    if !is_encrypted(data) {
        return Ok(data.to_string());
    }
    let parts: Vec<&str> = data.split(':').collect();
    let iv = hex::decode(parts[0]).map_err(|_| ())?;
    let tag = hex::decode(parts[1]).map_err(|_| ())?;
    let ciphertext = hex::decode(parts[2]).map_err(|_| ())?;
    if iv.len() != IV_LEN || tag.len() != TAG_LEN {
        return Err(());
    }
    let cipher = Aes256Gcm16::new(key.into());
    let mut sealed = ciphertext;
    sealed.extend_from_slice(&tag);
    let nonce = Nonce::<U16>::from_slice(&iv);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: &sealed, aad: &[] })
        .map_err(|_| ())?;
    String::from_utf8(plaintext).map_err(|_| ())
}

// ---- TOTP (2FA), compatible with otplib: SHA1, 6 digits, 30s period ----

pub fn generate_totp_secret() -> String {
    // Base32-encoded random 20 bytes, per otplib defaults.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    // Simple base32 encode (RFC 4648, no padding).
    let mut out = String::new();
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let b = u64::from_be_bytes([
            0, buf[0], buf[1], buf[2], buf[3], buf[4], 0, 0,
        ]) >> 24;
        for i in 0..8 {
            if i * 5 < chunk.len() * 8 {
                out.push(ALPHABET[((b >> (35 - i * 5)) & 0x1f) as usize] as char);
            }
        }
    }
    out
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut acc = 0u32;
    let mut out = Vec::new();
    for ch in input.trim_end_matches('=').bytes() {
        let val = ALPHABET.iter().position(|&c| c.eq_ignore_ascii_case(&ch))? as u32;
        acc = (acc << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn totp_now(secret_base32: &str, time_step: u64, digits: u32, at_unix: u64) -> Option<String> {
    let key = base32_decode(secret_base32)?;
    let counter = at_unix / time_step;
    let msg = counter.to_be_bytes();
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha1::Sha1> as hmac::Mac>::new_from_slice(&key).ok()?;
    mac.update(&msg);
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);
    Some(format!("{:0width$}", binary % 10u32.pow(digits), width = digits as usize))
}

/// Verify a TOTP with ±1 step window (otplib default window of 1).
pub fn verify_totp(secret_base32: &str, code: &str) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for drift in [-1i64, 0, 1] {
        let at = (now as i64 + drift).max(0) as u64;
        if let Some(expected) = totp_now(secret_base32, 30, 6, at) {
            if constant_time_eq(&expected, code) {
                return true;
            }
        }
    }
    false
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
