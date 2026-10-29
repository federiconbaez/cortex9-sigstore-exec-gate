//! cosign-compatible blob signatures (ECDSA P-256 / SHA-256, key-based mode).
//!
//! `cosign sign-blob --key k.key --output-signature f.sig blob` writes
//! base64(ASN.1 DER ECDSA signature over SHA-256(blob)); `cosign.pub` is a
//! PEM "PUBLIC KEY" (PKIX/SPKI). This module verifies exactly that format.
//! Keyless (Fulcio certificate + Rekor inclusion proof) is NOT implemented.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn load_public_pem(pem: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|e| anyhow!("bad public key PEM (need ECDSA P-256 SPKI): {e}"))
}

/// Verify a base64 DER (or raw 64-byte r||s) signature over `blob`.
pub fn verify_blob(key: &VerifyingKey, blob: &[u8], sig_b64: &str) -> Result<()> {
    let compact: String = sig_b64.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .context("signature is not base64")?;
    let sig = match Signature::from_der(&raw) {
        Ok(s) => s,
        Err(_) => Signature::from_slice(&raw)
            .map_err(|e| anyhow!("signature is neither DER nor r||s: {e}"))?,
    };
    key.verify(blob, &sig)
        .map_err(|_| anyhow!("signature does not verify"))
}

pub fn sign_blob(key: &SigningKey, blob: &[u8]) -> String {
    let sig: DerSignature = key.sign(blob);
    base64::engine::general_purpose::STANDARD.encode(sig.as_bytes())
}

pub fn load_private_pem(pem: &str) -> Result<SigningKey> {
    SigningKey::from_pkcs8_pem(pem.trim()).map_err(|e| anyhow!("bad PKCS#8 P-256 private key: {e}"))
}

/// Returns (private PKCS#8 PEM, public SPKI PEM).
pub fn keygen() -> Result<(String, String)> {
    let sk = SigningKey::random(&mut rand_core::OsRng);
    let priv_pem = sk.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let pub_pem = sk.verifying_key().to_public_key_pem(LineEnding::LF)?;
    Ok((priv_pem, pub_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let (sk_pem, pk_pem) = keygen().unwrap();
        let sk = load_private_pem(&sk_pem).unwrap();
        let pk = load_public_pem(&pk_pem).unwrap();
        let blob = b"\x7fELF hello".to_vec();
        let sig = sign_blob(&sk, &blob);
        verify_blob(&pk, &blob, &sig).unwrap();
        verify_blob(&pk, &blob, &format!("{sig}\n")).unwrap();
        let mut t = blob.clone();
        t[5] ^= 1;
        assert!(verify_blob(&pk, &t, &sig).is_err());
        let (_, other) = keygen().unwrap();
        assert!(verify_blob(&load_public_pem(&other).unwrap(), &blob, &sig).is_err());
        assert!(verify_blob(&pk, &blob, "not base64!!").is_err());
        assert!(verify_blob(&pk, &blob, "").is_err());
    }

    #[test]
    fn rejects_non_p256_key() {
        assert!(
            load_public_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----").is_err()
        );
    }
}
