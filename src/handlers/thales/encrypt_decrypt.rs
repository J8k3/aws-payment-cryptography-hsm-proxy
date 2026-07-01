use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield legacy 64-bit block encryption/decryption.
///
/// HE/HF — Encrypt Data Block → APC encrypt_data (TDES-ECB)  (PUGD0538-003 p.107)
/// HG/HH — Decrypt Data Block → APC decrypt_data (TDES-ECB)  (PUGD0538-003 p.108)
///
/// Both commands operate on a single 64-bit block (16H hex). The TAK key is under
/// LMK pair 16-17, variant 0. payShield treats TAK as a MAC-class key; in APC the
/// key_map must point the TAK label at a TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY ARN.
/// APC enforces key usage at call time, so a misconfigured mapping (e.g. pointing at
/// an M3 key) will return error 41.
///
/// HE field layout:
///   TAK:  16H | 'U'+32H | 'T'+48H  (LMK pair 16-17 variant 0)
///   Data: 16H  (hex-encoded 64-bit plaintext)
///
/// HG field layout (identical structure):
///   TAK:  16H | 'U'+32H | 'T'+48H
///   Data: 16H  (hex-encoded 64-bit ciphertext)
///
/// Optional trailing '%' + 2N LMK identifier is accepted by payShield; the proxy
/// consumes only the fixed fields above and ignores the optional suffix.
pub struct EncryptDecryptHandler;

const DATA_HEX_LEN: usize = 16;

#[async_trait]
impl Handler for EncryptDecryptHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["HE", "HG"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "HE encrypts / HG decrypts a single 64-bit block (16H) under a data key (TR31_D0), TDES-ECB. Wire: key then 16H data.",
            because: "PUGD0538-003 p.107 (HE) / p.108 (HG). Verified live: proxy HE ciphertext == APC encrypt_data (TDES-ECB, deterministic), and the HE→HG round-trip recovers the plaintext, over random plus all-zero / all-F blocks. Operational note (verified live): APC rejects encrypt+decrypt alone for a D0 key — the mapped key must use NoRestrictions (or encrypt+decrypt+wrap+unwrap) for both HE and HG to work.",
            wire: WireGrounding::DiffXprov,
            crypto: CryptoGrounding::Apc,
            proof: Proof::LiveTest("encrypt_decrypt_he_hg_differential"),
        }]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"HE" => handle_he(payload, state).await,
            b"HG" => handle_hg(payload, state).await,
            _ => HandlerResult::err(*b"68"),
        }
    }
}

fn parse_key_and_data(
    payload: &[u8],
    cmd: &str,
) -> Result<(crate::key_map::KeyDescriptor, Zeroizing<String>), ProxyError> {
    let (key_id, key_len) = parse_legacy_key(payload, 0)?;
    let data_start = key_len;
    let min_len = data_start + DATA_HEX_LEN;
    if payload.len() < min_len {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd} payload too short: {} < {}",
            payload.len(),
            min_len
        )));
    }
    let data = Zeroizing::new(
        String::from_utf8_lossy(&payload[data_start..data_start + DATA_HEX_LEN]).to_string(),
    );
    Ok((key_id, data))
}

async fn handle_he(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, plain_text) = match parse_key_and_data(payload, "HE") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        EncryptionDecryptionAttributes, EncryptionMode, SymmetricEncryptionAttributes,
    };

    let sym_attrs = match SymmetricEncryptionAttributes::builder()
        .mode(EncryptionMode::Ecb)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(key = %key_arn, "HE: encrypt_data TDES-ECB");

    match state
        .data
        .encrypt_data()
        .key_identifier(&key_arn)
        .plain_text(plain_text.as_str())
        .encryption_attributes(EncryptionDecryptionAttributes::Symmetric(sym_attrs))
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.cipher_text().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "HE: encrypt_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_hg(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, cipher_text) = match parse_key_and_data(payload, "HG") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        EncryptionDecryptionAttributes, EncryptionMode, SymmetricEncryptionAttributes,
    };

    let sym_attrs = match SymmetricEncryptionAttributes::builder()
        .mode(EncryptionMode::Ecb)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(key = %key_arn, "HG: decrypt_data TDES-ECB");

    match state
        .data
        .decrypt_data()
        .key_identifier(&key_arn)
        .cipher_text(cipher_text.as_str())
        .decryption_attributes(EncryptionDecryptionAttributes::Symmetric(sym_attrs))
        .send()
        .await
    {
        Ok(resp) => HandlerResult {
            error_code: *b"00",
            payload: Zeroizing::new(resp.plain_text().as_bytes().to_vec()),
        },
        Err(e) => {
            warn!(?e, "HG: decrypt_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tak_single() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16H
    }
    fn tak_double() -> Vec<u8> {
        let mut v = vec![b'U'];
        v.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        v
    }
    fn data_block() -> &'static [u8] {
        b"AABBCCDDEE112233" // 16H
    }

    #[test]
    fn he_parse_single_key() {
        let mut p = tak_single();
        p.extend_from_slice(data_block());
        let (key_id, data) = parse_key_and_data(&p, "HE").unwrap();
        assert_eq!(key_id.raw, "1234567890ABCDEF");
        assert_eq!(data.as_str(), "AABBCCDDEE112233");
    }

    #[test]
    fn he_parse_double_key() {
        let mut p = tak_double();
        p.extend_from_slice(data_block());
        let (key_id, data) = parse_key_and_data(&p, "HE").unwrap();
        // parse_legacy_key returns the identifier including the 'U' prefix;
        // the key_map must be configured with the same form.
        assert_eq!(key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(data.as_str(), "AABBCCDDEE112233");
    }

    #[test]
    fn he_parse_too_short_returns_error() {
        let mut p = tak_single();
        p.extend_from_slice(b"AABBCCDD"); // only 8H, need 16H
        assert!(parse_key_and_data(&p, "HE").is_err());
    }
}
