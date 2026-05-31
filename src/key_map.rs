use crate::error::ProxyError;
use std::collections::HashMap;
use tracing::{info, warn};

/// Metadata parsed from a TR-31 ('S' prefix) wrapped key block in a host command.
///
/// Wrapped key blocks carry their own type/algorithm in the header; KCV is optional
/// (present only if the producer included a "KC" optional block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlockMeta {
    /// TR-31 key usage code (e.g. "P0", "B0", "M6"). Always 2 ASCII chars.
    pub key_usage: String,
    /// TR-31 algorithm character ('A'=AES, 'D'=DES, 'T'=TDES, 'H'=HMAC, etc.).
    pub algorithm: char,
    /// KCV from the TR-31 "KC" optional block, if present. Hex string.
    pub kcv: Option<String>,
}

/// A key field as it appeared in the wire frame, parsed but not yet resolved.
///
/// `raw` is what `key_mappings` config keys against (back-compat: ASCII labels,
/// LMK-encrypted hex blobs, anything pre-existing config maps).
///
/// `block` is `Some` only for wrapped key blocks (TR-31 'S' prefix) — populated
/// from the block header so the resolver can do KCV-based lookup against keys
/// already imported into APC.
#[derive(Debug, Clone)]
pub struct KeyDescriptor {
    pub raw: String,
    pub block: Option<KeyBlockMeta>,
}

impl KeyDescriptor {
    /// Build a descriptor for a label / hex / pre-resolved identifier with no
    /// wrapped block metadata. Used by handlers that read fixed-width key fields
    /// (e.g. CA/CC's 32H source/dest keys, where the field can't carry a TR-31 block).
    pub fn label(raw: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            block: None,
        }
    }
}

/// Composite key for KCV-indexed lookup. Three-tuple defends against the rare
/// case where two unrelated clear keys produce the same 3-byte KCV by chance.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct KcvKey {
    key_usage: String,
    algorithm: String,
    kcv: String,
}

/// Resolves legacy HSM key identifiers to APC key ARNs.
///
/// Two lookup paths:
///
///  1. **Label path** — operator-provided `key_mappings` in `proxy.yaml`.
///     Used for ASCII labels and LMK-encrypted variant keys (16H/U+32H/T+48H)
///     where the wire form has no self-describing KCV.
///
///  2. **KCV path** — startup-scanned APC inventory keyed on
///     `(KeyUsage, Algorithm, KCV)`. Used for wrapped key blocks (TR-31 'S'
///     prefix) that carry their own metadata in the wire frame.
///
/// ARNs and aliases pass through unchanged from either path.
pub struct KeyMap {
    labels: HashMap<String, String>,
    kcv_index: HashMap<KcvKey, String>,
}

impl KeyMap {
    pub fn new(mappings: HashMap<String, String>) -> Self {
        Self {
            labels: mappings,
            kcv_index: HashMap::new(),
        }
    }

    /// Resolve a legacy string identifier — for fixed-width key fields (e.g. the
    /// 32H source/dest keys in CA/CC) that cannot carry a wrapped TR-31 block.
    /// KCV-blind: only label/config lookup and ARN/alias passthrough.
    pub fn resolve<'a>(&'a self, key_id: &'a str) -> Result<&'a str, ProxyError> {
        if key_id.starts_with("arn:aws:payment-cryptography") || key_id.starts_with("alias/") {
            return Ok(key_id);
        }
        self.labels
            .get(key_id)
            .map(std::string::String::as_str)
            .ok_or_else(|| ProxyError::KeyNotFound(key_id.to_string()))
    }

    /// Resolve a parsed key descriptor to an APC key ARN or alias.
    ///
    /// Precedence:
    ///   1. raw already looks like an APC identifier → pass through
    ///   2. wrapped block with KCV → KCV index lookup
    ///   3. label map (config) → return ARN
    ///   4. wrapped block without KCV → log usage/algorithm to aid diagnosis, fail
    pub fn resolve_descriptor<'a>(
        &'a self,
        desc: &'a KeyDescriptor,
    ) -> Result<&'a str, ProxyError> {
        if desc.raw.starts_with("arn:aws:payment-cryptography") || desc.raw.starts_with("alias/") {
            return Ok(&desc.raw);
        }

        if let Some(block) = &desc.block {
            if let Some(kcv) = &block.kcv {
                let key = KcvKey {
                    key_usage: tr31_usage_to_apc(&block.key_usage),
                    algorithm: tr31_algo_to_apc(block.algorithm).to_string(),
                    kcv: kcv.to_ascii_uppercase(),
                };
                if let Some(arn) = self.kcv_index.get(&key) {
                    return Ok(arn);
                }
                return Err(ProxyError::KeyNotFound(format!(
                    "wrapped key block (usage={}, algo={}, kcv={}) not in APC inventory",
                    block.key_usage, block.algorithm, kcv
                )));
            }
        }

        if let Some(arn) = self.labels.get(&desc.raw) {
            return Ok(arn);
        }

        if let Some(block) = &desc.block {
            return Err(ProxyError::KeyNotFound(format!(
                "wrapped key block (usage={}, algo={}) has no KCV in block; cannot resolve to APC ARN",
                block.key_usage, block.algorithm
            )));
        }
        Err(ProxyError::KeyNotFound(desc.raw.clone()))
    }

    /// Populate the KCV index from APC `list_keys`. Should be called once at startup.
    ///
    /// Filters to `CREATE_COMPLETE` + `Enabled=true` — keys in any other state
    /// (DELETE_PENDING, CREATE_IN_PROGRESS) or disabled cannot be used in
    /// data-plane operations. Disabled CREATE_COMPLETE keys are surfaced as a
    /// warning so operators notice unusable inventory.
    ///
    /// Logs a warning and picks the lexicographically smallest ARN on
    /// collisions (same clear key imported multiple times — functionally
    /// identical but ambiguous addressing).
    pub async fn scan_apc(
        &mut self,
        client: &aws_sdk_paymentcryptography::Client,
    ) -> Result<(), ProxyError> {
        use aws_sdk_paymentcryptography::types::KeyState;

        let mut collisions: HashMap<KcvKey, Vec<String>> = HashMap::new();
        let mut next_token: Option<String> = None;
        let mut scanned = 0_usize;
        let mut skipped_disabled = 0_usize;

        loop {
            let mut req = client.list_keys().key_state(KeyState::CreateComplete);
            if let Some(tok) = next_token.take() {
                req = req.next_token(tok);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| ProxyError::ApcError(format!("list_keys: {e}")))?;

            for summary in resp.keys() {
                scanned += 1;
                let Some(attrs) = summary.key_attributes() else {
                    continue;
                };
                if !summary.enabled() {
                    skipped_disabled += 1;
                    warn!(
                        arn   = %summary.key_arn(),
                        usage = %attrs.key_usage().as_str(),
                        algo  = %attrs.key_algorithm().as_str(),
                        kcv   = %summary.key_check_value(),
                        "APC key is disabled; skipping (cannot be used in data-plane ops)"
                    );
                    continue;
                }
                let key = KcvKey {
                    key_usage: attrs.key_usage().as_str().to_string(),
                    algorithm: attrs.key_algorithm().as_str().to_string(),
                    kcv: summary.key_check_value().to_ascii_uppercase(),
                };
                collisions
                    .entry(key)
                    .or_default()
                    .push(summary.key_arn().to_string());
            }

            next_token = resp.next_token().map(str::to_string);
            if next_token.is_none() {
                break;
            }
        }

        for (key, mut arns) in collisions {
            arns.sort();
            if arns.len() > 1 {
                warn!(
                    usage = %key.key_usage,
                    algo  = %key.algorithm,
                    kcv   = %key.kcv,
                    arns  = ?arns,
                    "multiple APC keys share (usage, algo, kcv); resolving to smallest ARN"
                );
            }
            self.kcv_index.insert(
                key,
                arns.into_iter().next().expect("collision Vec non-empty"),
            );
        }

        info!(
            scanned,
            indexed = self.kcv_index.len(),
            skipped_disabled,
            labels = self.labels.len(),
            "APC key inventory loaded"
        );
        Ok(())
    }
}

/// Map a TR-31 algorithm character to the APC `KeyAlgorithm` enum name.
///
/// Wrapped key blocks declare only the algorithm family, not the key length, so
/// the mapping below picks the conventional APC key class for each family. The
/// resolver compares this string against `KeyAlgorithm::as_str()`, so the
/// returned values must match the SDK's serialization exactly.
///
/// Caveat: there is no way to distinguish TDES 2KEY vs 3KEY purely from the
/// TR-31 algorithm char. We default to TDES_2KEY for 'T' (the common case);
/// 3KEY keys must be addressed via `key_mappings` label or pre-resolved ARN.
fn tr31_algo_to_apc(algo: char) -> &'static str {
    match algo {
        'A' => "AES_128",
        // Single DES ('D') and TDES ('T') both map to TDES_2KEY — the common
        // double-length form. Single DES is legacy; treating it as TDES_2KEY
        // matches how operators typically import these keys to APC.
        'D' | 'T' => "TDES_2KEY",
        'H' => "HMAC_SHA256",
        'R' => "RSA_2048",
        _ => "",
    }
}

/// TR-31 key usage code → APC `KeyUsage` enum string.
///
/// APC's `KeyUsage::as_str()` returns the full `TR31_xx_NAME` form; the wire
/// frame carries only the 2-char code. We don't validate exhaustively here —
/// unknown codes will simply miss the KCV index and fall through to the label
/// path or fail with the original code in the error message.
fn tr31_usage_to_apc(usage: &str) -> String {
    let suffix = match usage {
        "B0" => "BASE_DERIVATION_KEY",
        "C0" => "CARD_VERIFICATION_KEY",
        "D0" => "SYMMETRIC_DATA_ENCRYPTION_KEY",
        "E0" => "EMV_MKEY_APP_CRYPTOGRAMS",
        "E1" => "EMV_MKEY_CONFIDENTIALITY",
        "E2" => "EMV_MKEY_INTEGRITY",
        "E4" => "EMV_MKEY_DYNAMIC_NUMBERS",
        "E5" => "EMV_MKEY_CARD_PERSONALIZATION",
        "E6" => "EMV_MKEY_OTHER",
        "K0" | "K1" => "KEY_BLOCK_PROTECTION_KEY",
        "M1" => "ISO_9797_1_MAC_KEY",
        "M3" => "ISO_9797_3_MAC_KEY",
        "M6" => "ISO_9797_5_CMAC_KEY",
        "M7" => "HMAC_KEY",
        "P0" => "PIN_ENCRYPTION_KEY",
        "V1" => "IBM3624_PIN_VERIFICATION_KEY",
        "V2" => "VISA_PIN_VERIFICATION_KEY",
        _ => return String::new(),
    };
    format!("TR31_{usage}_{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arn(n: &str) -> String {
        format!("arn:aws:payment-cryptography:us-east-1:000000000000:key/{n}")
    }

    #[test]
    fn arn_passthrough() {
        let km = KeyMap::new(HashMap::new());
        let id = arn("abc");
        assert_eq!(km.resolve(&id).unwrap(), id);
    }

    #[test]
    fn alias_passthrough() {
        let km = KeyMap::new(HashMap::new());
        assert_eq!(
            km.resolve("alias/zpk-inbound").unwrap(),
            "alias/zpk-inbound"
        );
    }

    #[test]
    fn label_lookup() {
        let mut m = HashMap::new();
        m.insert("MY_LABEL".to_string(), arn("xyz"));
        let km = KeyMap::new(m);
        assert!(km.resolve("MY_LABEL").unwrap().ends_with("/xyz"));
    }

    #[test]
    fn label_miss_returns_keynotfound() {
        let km = KeyMap::new(HashMap::new());
        assert!(matches!(
            km.resolve("UNKNOWN"),
            Err(ProxyError::KeyNotFound(_))
        ));
    }

    #[test]
    fn descriptor_kcv_hit() {
        let mut km = KeyMap::new(HashMap::new());
        km.kcv_index.insert(
            KcvKey {
                key_usage: "TR31_P0_PIN_ENCRYPTION_KEY".to_string(),
                algorithm: "TDES_2KEY".to_string(),
                kcv: "ABCDEF".to_string(),
            },
            arn("pin1"),
        );
        let desc = KeyDescriptor {
            raw: "ignored".to_string(),
            block: Some(KeyBlockMeta {
                key_usage: "P0".to_string(),
                algorithm: 'T',
                kcv: Some("abcdef".to_string()), // case-insensitive
            }),
        };
        assert!(km.resolve_descriptor(&desc).unwrap().ends_with("/pin1"));
    }

    #[test]
    fn descriptor_kcv_miss_does_not_fall_back_to_label() {
        // If a wrapped block has a KCV that isn't in the index, we don't silently
        // resolve via the label path — that could send the operation to the wrong key.
        let mut labels = HashMap::new();
        labels.insert("S...".to_string(), arn("wrong"));
        let km = KeyMap::new(labels);
        let desc = KeyDescriptor {
            raw: "S...".to_string(),
            block: Some(KeyBlockMeta {
                key_usage: "P0".to_string(),
                algorithm: 'T',
                kcv: Some("DEADBE".to_string()),
            }),
        };
        assert!(matches!(
            km.resolve_descriptor(&desc),
            Err(ProxyError::KeyNotFound(_))
        ));
    }

    #[test]
    fn descriptor_block_no_kcv_falls_back_to_label() {
        let mut labels = HashMap::new();
        labels.insert("RAWBLOB".to_string(), arn("zpk"));
        let km = KeyMap::new(labels);
        let desc = KeyDescriptor {
            raw: "RAWBLOB".to_string(),
            block: Some(KeyBlockMeta {
                key_usage: "P0".to_string(),
                algorithm: 'T',
                kcv: None,
            }),
        };
        assert!(km.resolve_descriptor(&desc).unwrap().ends_with("/zpk"));
    }
}
