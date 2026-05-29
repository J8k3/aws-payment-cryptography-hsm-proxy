pub mod futurex;
pub mod noop;
pub mod thales;

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::key_map::KeyMap;

/// Shared application state cloned into every connection task.
pub struct AppState {
    pub key_map: KeyMap,
    pub data: aws_sdk_paymentcryptographydata::Client,
}

/// Result returned by every command handler.
pub struct HandlerResult {
    /// 2-byte ASCII error code. b"00" = success.
    pub error_code: [u8; 2],
    /// Response payload. Zeroized on drop to avoid key/PIN material lingering in heap.
    pub payload: Zeroizing<Vec<u8>>,
}

impl HandlerResult {
    pub fn success(payload: Vec<u8>) -> Self {
        Self {
            error_code: *b"00",
            payload: Zeroizing::new(payload),
        }
    }

    pub fn err(code: [u8; 2]) -> Self {
        Self {
            error_code: code,
            payload: Zeroizing::new(vec![]),
        }
    }

    pub fn from_proxy_error(e: &ProxyError) -> Self {
        Self::err(e.payshield_code())
    }
}

/// Every command handler implements this trait.
#[async_trait]
pub trait Handler: Send + Sync {
    /// Handle one command. `command_code` is the raw bytes from the parsed frame
    /// (2 bytes for Thales, 4 bytes for Futurex).
    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult;
    /// The command codes this handler accepts. Matched by byte equality against parsed frames.
    fn command_codes(&self) -> &'static [&'static str];
}

/// O(1) command dispatch table built at startup.
pub struct Registry {
    map: HashMap<Vec<u8>, Arc<dyn Handler>>,
}

impl Registry {
    pub fn build() -> Self {
        let mut map: HashMap<Vec<u8>, Arc<dyn Handler>> = HashMap::new();

        // `h: Arc<dyn Handler>` by value is intentional — Rust coerces Arc<ConcreteType> to
        // Arc<dyn Handler> at the call site, which doesn't work through a `&Arc<dyn Handler>` ref.
        #[allow(clippy::needless_pass_by_value)]
        fn register(map: &mut HashMap<Vec<u8>, Arc<dyn Handler>>, h: Arc<dyn Handler>) {
            for code in h.command_codes() {
                map.insert(code.as_bytes().to_vec(), Arc::clone(&h));
            }
        }

        // Thales payShield handlers
        register(&mut map, Arc::new(thales::pin::PinHandler));
        register(&mut map, Arc::new(thales::pin_change::PinChangeHandler));
        register(&mut map, Arc::new(thales::diebold_pin::DieboldPinHandler));
        register(&mut map, Arc::new(thales::random_pin::RandomPinHandler));
        register(
            &mut map,
            Arc::new(thales::dukpt_pin_verify::DukptPinVerifyHandler),
        );
        register(
            &mut map,
            Arc::new(thales::dukpt_pin_verify_aes::DukptPinVerifyAesHandler),
        );
        register(
            &mut map,
            Arc::new(thales::pin_verify_non_dukpt::PinVerifyNonDukptHandler),
        );
        register(
            &mut map,
            Arc::new(thales::encrypt_decrypt::EncryptDecryptHandler),
        );
        register(
            &mut map,
            Arc::new(thales::international_encrypt::InternationalEncryptHandler),
        );
        register(&mut map, Arc::new(thales::dukpt_mac::DukptMacHandler));
        register(
            &mut map,
            Arc::new(thales::issuer_script_mac::IssuerScriptMacHandler),
        );
        register(&mut map, Arc::new(thales::cap_arqc::CapArqcHandler));
        register(&mut map, Arc::new(thales::emv_decrypt::EmvDecryptHandler));
        register(&mut map, Arc::new(thales::kq_arqc::KqArqcHandler));
        register(&mut map, Arc::new(thales::kw_arqc::KwArqcHandler));
        register(
            &mut map,
            Arc::new(thales::unionpay_arqc::UnionPayArqcHandler),
        );
        register(&mut map, Arc::new(thales::hmac::HmacHandler));
        register(&mut map, Arc::new(thales::mac::MacHandler));
        register(
            &mut map,
            Arc::new(thales::mac_translate::MacTranslateHandler),
        );
        register(&mut map, Arc::new(thales::legacy_mac::LegacyMacHandler));
        register(&mut map, Arc::new(thales::cvv::CvvHandler));
        register(&mut map, Arc::new(thales::dynamic_cvv::DynamicCvvHandler));
        register(&mut map, Arc::new(thales::heartbeat::HeartbeatHandler));

        // Futurex Excrypt handlers
        register(&mut map, Arc::new(futurex::echo::EchoHandler));
        register(&mut map, Arc::new(futurex::tpin::TpinHandler));

        // Vendor-agnostic stubs
        register(&mut map, Arc::new(noop::NotAvailableHandler));

        Self { map }
    }

    pub fn get(&self, command_code: &[u8]) -> Option<Arc<dyn Handler>> {
        self.map.get(command_code).cloned()
    }
}
