pub mod cap_arqc;
pub mod common;
pub mod cvv;
pub mod diebold_pin;
pub mod dukpt_mac;
pub mod dukpt_pin_verify;
pub mod dukpt_pin_verify_aes;
pub mod dynamic_cvv;
pub mod emv_decrypt;
pub mod encrypt_decrypt;
pub mod heartbeat;
pub mod hmac;
pub mod international_encrypt;
pub mod issuer_script_mac;
pub mod kq_arqc;
pub mod kw_arqc;
pub mod legacy_mac;
pub mod mac;
pub mod mac_translate;
pub mod pin;
pub mod pin_change;
pub mod pin_verify_non_dukpt;
pub mod random_pin;
pub mod reader;
pub mod unionpay_arqc;

use std::sync::Arc;

use crate::handlers::Handler;
use crate::protocol::Protocol;
use crate::vendor::VendorModule;

/// The built-in Thales payShield 10K vendor module: the payShield wire protocol
/// plus every payShield command handler. Registered through the same
/// [`VendorModule`] seam as any bolt-on vendor.
pub struct ThalesModule;

impl VendorModule for ThalesModule {
    fn vendor(&self) -> &'static str {
        "thales_payshield"
    }

    fn protocol(&self) -> Arc<dyn Protocol> {
        Arc::new(crate::protocol::thales::ThalesPayShield)
    }

    fn handlers(&self) -> Vec<Arc<dyn Handler>> {
        vec![
            Arc::new(pin::PinHandler),
            Arc::new(pin_change::PinChangeHandler),
            Arc::new(diebold_pin::DieboldPinHandler),
            Arc::new(random_pin::RandomPinHandler),
            Arc::new(dukpt_pin_verify::DukptPinVerifyHandler),
            Arc::new(dukpt_pin_verify_aes::DukptPinVerifyAesHandler),
            Arc::new(pin_verify_non_dukpt::PinVerifyNonDukptHandler),
            Arc::new(encrypt_decrypt::EncryptDecryptHandler),
            Arc::new(international_encrypt::InternationalEncryptHandler),
            Arc::new(dukpt_mac::DukptMacHandler),
            Arc::new(issuer_script_mac::IssuerScriptMacHandler),
            Arc::new(cap_arqc::CapArqcHandler),
            Arc::new(emv_decrypt::EmvDecryptHandler),
            Arc::new(kq_arqc::KqArqcHandler),
            Arc::new(kw_arqc::KwArqcHandler),
            Arc::new(unionpay_arqc::UnionPayArqcHandler),
            Arc::new(hmac::HmacHandler),
            Arc::new(mac::MacHandler),
            Arc::new(mac_translate::MacTranslateHandler),
            Arc::new(legacy_mac::LegacyMacHandler),
            Arc::new(cvv::CvvHandler),
            Arc::new(dynamic_cvv::DynamicCvvHandler),
            Arc::new(heartbeat::HeartbeatHandler),
        ]
    }
}
