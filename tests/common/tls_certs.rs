//! Generate self-signed TLS material for tests that exercise the proxy's
//! inbound TLS listener. `rcgen` builds an ephemeral CA + leaf so the test
//! client can trust the server cert via a custom RootCertStore without any
//! committed PEM fixtures in the repo.

use std::path::PathBuf;
use std::sync::Arc;

#[allow(dead_code)] // used by tests/tls.rs; passthrough.rs compiles common/ separately
pub struct TlsCerts {
    /// Path to the server certificate (PEM, leaf only).
    pub cert_path: PathBuf,
    /// Path to the server private key (PEM, PKCS8).
    pub key_path: PathBuf,
    /// In-memory CA cert as DER. Use to build a `RootCertStore` for the test
    /// client so it trusts the server cert.
    pub ca_cert_der: rustls::pki_types::CertificateDer<'static>,
}

#[allow(dead_code)]
impl TlsCerts {
    /// Generate a CA, then a leaf cert signed by it whose subjectAltName
    /// matches `server_name`. Writes the leaf cert and key to PEM files in
    /// `dir`.
    pub fn generate(dir: &std::path::Path, server_name: &str) -> Self {
        // Self-signed CA.
        let ca_key = rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("ca key: {e}"));
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|e| panic!("ca params: {e}"));
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "apc-proxy test CA");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .unwrap_or_else(|e| panic!("self-sign ca: {e}"));

        // Leaf cert signed by the CA.
        let leaf_key = rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("leaf key: {e}"));
        let mut leaf_params = rcgen::CertificateParams::new(vec![server_name.to_string()])
            .unwrap_or_else(|e| panic!("leaf params: {e}"));
        leaf_params.distinguished_name = rcgen::DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, server_name);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap_or_else(|e| panic!("sign leaf: {e}"));

        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        std::fs::write(&cert_path, leaf_cert.pem()).expect("write cert");
        std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write key");

        let ca_cert_der = rustls::pki_types::CertificateDer::from(ca_cert.der().to_vec());

        Self {
            cert_path,
            key_path,
            ca_cert_der,
        }
    }

    /// Build a rustls `ClientConfig` that trusts only this fixture's CA.
    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.ca_cert_der.clone())
            .expect("add CA to root store");
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    }
}
