//! Generate self-signed TLS material for tests that exercise the proxy's
//! inbound TLS listener. `rcgen` builds an ephemeral CA + leaf so the test
//! client can trust the server cert via a custom RootCertStore without any
//! committed PEM fixtures in the repo.

use std::path::{Path, PathBuf};
use std::sync::Arc;

#[allow(dead_code)] // used by tests/tls.rs; passthrough.rs compiles common/ separately
pub struct TlsCerts {
    /// Path to the server certificate (PEM, leaf only).
    pub cert_path: PathBuf,
    /// Path to the server private key (PEM, PKCS8).
    pub key_path: PathBuf,
    /// Path to the CA certificate (PEM). For mTLS, the listener's
    /// `listen.tls.ca_file` should point here.
    pub ca_cert_pem_path: PathBuf,
    /// In-memory CA cert as DER. Use to build a `RootCertStore` for the test
    /// client so it trusts the server cert.
    pub ca_cert_der: rustls::pki_types::CertificateDer<'static>,
    // Retained so we can sign additional certs (client certs) with the same CA.
    ca_key: rcgen::KeyPair,
    ca_cert: rcgen::Certificate,
}

#[allow(dead_code)]
pub struct ClientCert {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Parsed cert chain ready to hand to a rustls `ClientConfig`.
    pub cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// Parsed private key ready to hand to a rustls `ClientConfig`.
    pub private_key: rustls::pki_types::PrivateKeyDer<'static>,
}

#[allow(dead_code)]
impl TlsCerts {
    /// Generate a CA, then a leaf cert signed by it whose subjectAltName
    /// matches `server_name`. Writes the leaf cert, key, and CA cert to PEM
    /// files in `dir`.
    pub fn generate(dir: &Path, server_name: &str) -> Self {
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

        // Leaf server cert signed by the CA.
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
        let ca_cert_pem_path = dir.join("ca.crt");
        std::fs::write(&cert_path, leaf_cert.pem()).expect("write cert");
        std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write key");
        std::fs::write(&ca_cert_pem_path, ca_cert.pem()).expect("write ca cert");

        let ca_cert_der = rustls::pki_types::CertificateDer::from(ca_cert.der().to_vec());

        Self {
            cert_path,
            key_path,
            ca_cert_pem_path,
            ca_cert_der,
            ca_key,
            ca_cert,
        }
    }

    /// Build a rustls `ClientConfig` that trusts only this fixture's CA.
    /// No client auth.
    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        Self::install_default_crypto();
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(self.root_store())
            .with_no_client_auth();
        Arc::new(cfg)
    }

    /// Build a rustls `ClientConfig` that trusts this fixture's CA AND
    /// presents the supplied client cert for mTLS.
    pub fn client_config_with_auth(&self, client: &ClientCert) -> Arc<rustls::ClientConfig> {
        Self::install_default_crypto();
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(self.root_store())
            .with_client_auth_cert(client.cert_chain.clone(), client.private_key.clone_key())
            .unwrap_or_else(|e| panic!("build client config with auth: {e}"));
        Arc::new(cfg)
    }

    /// Mint a client cert signed by this fixture's CA (so the proxy listener
    /// configured with this fixture's `ca_cert_pem_path` will accept it).
    pub fn issue_client_cert(&self, dir: &Path, name: &str) -> ClientCert {
        let client_key = rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("client key: {e}"));
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap_or_else(|e| panic!("client params: {e}"));
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let cert = params
            .signed_by(&client_key, &self.ca_cert, &self.ca_key)
            .unwrap_or_else(|e| panic!("sign client cert: {e}"));

        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).expect("write client cert");
        std::fs::write(&key_path, client_key.serialize_pem()).expect("write client key");

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(client_key.serialize_der())
            .unwrap_or_else(|e| panic!("private key into rustls: {e}"));

        ClientCert {
            cert_path,
            key_path,
            cert_chain,
            private_key,
        }
    }

    fn root_store(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.ca_cert_der.clone())
            .expect("add CA to root store");
        roots
    }

    fn install_default_crypto() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
