use crate::config::TlsConfig;
use crate::error::{HttpCliError, Result};
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::{certs, private_key};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use webpki_roots;

pub struct TlsConnector {
    config: TlsConfig,
    client_config: Arc<ClientConfig>,
}

impl TlsConnector {
    pub fn new(config: &TlsConfig) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client_config = Self::build_client_config(config)?;

        Ok(Self {
            config: config.clone(),
            client_config: Arc::new(client_config),
        })
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        self.client_config.clone()
    }

    fn build_client_config(config: &TlsConfig) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();

        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        if let Some(ref ca_cert_path) = config.ca_cert {
            Self::load_ca_certificates(&mut root_store, ca_cert_path)?;
        }

        let config_builder = ClientConfig::builder().with_root_certificates(root_store);

        let mut client_config = if let (Some(ref cert_path), Some(ref key_path)) =
            (&config.client_cert, &config.client_key)
        {
            let cert_chain = Self::load_client_certificate(cert_path)?;
            let private_key = Self::load_private_key(key_path)?;

            config_builder
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|e| {
                    HttpCliError::Tls(rustls::Error::General(format!("Client cert error: {}", e)))
                })?
        } else {
            config_builder.with_no_client_auth()
        };

        Self::configure_protocol_versions(&mut client_config, config)?;

        if !config.verify {
            client_config = Self::disable_verification(client_config)?;
        }

        Ok(client_config)
    }

    fn load_ca_certificates(
        root_store: &mut RootCertStore,
        ca_cert_path: &std::path::Path,
    ) -> Result<()> {
        let ca_file = File::open(ca_cert_path)?;
        let mut ca_reader = BufReader::new(ca_file);

        let ca_certs = certs(&mut ca_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                HttpCliError::Tls(rustls::Error::General(format!(
                    "CA cert parsing error: {}",
                    e
                )))
            })?;

        for cert in ca_certs {
            root_store.add(cert).map_err(|e| {
                HttpCliError::Tls(rustls::Error::General(format!("CA cert add error: {}", e)))
            })?;
        }

        Ok(())
    }

    fn load_client_certificate(
        cert_path: &std::path::Path,
    ) -> Result<Vec<CertificateDer<'static>>> {
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);

        let cert_chain = certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                HttpCliError::Tls(rustls::Error::General(format!(
                    "Client cert parsing error: {}",
                    e
                )))
            })?;

        Ok(cert_chain)
    }

    fn load_private_key(key_path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);

        private_key(&mut key_reader)
            .map_err(|e| {
                HttpCliError::Tls(rustls::Error::General(format!(
                    "Private key parsing error: {}",
                    e
                )))
            })?
            .ok_or_else(|| {
                HttpCliError::Tls(rustls::Error::General(
                    "No valid private key found in file".to_string(),
                ))
            })
    }

    fn configure_protocol_versions(
        _client_config: &mut ClientConfig,
        config: &TlsConfig,
    ) -> Result<()> {
        // rustls 0.23 doesn't support runtime protocol version config
        tracing::info!(
            "TLS version range: {} - {}",
            config.min_version,
            config.max_version
        );

        Ok(())
    }

    fn disable_verification(mut client_config: ClientConfig) -> Result<ClientConfig> {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, Error, SignatureScheme};

        #[derive(Debug)]
        struct AcceptAllVerifier;

        impl ServerCertVerifier for AcceptAllVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> std::result::Result<ServerCertVerified, Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::RSA_PKCS1_SHA1,
                    SignatureScheme::ECDSA_SHA1_Legacy,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::ED25519,
                    SignatureScheme::ED448,
                ]
            }
        }

        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAllVerifier));

        tracing::warn!("TLS certificate verification is DISABLED - this is insecure!");
        Ok(client_config)
    }

    pub fn validate_config(config: &TlsConfig) -> Result<()> {
        if let Some(ref ca_cert_path) = config.ca_cert {
            if !ca_cert_path.exists() {
                return Err(HttpCliError::Config(format!(
                    "CA certificate file not found: {}",
                    ca_cert_path.display()
                )));
            }
        }

        if let Some(ref cert_path) = config.client_cert {
            if !cert_path.exists() {
                return Err(HttpCliError::Config(format!(
                    "Client certificate file not found: {}",
                    cert_path.display()
                )));
            }
        }

        if let Some(ref key_path) = config.client_key {
            if !key_path.exists() {
                return Err(HttpCliError::Config(format!(
                    "Client private key file not found: {}",
                    key_path.display()
                )));
            }
        }

        match (&config.client_cert, &config.client_key) {
            (Some(_), None) => {
                return Err(HttpCliError::Config(
                    "Client certificate provided but private key is missing".to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(HttpCliError::Config(
                    "Client private key provided but certificate is missing".to_string(),
                ));
            }
            _ => {}
        }

        Ok(())
    }

    pub fn get_connection_info(&self) -> TlsConnectionInfo {
        TlsConnectionInfo {
            verify_enabled: self.config.verify,
            ca_cert_path: self.config.ca_cert.clone(),
            client_cert_path: self.config.client_cert.clone(),
            min_version: self.config.min_version.clone(),
            max_version: self.config.max_version.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsConnectionInfo {
    pub verify_enabled: bool,
    pub ca_cert_path: Option<std::path::PathBuf>,
    pub client_cert_path: Option<std::path::PathBuf>,
    pub min_version: String,
    pub max_version: String,
}

impl TlsConnectionInfo {
    pub fn display(&self) {
        println!("TLS Configuration:");
        println!(
            "  Verification: {}",
            if self.verify_enabled {
                "enabled"
            } else {
                "DISABLED"
            }
        );
        println!(
            "  Protocol versions: {} - {}",
            self.min_version, self.max_version
        );

        if let Some(ref ca_cert) = self.ca_cert_path {
            println!("  CA Certificate: {}", ca_cert.display());
        }

        if let Some(ref client_cert) = self.client_cert_path {
            println!("  Client Certificate: {}", client_cert.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_test_tls_config() -> TlsConfig {
        TlsConfig {
            verify: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            min_version: "1.2".to_string(),
            max_version: "1.3".to_string(),
            ciphers: vec![],
        }
    }

    #[test]
    fn test_tls_connector_creation() {
        let config = create_test_tls_config();
        let result = TlsConnector::new(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = create_test_tls_config();

        assert!(TlsConnector::validate_config(&config).is_ok());

        config.client_cert = Some(PathBuf::from("/nonexistent/cert.pem"));
        assert!(TlsConnector::validate_config(&config).is_err());
    }

    #[test]
    fn test_cert_key_validation() {
        let mut config = create_test_tls_config();

        config.client_cert = Some(PathBuf::from("cert.pem"));
        assert!(TlsConnector::validate_config(&config).is_err());

        config.client_cert = None;
        config.client_key = Some(PathBuf::from("key.pem"));
        assert!(TlsConnector::validate_config(&config).is_err());
    }
}

