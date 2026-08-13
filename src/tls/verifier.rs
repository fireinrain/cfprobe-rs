use std::fmt;
use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, Error,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

#[derive(Clone)]
pub struct ObservationVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ObservationVerifier {
    pub fn new(algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self { algorithms }
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl fmt::Debug for ObservationVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservationVerifier").finish()
    }
}

impl ServerCertVerifier for ObservationVerifier {
    fn verify_server_cert(
        &self,

        _end_entity: &CertificateDer<'_>,

        _intermediates: &[CertificateDer<'_>],

        _server_name: &ServerName<'_>,

        _ocsp_response: &[u8],

        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        /*
         * Important:
         *
         * This verifier is ONLY used by the TLS
         * observation path.
         *
         * It deliberately does not validate:
         *
         * - trust chain
         * - hostname
         * - expiration
         * - revocation
         *
         * The TLS cryptographic handshake signatures
         * are still verified below.
         */
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,

        message: &[u8],

        cert: &CertificateDer<'_>,

        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,

        message: &[u8],

        cert: &CertificateDer<'_>,

        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }
}
