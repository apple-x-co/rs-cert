use crate::cert::Cert;
use rustls::RootCertStore;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

pub struct Checker {}

impl Checker {
    /// TLS 証明書を取得する
    pub fn check(hostname: &str, port: i32) -> Cert {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.key_log = Arc::new(rustls::KeyLogFile::new());

        let server_name = format!("{hostname}").try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = TcpStream::connect(format!("{}:{}", hostname, port)).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.flush().unwrap();
        let peer_cert = conn.peer_certificates()
            .expect("Failed to get peer certificates.").first().unwrap();

        let x509 = X509Certificate::from_der(peer_cert.as_bytes());

        match x509 {
            Ok((_rem, cert)) => Cert::new(
                cert.version().to_string().as_str(),
                cert.tbs_certificate.raw_serial_as_string().as_str(),
                cert.subject().to_string().as_str(),
                cert.issuer().to_string().as_str(),
                cert.validity().not_before.to_string().as_str(),
                cert.validity().not_after.to_string().as_str(),
                cert.validity().is_valid(),
            ),
            _ => panic!("x509 parsing failed: {:?}", x509),
        }
    }
}