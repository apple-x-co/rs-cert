mod cert;

use clap::Parser;
use rustls::RootCertStore;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    hostname: String,
}

fn main() {
    let args = Args::parse();

    let hostname = args.hostname;
    let port = 443;

    // ---
    // Use "native-tls"
    // ---
    // let addr = format!("{}:{}", hostname, port);
    // let mut stream = TcpStream::connect(&addr).expect("Failed to connect.");
    // let connector = TlsConnector::new().expect("Failed to create TLS connector.");
    // let tls_stream = connector.connect(hostname, stream).expect("Failed to connect with TLS.");
    // let cert = tls_stream.peer_certificate().expect("Failed to get certificates.").unwrap();
    // let der = cert.to_der().expect("Failed convert to DER");
    // let x509 = X509Certificate::from_der(&*der);

    // ---
    // Use "rustls"
    // ---
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

    // Display
    let cert = match x509 {
        Ok((_rem, cert)) => cert::Cert::new(
            cert.version().to_string().as_str(),
            cert.tbs_certificate.raw_serial_as_string().as_str(),
            cert.subject().to_string().as_str(),
            cert.issuer().to_string().as_str(),
            cert.validity().not_before.to_string().as_str(),
            cert.validity().not_after.to_string().as_str(),
            cert.validity().is_valid(),
        ),
        _ => panic!("x509 parsing failed: {:?}", x509),
    };

    println!("Version: {}", cert.version);
    println!("Serial: {}", cert.serial);
    println!("Subject: {}", cert.subject);
    println!("Issuer: {}", cert.issuer);
    println!("Validity:");
    println!("  NotBefore: {}", cert.validity.not_before);
    println!("  NotAfter: {}", cert.validity.not_after);
    println!("  is_valid: {}", cert.validity.is_valid);
}