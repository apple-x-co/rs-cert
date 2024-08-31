use native_tls::TlsConnector;
use std::net::TcpStream;
use clap::{App, Arg};
use x509_parser::prelude::*;

fn main() {
    let args = App::new("rs-cert")
        .version("0.1")
        .about("TLS certificate information")
        .arg(Arg::with_name("hostname")
            .help("For verifying certificate")
            .takes_value(true)
            .required(true))
        .get_matches();

    let hostname = args.value_of("hostname").unwrap();
    let port = 443;

    let addr = format!("{}:{}", hostname, port);
    let stream = TcpStream::connect(&addr).expect("Failed to connect.");

    let connector = TlsConnector::new().expect("Failed to create TLS connector.");
    let tls_stream = connector.connect(hostname, stream).expect("Failed to connect with TLS.");
    let cert = tls_stream.peer_certificate().expect("Failed to get certificates.").unwrap();
    let der = cert.to_der().expect("Failed convert to DER");
    let x509 = X509Certificate::from_der(&*der);

    match x509 {
        Ok((rem, cert)) => {
            assert!(rem.is_empty());

            println!("Version: {}", cert.version());
            println!("Serial: {}", cert.tbs_certificate.raw_serial_as_string());
            println!("Subject: {}", cert.subject());
            println!("Issuer: {}", cert.issuer());
            println!("Validity:");
            println!("  NotBefore: {}", cert.validity().not_before);
            println!("  NotAfter: {}", cert.validity().not_after);
            println!("  is_valid: {}", cert.validity().is_valid());
        }
        _ => panic!("x509 parsing failed: {:?}", x509),
    }
}