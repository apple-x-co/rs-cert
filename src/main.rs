mod cert;
mod checker;

use checker::Checker;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    hostname: String,
}

fn main() {
    let args = Args::parse();
    let hostname = args.hostname;

    let cert = Checker::check(hostname.as_str(), 443);
    println!("Version: {}", cert.version);
    println!("Serial: {}", cert.serial);
    println!("Subject: {}", cert.subject);
    println!("Issuer: {}", cert.issuer);
    println!("Validity:");
    println!("  NotBefore: {}", cert.validity.not_before);
    println!("  NotAfter: {}", cert.validity.not_after);
    println!("  is_valid: {}", cert.validity.is_valid);
}