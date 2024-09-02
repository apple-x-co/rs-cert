# rs-cert

```bash
./rs-cert --hostname example.com
```

```text
Version: V3
Serial: 07:5b:ce:f3:06:89:c8:ad:df:13:e5:1a:f4:af:e1:87
Subject: C=US, ST=California, L=Los Angeles, O=Internet Corporation for Assigned Names and Numbers, CN=www.example.org
Issuer: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
Validity:
  NotBefore: Jan 30 00:00:00 2024 +00:00
  NotAfter: Mar  1 23:59:59 2025 +00:00
  is_valid: true
```

## compile

```text
$ cargo --version
cargo 1.80.1 (376290515 2024-07-16)
```

### On M2 macOS

```bash
# cargo check
# cargo build # dev profile
cargo build --release
```

### For Linux

```bash
# cargo install cross
# docker pull ghcr.io/cross-rs/x86_64-unknown-linux-musl:0.2.5 --platform=linux/amd64
cross build --release --target=x86_64-unknown-linux-musl
```