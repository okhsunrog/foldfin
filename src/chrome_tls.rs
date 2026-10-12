//! Experimental Chrome profile derived from captures, retaining TLS verification.
use anyhow::{Result, bail};
use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, KeyShare, SslConnector, SslMethod,
    SslSignatureAlgorithm, SslVersion,
};
use std::{io::Write, pin::Pin};
use tokio::net::TcpStream;
use tokio_btls::SslStream;

struct BrotliCertificates;

impl CertificateCompressor for BrotliCertificates {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        brotli::BrotliDecompress(&mut &input[..], output)
    }
}

pub async fn connect(
    tcp: TcpStream,
    name: &str,
    ca: Option<&[u8]>,
) -> Result<SslStream<TcpStream>> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    if let Some(ca) = ca {
        for certificate in btls::x509::X509::stack_from_pem(ca)? {
            builder.cert_store_mut().add_cert(certificate)?;
        }
    }
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_grease_enabled(true);
    builder.set_grease_sigalgs_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_cipher_list(concat!(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:",
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    ))?;
    builder.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")?;
    builder.set_verify_algorithm_prefs(&[
        SslSignatureAlgorithm::ML_DSA_44,
        SslSignatureAlgorithm::ML_DSA_65,
        SslSignatureAlgorithm::ML_DSA_87,
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA512,
    ])?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    builder.add_certificate_compression_algorithm(BrotliCertificates)?;
    let connector = builder.build();
    // into_ssl keeps both peer chain and hostname verification enabled.
    let mut ssl = connector.configure()?.into_ssl(name)?;
    ssl.set_enable_ech_grease(true);
    ssl.set_alps_use_new_codepoint(true);
    ssl.add_application_settings(b"h2", None)?;
    ssl.set_client_key_shares(&[KeyShare::X25519_MLKEM768, KeyShare::X25519])?;
    let anchors = include_bytes!("../profiles/chrome-154-trust-anchors.bin");
    // This only advertises IDs and never bypasses certificate verification.
    ssl.set_requested_trust_anchors(anchors)?;
    let mut tls = SslStream::new(ssl, tcp)?;
    Pin::new(&mut tls).connect().await?;
    if tls.ssl().selected_alpn_protocol() != Some(b"h2".as_slice()) {
        bail!("server did not negotiate h2");
    }
    Ok(tls)
}
