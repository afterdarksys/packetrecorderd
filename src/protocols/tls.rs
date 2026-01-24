use anyhow::Result;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension, TlsExtensionType};
use openssl::hash::{hash, MessageDigest};
use super::{ProtocolInfo, TlsInfo};
use x509_parser::prelude::*;

pub struct TlsParser;

const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

impl TlsParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // Simple wrapper around tls-parser
        match parse_tls_plaintext(data) {
            Ok((_, plaintext)) => {
                for msg in plaintext.msg {
                    if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
                        // Extract SNI and JA3 components
                        let mut sni = None;
                        let mut ja3_ciphers = Vec::new();
                        let mut ja3_extensions = Vec::new();
                        let mut ja3_curves = Vec::new();
                        let mut ja3_points = Vec::new();

                        // JA3: SSL Version (decimal)
                        let ja3_version = u16::from(client_hello.version);

                        // JA3: Ciphers
                        for cipher in client_hello.ciphers {
                             let c = u16::from(cipher);
                             if !GREASE_VALUES.contains(&c) {
                                 ja3_ciphers.push(c.to_string());
                             }
                        }

                        if let Some(extensions) = client_hello.ext {
                            if let Ok((_, exts)) = tls_parser::parse_tls_extensions(extensions) {
                                for ext in exts {
                                    let ext_type = u16::from(TlsExtensionType::from(&ext)); // Get extension type
                                    
                                    if !GREASE_VALUES.contains(&ext_type) {
                                        ja3_extensions.push(ext_type.to_string());
                                    }

                                    match ext {
                                        TlsExtension::SNI(sni_ext) => {
                                            if !sni_ext.is_empty() {
                                                sni = Some(String::from_utf8_lossy(sni_ext[0].1).to_string());
                                            }
                                        },
                                        TlsExtension::EllipticCurves(curves) => {
                                            for curve in curves {
                                                let c = curve.0;
                                                if !GREASE_VALUES.contains(&c) {
                                                    ja3_curves.push(c.to_string());
                                                }
                                            }
                                        },
                                        TlsExtension::EcPointFormats(formats) => {
                                            for format in formats {
                                                ja3_points.push(format.to_string());
                                            }
                                        },
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Construct JA3 String
                        // SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
                        let ja3_string = format!(
                            "{},{},{},{},{}",
                            ja3_version,
                            ja3_ciphers.join("-"),
                            ja3_extensions.join("-"),
                            ja3_curves.join("-"),
                            ja3_points.join("-")
                        );

                        // MD5 Hash
                        let ja3_hash = hash(MessageDigest::md5(), ja3_string.as_bytes())
                            .map(hex::encode)
                            .ok();

                        return Ok(ProtocolInfo::Tls(TlsInfo {
                            version: format!("{:?}", client_hello.version),
                            sni,
                            ja3: ja3_hash,
                            ja3_string: Some(ja3_string),
                            server_certificates: None,
                        }));
                    }
                    
                    // Parse Server Hello / Certificate
                    if let TlsMessage::Handshake(TlsMessageHandshake::Certificate(cert_msg)) = msg {
                        let mut cert_names = Vec::new();
                        
                        // cert_msg.cert_chain is Vec<(u32, Vec<u8>)> usually? 
                        // tls-parser 0.11: Certificate(TlsCertificate)
                        // TlsCertificate { cert_chain: Vec<RawCertificate> }
                        // RawCertificate { data: &[u8] }
                        
                        for cert_data in &cert_msg.cert_chain {
                             if let Ok((_, x509)) = X509Certificate::from_der(cert_data.data) {
                                 // Get Subject Common Name
                                 for cn in x509.subject().iter_common_name() {
                                     if let Ok(s) = cn.as_str() {
                                         cert_names.push(format!("CN={}", s));
                                     }
                                 }
                                 
                                 // Get SANs
                                 if let Ok(Some(sans)) = x509.subject_alternative_name() {
                                     for name in &sans.value.general_names {
                                         match name {
                                             GeneralName::DNSName(dns) => {
                                                 cert_names.push(format!("SAN=DNS:{}", dns));
                                             },
                                             GeneralName::IPAddress(ip) => {
                                                 cert_names.push(format!("SAN=IP:{:?}", ip));
                                             },
                                             _ => {}
                                         }
                                     }
                                 }
                             }
                        }

                        if !cert_names.is_empty() {
                            return Ok(ProtocolInfo::Tls(TlsInfo {
                                version: "ServerCertificate".to_string(),
                                sni: None,
                                ja3: None,
                                ja3_string: None,
                                server_certificates: Some(cert_names),
                            }));
                        }
                    }
                }
                Ok(ProtocolInfo::Unknown)
            },
            Err(_) => Ok(ProtocolInfo::Unknown),
        }
    }
}
