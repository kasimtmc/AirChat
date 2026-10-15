//! The parts of an X.509 certificate (RFC 5280) a key attestation chain needs: what is signed, by
//! which algorithm, the serial number, the public key, and Android's attestation extension.

use super::{
    AttestError,
    der::{self, BIT_STRING, CONTEXT, INTEGER, OCTET_STRING, OID, SEQUENCE},
};
use crate::crypto::certsig::{CertAlgorithm, CertKey};

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// 1.3.6.1.4.1.11129.2.1.17: Android's key description.
const KEY_DESCRIPTION: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];

pub struct Cert<'a> {
    /// The TBSCertificate, as signed.
    pub tbs: &'a [u8],
    pub algorithm: CertAlgorithm,
    pub signature: &'a [u8],
    /// The serial number in lowercase hexadecimal without leading zeros, as Google's revocation
    /// list writes it.
    pub serial: String,
    pub key: CertKey<'a>,
    /// The DER of the key description, if the certificate has the extension.
    pub key_description: Option<&'a [u8]>,
}

pub fn parse(bytes: &[u8]) -> Result<Cert<'_>, AttestError> {
    let mut outer = der::single(bytes)?.children(SEQUENCE)?;
    let tbs = outer.take()?;
    let algorithm = signature_algorithm(outer.take()?)?;
    let signature = bit_string(outer.take()?)?;
    outer.end()?;

    let mut fields = tbs.children(SEQUENCE)?;
    let mut serial = fields.take()?;
    if serial.class == CONTEXT && serial.tag == 0 {
        serial = fields.take()?; // after the version
    }
    let serial = hex_without_leading_zeros(serial.expect(INTEGER)?);
    if signature_algorithm(fields.take()?)? != algorithm {
        return Err(AttestError::Malformed);
    }
    let _issuer = fields.take()?;
    let _validity = fields.take()?;
    let _subject = fields.take()?;
    let key = public_key(fields.take()?)?;
    let mut key_description = None;
    while let Some(field) = fields.element()? {
        // [1] and [2] are unique ids; [3] holds the extensions.
        if field.class != CONTEXT || field.tag != 3 {
            continue;
        }
        let mut extensions = der::single(field.content)?.children(SEQUENCE)?;
        while let Some(extension) = extensions.element()? {
            let mut parts = extension.children(SEQUENCE)?;
            let id = parts.take()?.expect(OID)?;
            let mut value = parts.take()?;
            if value.is(der::BOOLEAN) {
                value = parts.take()?; // critical
            }
            parts.end()?;
            if id == KEY_DESCRIPTION {
                if key_description.is_some() {
                    return Err(AttestError::Malformed);
                }
                key_description = Some(value.expect(OCTET_STRING)?);
            }
        }
    }
    Ok(Cert {
        tbs: tbs.raw,
        algorithm,
        signature,
        serial,
        key,
        key_description,
    })
}

fn signature_algorithm(tlv: der::Tlv<'_>) -> Result<CertAlgorithm, AttestError> {
    let mut parts = tlv.children(SEQUENCE)?;
    Ok(match parts.take()?.expect(OID)? {
        ECDSA_SHA256 => CertAlgorithm::EcdsaSha256,
        ECDSA_SHA384 => CertAlgorithm::EcdsaSha384,
        RSA_SHA256 => CertAlgorithm::RsaSha256,
        RSA_SHA384 => CertAlgorithm::RsaSha384,
        RSA_SHA512 => CertAlgorithm::RsaSha512,
        _ => return Err(AttestError::Untrusted),
    })
}

fn public_key(tlv: der::Tlv<'_>) -> Result<CertKey<'_>, AttestError> {
    let mut parts = tlv.children(SEQUENCE)?;
    let mut algorithm = parts.take()?.children(SEQUENCE)?;
    let key = bit_string(parts.take()?)?;
    parts.end()?;
    match algorithm.take()?.expect(OID)? {
        EC_PUBLIC_KEY => match algorithm.take()?.expect(OID)? {
            P256 => Ok(CertKey::P256(key)),
            P384 => Ok(CertKey::P384(key)),
            _ => Err(AttestError::Untrusted),
        },
        RSA_ENCRYPTION => Ok(CertKey::Rsa(key)),
        _ => Err(AttestError::Untrusted),
    }
}

/// A BIT STRING of whole bytes.
fn bit_string(tlv: der::Tlv<'_>) -> Result<&[u8], AttestError> {
    match tlv.expect(BIT_STRING)?.split_first() {
        Some((0, bits)) => Ok(bits),
        _ => Err(AttestError::Malformed),
    }
}

fn hex_without_leading_zeros(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}
