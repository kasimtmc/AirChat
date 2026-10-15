//! Verified builds (docs/protocol.md §6.10): an Android key attestation shows that a contact's
//! AirChat is the official build, on a phone whose bootloader is locked and whose system is
//! verified. The phone's secure hardware signs a certificate for a key it made; the chain of that
//! certificate leads to Google's attestation roots, and the certificate says which app (package
//! and signing certificate) asked for the key, the state of the phone's boot, and a challenge
//! bound to this AirChat identity. That key then signs each link's handshake hash, so a chain
//! cannot be replayed elsewhere.
//!
//! A sign, not a proof: phones whose attestation keys leaked can fake it until Google revokes
//! them, and the revocation list here is only as recent as the build.

pub mod der;

mod cert;
mod roots;

use crate::{
    crypto::{
        certsig::{self, CertAlgorithm, CertKey},
        hash::sha256,
    },
    identity::PublicIdentity,
    labels,
};
use der::{CONTEXT, ENUMERATED, INTEGER, OCTET_STRING, SEQUENCE, SET};

/// The package official builds are.
pub const PACKAGE: &str = "com.plyg.airchat";
/// SHA-256 of the certificate official builds are signed with.
pub const OFFICIAL_SIGNER: [u8; 32] = [
    0x29, 0x9e, 0x51, 0x34, 0xcc, 0x07, 0x03, 0x26, 0x2f, 0x93, 0xd5, 0xe8, 0x1e, 0x84, 0xb2, 0xf8, 0xa0, 0x3f, 0xdd,
    0x84, 0x64, 0x4e, 0x9e, 0xe4, 0x40, 0xcf, 0xc1, 0x9e, 0x17, 0xc6, 0x5d, 0xb5,
];
/// Certificates a chain may carry (the root may be left out) and how large each may be.
pub const MAX_CERTS: usize = 5;
pub const MAX_CERT_LEN: usize = 3 * 1024;

/// The revoked and suspended serial numbers, as `scripts/update-attestation-status.py` fetched them.
const REVOKED: &str = include_str!("revoked.txt");

/// Tags of Android's authorization list (KeyMint's Tag.aidl).
const ROOT_OF_TRUST: u32 = 704;
const OS_PATCH_LEVEL: u32 = 706;
const APPLICATION_ID: u32 = 709;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    #[error("malformed attestation")]
    Malformed,
    #[error("the chain does not lead to a trusted root")]
    Untrusted,
    #[error("a certificate of the chain is revoked")]
    Revoked,
    #[error("the attestation is not this identity's")]
    Challenge,
    #[error("not attested by secure hardware")]
    Software,
    #[error("not the official build")]
    NotOfficial,
    #[error("the phone's bootloader is unlocked or its system not verified")]
    DeviceNotVerified,
    #[error("the attested key did not sign this link")]
    Proof,
}

/// Where the attested key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    TrustedEnvironment,
    StrongBox,
}

/// What a verified attestation says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attested {
    pub level: SecurityLevel,
    /// The phone's security patch level as YYYYMM (or YYYYMMDD), 0 if not given.
    pub os_patch_level: u32,
}

/// A trusted root key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootKey {
    Rsa(Vec<u8>),
    P256(Vec<u8>),
    P384(Vec<u8>),
}

impl RootKey {
    fn key(&self) -> CertKey<'_> {
        match self {
            Self::Rsa(key) => CertKey::Rsa(key),
            Self::P256(key) => CertKey::P256(key),
            Self::P384(key) => CertKey::P384(key),
        }
    }
}

/// What a verification trusts: roots, signing certificates of the app, revoked serials.
pub struct Trust {
    roots: Vec<RootKey>,
    signers: Vec<[u8; 32]>,
    revoked: Vec<String>,
}

impl Trust {
    /// Google's roots, the revocation list compiled in, and the official signer; `extra_signers`
    /// is for debug builds, which test with their own signing certificate.
    pub fn google(extra_signers: &[[u8; 32]]) -> Self {
        Self {
            roots: vec![
                RootKey::Rsa(roots::RSA_4096.to_vec()),
                RootKey::P384(roots::P384_CA1.to_vec()),
            ],
            signers: std::iter::once(OFFICIAL_SIGNER)
                .chain(extra_signers.iter().copied())
                .collect(),
            revoked: REVOKED
                .lines()
                .filter(|line| !line.starts_with('#') && !line.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }

    /// Other roots and signers, for tests and the published test vector.
    pub fn new(roots: Vec<RootKey>, signers: Vec<[u8; 32]>, revoked: Vec<String>) -> Self {
        Self {
            roots,
            signers,
            revoked,
        }
    }
}

/// The challenge this identity's attestation carries.
pub fn challenge(identity: &PublicIdentity) -> [u8; 32] {
    sha256(&[labels::BUILD_ATTEST_CHALLENGE, identity.as_bytes()])
}

/// What the attested key signs on a link: the label and the handshake hash.
pub fn proof_message(handshake_hash: &[u8; 32]) -> Vec<u8> {
    [labels::BUILD_ATTEST_PROOF, handshake_hash].concat()
}

/// Checks `chain` (the attested certificate first; the root may be left out) as the attestation
/// of `identity`'s official build on a verified phone, and `proof` as its key's signature over
/// this link's `handshake_hash`.
pub fn verify(
    chain: &[Vec<u8>],
    identity: &PublicIdentity,
    handshake_hash: &[u8; 32],
    proof: &[u8],
    trust: &Trust,
) -> Result<Attested, AttestError> {
    if chain.is_empty() || chain.len() > MAX_CERTS || chain.iter().any(|c| c.len() > MAX_CERT_LEN) {
        return Err(AttestError::Malformed);
    }
    let certs = chain.iter().map(|c| cert::parse(c)).collect::<Result<Vec<_>, _>>()?;
    if certs.iter().any(|c| trust.revoked.contains(&c.serial)) {
        return Err(AttestError::Revoked);
    }
    // Each certificate is signed by the next; the last by a root, unless it is one.
    for pair in certs.windows(2) {
        certsig::verify(pair[1].key, pair[0].algorithm, pair[0].tbs, pair[0].signature)
            .map_err(|_| AttestError::Untrusted)?;
    }
    let last = certs.last().ok_or(AttestError::Malformed)?;
    let anchored = trust.roots.iter().any(|root| {
        root.key() == last.key || certsig::verify(root.key(), last.algorithm, last.tbs, last.signature).is_ok()
    });
    if !anchored {
        return Err(AttestError::Untrusted);
    }
    // Only the attested certificate may carry a key description: anyone holding an attested key
    // can sign a certificate below it that says anything.
    if certs[1..].iter().any(|c| c.key_description.is_some()) {
        return Err(AttestError::Untrusted);
    }
    let description = KeyDescription::parse(certs[0].key_description.ok_or(AttestError::Malformed)?)?;
    if description.challenge != challenge(identity) {
        return Err(AttestError::Challenge);
    }
    // The app's identity comes from the system: trusted only on a locked, verified phone.
    if !description.locked || description.boot_state != 0 {
        return Err(AttestError::DeviceNotVerified);
    }
    let official = description.packages.len() == 1
        && description.packages[0] == PACKAGE.as_bytes()
        && !description.signers.is_empty()
        && description
            .signers
            .iter()
            .all(|s| trust.signers.iter().any(|t| t[..] == **s));
    if !official {
        return Err(AttestError::NotOfficial);
    }
    let CertKey::P256(_) = certs[0].key else {
        return Err(AttestError::Proof);
    };
    certsig::verify(
        certs[0].key,
        CertAlgorithm::EcdsaSha256,
        &proof_message(handshake_hash),
        proof,
    )
    .map_err(|_| AttestError::Proof)?;
    Ok(Attested {
        level: description.level,
        os_patch_level: description.os_patch_level,
    })
}

/// The parts of Android's KeyDescription that matter here
/// (source.android.com/docs/security/features/keystore/attestation#schema).
struct KeyDescription<'a> {
    level: SecurityLevel,
    challenge: &'a [u8],
    packages: Vec<&'a [u8]>,
    signers: Vec<&'a [u8]>,
    locked: bool,
    boot_state: u64,
    os_patch_level: u32,
}

impl<'a> KeyDescription<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, AttestError> {
        let mut fields = der::single(bytes)?.children(SEQUENCE)?;
        let _version = fields.take()?.small(INTEGER)?;
        let level = match fields.take()?.small(ENUMERATED)? {
            1 => SecurityLevel::TrustedEnvironment,
            2 => SecurityLevel::StrongBox,
            _ => return Err(AttestError::Software),
        };
        let _keymint_version = fields.take()?.small(INTEGER)?;
        if fields.take()?.small(ENUMERATED)? == 0 {
            return Err(AttestError::Software);
        }
        let challenge = fields.take()?.expect(OCTET_STRING)?;
        let _unique_id = fields.take()?.expect(OCTET_STRING)?;
        let software = authorizations(fields.take()?)?;
        let hardware = authorizations(fields.take()?)?;
        fields.end()?;

        // The application id is the system's (keystore's) word, in the software list.
        let application = software
            .iter()
            .chain(&hardware)
            .find(|(tag, _)| *tag == APPLICATION_ID)
            .ok_or(AttestError::NotOfficial)?
            .1;
        // An OCTET STRING holding the DER of a SEQUENCE.
        let mut application = der::single(application.expect(OCTET_STRING)?)?.children(SEQUENCE)?;
        let (packages, signers) = application_id(&mut application)?;

        // Root of trust and patch level only count when the secure hardware enforces them.
        let root = hardware
            .iter()
            .find(|(tag, _)| *tag == ROOT_OF_TRUST)
            .ok_or(AttestError::DeviceNotVerified)?
            .1;
        let mut root = root.children(SEQUENCE)?;
        let _boot_key = root.take()?.expect(OCTET_STRING)?;
        let locked = root.take()?.boolean()?;
        let boot_state = root.take()?.small(ENUMERATED)?;
        let os_patch_level = match hardware.iter().find(|(tag, _)| *tag == OS_PATCH_LEVEL) {
            Some((_, tlv)) => u32::try_from(tlv.small(INTEGER)?).map_err(|_| AttestError::Malformed)?,
            None => 0,
        };
        Ok(Self {
            level,
            challenge,
            packages,
            signers,
            locked,
            boot_state,
            os_patch_level,
        })
    }
}

/// An AuthorizationList: `[tag] EXPLICIT value`, each tag once.
fn authorizations(list: der::Tlv<'_>) -> Result<Vec<(u32, der::Tlv<'_>)>, AttestError> {
    let mut items = list.children(SEQUENCE)?;
    let mut out: Vec<(u32, der::Tlv<'_>)> = Vec::new();
    while let Some(item) = items.element()? {
        if item.class != CONTEXT || !item.constructed || out.iter().any(|(tag, _)| *tag == item.tag) {
            return Err(AttestError::Malformed);
        }
        out.push((item.tag, der::single(item.content)?));
    }
    Ok(out)
}

/// Several byte strings, borrowed from the attestation.
type Byteses<'a> = Vec<&'a [u8]>;

/// AttestationApplicationId: the packages (name, version) and the SHA-256 of their signing
/// certificates.
fn application_id<'a>(fields: &mut der::Reader<'a>) -> Result<(Byteses<'a>, Byteses<'a>), AttestError> {
    let mut packages = Vec::new();
    let mut infos = fields.take()?.children(SET)?;
    while let Some(info) = infos.element()? {
        let mut info = info.children(SEQUENCE)?;
        packages.push(info.take()?.expect(OCTET_STRING)?);
        let _version = info.take()?.expect(INTEGER)?;
        info.end()?;
    }
    let mut signers = Vec::new();
    let mut digests = fields.take()?.children(SET)?;
    while let Some(digest) = digests.element()? {
        signers.push(digest.expect(OCTET_STRING)?);
    }
    fields.end()?;
    Ok((packages, signers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            SecretBytes,
            test_util::{hex, hex_array, vector_field},
        },
        identity::Identity,
    };

    fn field(key: &str) -> String {
        vector_field("attestation", key)
    }

    fn trust() -> Trust {
        Trust::new(
            vec![RootKey::Rsa(hex(&field("root_rsa_public_key")))],
            vec![hex_array(&field("signer"))],
            Vec::new(),
        )
    }

    fn identity() -> PublicIdentity {
        Identity::from_seed(SecretBytes::from_slice(&hex(&field("identity_seed"))).unwrap()).public()
    }

    /// A chain of the vector and its proof.
    fn chain(name: &str) -> (Vec<Vec<u8>>, Vec<u8>) {
        (
            vec![
                hex(&field(&format!("{name}_leaf"))),
                hex(&field(&format!("{name}_intermediate"))),
            ],
            hex(&field(&format!("{name}_proof"))),
        )
    }

    fn hash() -> [u8; 32] {
        hex_array(&field("handshake_hash"))
    }

    /// `tests/vectors/attestation.json`, made by make_attestation.py; check_attestation.py checks
    /// it again from docs/protocol.md §6.10.
    #[test]
    fn the_published_vector_verifies() {
        assert_eq!(identity().as_bytes(), &hex_array(&field("identity")));
        assert_eq!(challenge(&identity()), hex_array(&field("challenge")));
        let (chain, proof) = chain("official");
        assert_eq!(
            verify(&chain, &identity(), &hash(), &proof, &trust()),
            Ok(Attested {
                level: SecurityLevel::TrustedEnvironment,
                os_patch_level: field("os_patch_level").parse().unwrap(),
            })
        );
    }

    #[test]
    fn only_the_official_build_on_a_verified_phone_passes() {
        let (official, proof) = chain("official");
        let check = |chain: &[Vec<u8>], proof: &[u8], trust: &Trust| verify(chain, &identity(), &hash(), proof, trust);
        let (unlocked, unlocked_proof) = chain("unlocked");
        assert_eq!(
            check(&unlocked, &unlocked_proof, &trust()),
            Err(AttestError::DeviceNotVerified)
        );
        let (other, other_proof) = chain("other_app");
        assert_eq!(check(&other, &other_proof, &trust()), Err(AttestError::NotOfficial));
        let stranger = Trust::new(trust().roots, vec![[0x11; 32]], Vec::new());
        assert_eq!(check(&official, &proof, &stranger), Err(AttestError::NotOfficial));
        // Another identity's, another link's.
        let other_identity = Identity::from_seed(SecretBytes::from_slice(&[0x0b; 32]).unwrap()).public();
        assert_eq!(
            verify(&official, &other_identity, &hash(), &proof, &trust()),
            Err(AttestError::Challenge)
        );
        assert_eq!(
            verify(&official, &identity(), &[0x5b; 32], &proof, &trust()),
            Err(AttestError::Proof)
        );
        // A revoked certificate anywhere in the chain.
        let revoked = Trust::new(trust().roots, trust().signers, vec!["1001".into()]);
        assert_eq!(check(&official, &proof, &revoked), Err(AttestError::Revoked));
        // Not under the trusted roots: Google's, or none (the leaf alone).
        assert_eq!(
            check(&official, &proof, &Trust::google(&[])),
            Err(AttestError::Untrusted)
        );
        assert_eq!(check(&official[..1], &proof, &trust()), Err(AttestError::Untrusted));
        // A changed certificate.
        let mut changed = official.clone();
        let middle = changed[0].len() / 2;
        changed[0][middle] ^= 1;
        assert!(check(&changed, &proof, &trust()).is_err());
        assert_eq!(check(&[], &proof, &trust()), Err(AttestError::Malformed));
        assert_eq!(
            check(&vec![official[0].clone(); 6], &proof, &trust()),
            Err(AttestError::Malformed)
        );
    }

    #[test]
    fn googles_roots_and_revocation_list_are_compiled_in() {
        let google = Trust::google(&[[0x22; 32]]);
        assert_eq!(google.roots.len(), 2);
        assert_eq!(google.signers, [OFFICIAL_SIGNER, [0x22; 32]]);
        assert!(google.revoked.len() > 1000);
        assert!(
            google
                .revoked
                .iter()
                .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
        );
    }
}
