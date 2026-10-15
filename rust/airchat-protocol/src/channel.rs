//! Walkie-talkie channels (docs/protocol.md §11): everyone holding a channel's key hears the
//! push-to-talk of the members around them. The key comes from a QR code or from a password; from
//! it derive the channel's id, the key of its beacons and the key its links start from. Formats and
//! cryptography only; links and voice live elsewhere.

use zeroize::Zeroizing;

use crate::{
    crypto::{
        CryptoError, SecretBytes,
        hash::{equal_in_constant_time, hmac_sha256, sha256},
        kdf,
        pin::{self, PinParams},
        random::{self, OsRng, Rng},
    },
    labels,
    link::{LinkError, TagKey},
    pairing::{QR_PREFIX, QR_VERSION, base32_decode, base32_encode},
};

pub const CHANNEL_ID_LEN: usize = 16;
pub type ChannelId = [u8; CHANNEL_ID_LEN];
pub const KEY_LEN: usize = 32;
/// A channel's name, as its QR code carries it and members see it.
pub const MAX_NAME_BYTES: usize = 64;
/// Shortest password a channel may be derived from; anyone who guesses it hears the channel.
pub const MIN_PASSWORD_CHARS: usize = 8;
/// A beacon: a random nonce and a MAC over it (§11.2).
pub const TOKEN_LEN: usize = 8;
const TOKEN_NONCE_LEN: usize = 4;
/// What a member tells the other end of a link about itself: a nonce naming its device while the
/// app runs, and the name it shows (§11.3).
pub const DEVICE_NONCE_LEN: usize = 16;
const QR_KIND_CHANNEL: u8 = 2;

pub type Token = [u8; TOKEN_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    #[error("not an AirChat channel code")]
    NotAChannel,
    #[error("a channel name needs 1 to {MAX_NAME_BYTES} bytes")]
    InvalidName,
    #[error("a channel password needs at least {MIN_PASSWORD_CHARS} characters")]
    PasswordTooShort,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// A channel's key and what derives from it.
pub struct Channel {
    key: SecretBytes<KEY_LEN>,
    id: ChannelId,
    presence_key: SecretBytes<32>,
    link_psk: SecretBytes<32>,
}

impl Channel {
    /// A new channel with a random key, to share by QR code.
    pub fn new() -> Result<Self, ChannelError> {
        Self::from_key(SecretBytes::random()?)
    }

    pub fn from_key(key: SecretBytes<KEY_LEN>) -> Result<Self, ChannelError> {
        let id = kdf::derive::<CHANNEL_ID_LEN>(&[], key.expose(), labels::CHANNEL_ID)?;
        Ok(Self {
            id: *id.expose(),
            presence_key: kdf::derive(&[], key.expose(), labels::CHANNEL_PRESENCE)?,
            link_psk: kdf::derive(&[], key.expose(), labels::CHANNEL_LINK_PSK)?,
            key,
        })
    }

    /// The channel everyone typing `password` reaches: its key is Argon2id of the password with
    /// a fixed salt, so the same password gives the same channel on every device.
    pub fn from_password(password: &str) -> Result<Self, ChannelError> {
        Self::from_password_with(password, PinParams::DEFAULT)
    }

    pub(crate) fn from_password_with(password: &str, params: PinParams) -> Result<Self, ChannelError> {
        if password.chars().count() < MIN_PASSWORD_CHARS {
            return Err(ChannelError::PasswordTooShort);
        }
        Self::from_key(pin::derive_key(password.as_bytes(), &password_salt(), params)?)
    }

    pub fn key(&self) -> &SecretBytes<KEY_LEN> {
        &self.key
    }

    pub fn id(&self) -> &ChannelId {
        &self.id
    }

    pub fn link_psk(&self) -> &SecretBytes<32> {
        &self.link_psk
    }

    /// Key of the tags on links between members.
    pub fn tag_key(&self) -> Result<TagKey, LinkError> {
        TagKey::for_channel(&self.link_psk, &self.id)
    }

    /// Key of the tags and proofs of paths to members through Air Providers (§11.5): every member
    /// holds it, so any of them answers.
    pub fn path_key(&self) -> Result<SecretBytes<32>, CryptoError> {
        kdf::derive(
            &[],
            self.link_psk.expose(),
            &[labels::CHANNEL_PATH_KEY, &self.id[..]].concat(),
        )
    }

    /// This device's beacon for `epoch`, with a fresh random nonce.
    pub fn token(&self, epoch: u64) -> Result<Token, ChannelError> {
        Ok(self.token_with(epoch, &random::array()?))
    }

    pub(crate) fn token_with(&self, epoch: u64, nonce: &[u8; TOKEN_NONCE_LEN]) -> Token {
        let mut token = [0; TOKEN_LEN];
        token[..TOKEN_NONCE_LEN].copy_from_slice(nonce);
        token[TOKEN_NONCE_LEN..].copy_from_slice(&self.token_mac(epoch, nonce));
        token
    }

    /// Whether another member made `token`, for `epoch` or its neighbours (clock skew). A chance
    /// match with a stranger costs one failed handshake.
    pub fn recognizes(&self, token: &Token, epoch: u64) -> bool {
        let (nonce, mac) = token.split_at(TOKEN_NONCE_LEN);
        (epoch.saturating_sub(1)..=epoch.saturating_add(1))
            .any(|e| equal_in_constant_time(&self.token_mac(e, nonce), mac))
    }

    fn token_mac(&self, epoch: u64, nonce: &[u8]) -> [u8; TOKEN_LEN - TOKEN_NONCE_LEN] {
        let mac = hmac_sha256(
            self.presence_key.expose(),
            &[labels::CHANNEL_TOKEN, &epoch.to_be_bytes(), nonce],
        );
        mac.expose()[..TOKEN_LEN - TOKEN_NONCE_LEN]
            .try_into()
            .expect("MAC is longer than its truncation")
    }

    /// The text of the channel's QR code: `AIRCHAT:` and Base32 of the key and the name.
    pub fn qr_text(&self, name: &str) -> Result<Zeroizing<String>, ChannelError> {
        check_name(name)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(2 + KEY_LEN + name.len()));
        payload.extend_from_slice(&[QR_VERSION, QR_KIND_CHANNEL]);
        payload.extend_from_slice(self.key.expose());
        payload.extend_from_slice(name.as_bytes());
        let mut text = Zeroizing::new(String::from(QR_PREFIX));
        text.push_str(&base32_encode(&payload));
        Ok(text)
    }

    /// A channel and its name read from a QR code.
    pub fn parse_qr(text: &str) -> Result<(Self, String), ChannelError> {
        let encoded = text.trim().strip_prefix(QR_PREFIX).ok_or(ChannelError::NotAChannel)?;
        let payload = base32_decode(encoded).ok_or(ChannelError::NotAChannel)?;
        match payload.as_slice() {
            [QR_VERSION, QR_KIND_CHANNEL, rest @ ..] if rest.len() > KEY_LEN => {
                let (key, name) = rest.split_at(KEY_LEN);
                let name = std::str::from_utf8(name).map_err(|_| ChannelError::NotAChannel)?;
                check_name(name).map_err(|_| ChannelError::NotAChannel)?;
                Ok((Self::from_key(SecretBytes::from_slice(key)?)?, name.to_owned()))
            }
            _ => Err(ChannelError::NotAChannel),
        }
    }
}

pub fn check_name(name: &str) -> Result<(), ChannelError> {
    if name.trim().is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(ChannelError::InvalidName);
    }
    Ok(())
}

/// The salt of password-derived keys: the same everywhere, so a password names one channel.
fn password_salt() -> [u8; pin::SALT_LEN] {
    sha256(&[labels::CHANNEL_PASSWORD])[..pin::SALT_LEN]
        .try_into()
        .expect("hash is longer than the salt")
}

/// What a member says about itself in the link handshake (§11.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Random, new every time the app starts: tells two links to the same device apart from
    /// links to two devices, and nothing else.
    pub device: [u8; DEVICE_NONCE_LEN],
    /// What the other members see when it talks; may be empty.
    pub name: String,
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let name = truncate(&self.name, MAX_NAME_BYTES);
        [&self.device[..], &[name.len() as u8], name.as_bytes()].concat()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (device, rest) = bytes.split_first_chunk::<DEVICE_NONCE_LEN>()?;
        let (&len, name) = rest.split_first()?;
        if name.len() != usize::from(len) || name.len() > MAX_NAME_BYTES {
            return None;
        }
        Some(Self {
            device: *device,
            name: std::str::from_utf8(name).ok()?.to_owned(),
        })
    }
}

/// `text` cut to at most `max` bytes, on a character boundary.
fn truncate(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The nonce of a path request a cluster whose head is `head` makes (§11.5): `random`, then a MAC
/// only members can check.
pub fn cluster_nonce(path_key: &SecretBytes<32>, head: &[u8; DEVICE_NONCE_LEN], random: &[u8; 8]) -> [u8; 16] {
    let mut nonce = [0; 16];
    nonce[..8].copy_from_slice(random);
    nonce[8..].copy_from_slice(&cluster_mac(path_key, head, random));
    nonce
}

/// Whether a path request's `nonce` comes from the cluster whose head is `head`.
pub fn from_cluster(path_key: &SecretBytes<32>, head: &[u8; DEVICE_NONCE_LEN], nonce: &[u8; 16]) -> bool {
    let random: &[u8; 8] = nonce[..8].try_into().expect("8 bytes");
    equal_in_constant_time(&cluster_mac(path_key, head, random), &nonce[8..])
}

fn cluster_mac(path_key: &SecretBytes<32>, head: &[u8; DEVICE_NONCE_LEN], random: &[u8; 8]) -> [u8; 8] {
    hmac_sha256(path_key.expose(), &[labels::CHANNEL_CLUSTER, head, random]).expose()[..8]
        .try_into()
        .expect("a MAC is longer than 8 bytes")
}

/// A random device nonce for [`Hello`].
pub fn device_nonce() -> Result<[u8; DEVICE_NONCE_LEN], CryptoError> {
    let mut nonce = [0; DEVICE_NONCE_LEN];
    OsRng.fill(&mut nonce)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: PinParams = PinParams {
        memory_kib: 256,
        iterations: 2,
        parallelism: 1,
    };

    #[test]
    fn the_same_password_reaches_the_same_channel() {
        let a = Channel::from_password_with("kamp ateşi 2026", CHEAP).unwrap();
        let b = Channel::from_password_with("kamp ateşi 2026", CHEAP).unwrap();
        let c = Channel::from_password_with("kamp ateşi 2027", CHEAP).unwrap();
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), c.id());
        assert!(matches!(
            Channel::from_password_with("kısa", CHEAP),
            Err(ChannelError::PasswordTooShort)
        ));
    }

    #[test]
    fn members_recognise_each_others_tokens_and_strangers_do_not() {
        let channel = Channel::new().unwrap();
        let other = Channel::new().unwrap();
        let token = channel.token(100).unwrap();
        assert!(channel.recognizes(&token, 100));
        assert!(channel.recognizes(&token, 101), "clock skew");
        assert!(!channel.recognizes(&token, 102));
        assert!(!other.recognizes(&token, 100));
        assert_ne!(channel.token(100).unwrap(), token, "a fresh nonce every time");
    }

    #[test]
    fn qr_codes_round_trip() {
        let channel = Channel::new().unwrap();
        let text = channel.qr_text("Kamp telsizi").unwrap();
        assert!(text.starts_with("AIRCHAT:"));
        let (read, name) = Channel::parse_qr(&text).unwrap();
        assert_eq!((read.id(), name.as_str()), (channel.id(), "Kamp telsizi"));
        assert!(matches!(
            Channel::parse_qr("AIRCHAT:ABC"),
            Err(ChannelError::NotAChannel)
        ));
        assert!(channel.qr_text("").is_err());
    }

    #[test]
    fn hellos_round_trip_and_long_names_are_cut() {
        let hello = Hello {
            device: [7; 16],
            name: "Ayşe".into(),
        };
        assert_eq!(Hello::decode(&hello.encode()), Some(hello));
        let long = Hello {
            device: [1; 16],
            name: "ş".repeat(40),
        };
        let read = Hello::decode(&long.encode()).unwrap();
        assert_eq!(read.name.chars().count(), 32);
        assert!(Hello::decode(&[0; 10]).is_none());
    }
}
