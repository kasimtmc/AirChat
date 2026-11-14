//! Accounts at a server, for AirChat+ over the internet (docs/protocol.md §13): names, the auth key
//! derived from a password, and the messages a device and its server exchange to register, sign in
//! and act on a session; and the requests of §14 to the same endpoint: lookups and deposits.

use crate::{
    crypto::{
        CryptoError, SecretBytes,
        hash::hmac_sha256,
        kdf,
        pin::{self, PinParams},
        sign::{SIGNATURE_LEN, Signature},
    },
    identity::{Identity, PublicIdentity},
    labels,
    mail::{self, DELIVERY_KEY_LEN, SignedStaticKey},
};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 32;
pub const TOKEN_LEN: usize = 32;
pub const AUTH_KEY_LEN: usize = 32;

const VERSION: u8 = 0x00;
const PRELOGIN: u8 = 0x70;
const PARAMETERS: u8 = 0x71;
const REGISTER: u8 = 0x72;
const CHALLENGE_REQUEST: u8 = 0x73;
const CHALLENGE: u8 = 0x74;
const SIGN_IN: u8 = 0x75;
const SESSION: u8 = 0x76;
const AUTHORIZED: u8 = 0x77;
const DONE: u8 = 0x78;
const FAILURE: u8 = 0x7f;
const LOOKUP: u8 = 0x80;
const KEYS: u8 = 0x81;
const DEPOSIT: u8 = 0x82;
const DEPOSIT_REQUEST: u8 = 0x83;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountError {
    #[error("malformed account message")]
    Malformed,
    #[error("not a valid name")]
    InvalidName,
    #[error("not a valid server name")]
    InvalidServer,
    #[error("password parameters out of range")]
    Params,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Argon2id parameters of an account's password (§13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u8,
}

impl Params {
    /// The least a server accepts, and the default: as the app PIN (§3).
    pub const MIN: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };
    pub const MAX: Self = Self {
        memory_kib: 1024 * 1024,
        iterations: 10,
        parallelism: 4,
    };

    pub fn accepted(&self) -> bool {
        (Self::MIN.memory_kib..=Self::MAX.memory_kib).contains(&self.memory_kib)
            && (Self::MIN.iterations..=Self::MAX.iterations).contains(&self.iterations)
            && (Self::MIN.parallelism..=Self::MAX.parallelism).contains(&self.parallelism)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.memory_kib.to_be_bytes());
        out.extend_from_slice(&self.iterations.to_be_bytes());
        out.push(self.parallelism);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, AccountError> {
        Ok(Self {
            memory_kib: reader.u32()?,
            iterations: reader.u32()?,
            parallelism: reader.u8()?,
        })
    }
}

/// Checks a name as §13.1 defines it; a device lowercases what the user typed first.
pub fn check_name(name: &str) -> Result<(), AccountError> {
    let bytes = name.as_bytes();
    let punctuation = |b: u8| b == b'.' || b == b'_';
    let ok = (3..=32).contains(&bytes.len())
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || punctuation(b))
        && !punctuation(bytes[0])
        && !punctuation(bytes[bytes.len() - 1])
        && !bytes.windows(2).any(|w| punctuation(w[0]) && punctuation(w[1]));
    if ok { Ok(()) } else { Err(AccountError::InvalidName) }
}

/// Checks a server's DNS name: lowercase letters, digits, hyphens and dots, 1–253 bytes.
pub fn check_server(server: &str) -> Result<(), AccountError> {
    let ok = (1..=253).contains(&server.len())
        && server.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if ok { Ok(()) } else { Err(AccountError::InvalidServer) }
}

/// `auth_key` of §13.2: all a server ever gets of a password. `password` is the UTF-8 of the
/// password in Unicode NFC; slow by design (Argon2id with `params`).
pub fn auth_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: Params,
    server: &str,
    name: &str,
) -> Result<SecretBytes<AUTH_KEY_LEN>, AccountError> {
    check_server(server)?;
    check_name(name)?;
    let pin_params = PinParams {
        memory_kib: params.memory_kib,
        iterations: params.iterations,
        parallelism: u32::from(params.parallelism),
    };
    let root = pin::derive_key(password, salt, pin_params)?;
    let mut info = labels::ACCOUNT_AUTH.to_vec();
    put_name(&mut info, server);
    put_name(&mut info, name);
    Ok(kdf::derive(b"", root.expose(), &info)?)
}

/// The salt a server gives for a name with no account (§13.3).
pub fn fake_salt(server_secret: &[u8], name: &str) -> [u8; SALT_LEN] {
    let mut input = Vec::with_capacity(33);
    put_name(&mut input, name);
    let mac = hmac_sha256(server_secret, &[labels::ACCOUNT_FAKE_SALT, &input]);
    let mut salt = [0; SALT_LEN];
    salt.copy_from_slice(&mac.expose()[..SALT_LEN]);
    salt
}

/// New password material: what replaces an account's salt, parameters and auth key.
#[derive(Debug, Clone)]
pub struct Rekey {
    pub salt: [u8; SALT_LEN],
    pub params: Params,
    pub auth_key: SecretBytes<AUTH_KEY_LEN>,
}

impl Rekey {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.salt);
        self.params.encode(out);
        out.extend_from_slice(self.auth_key.expose());
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, AccountError> {
        Ok(Self {
            salt: reader.array()?,
            params: Params::decode(reader)?,
            auth_key: reader.secret()?,
        })
    }
}

/// `0x72 register` (§13.4).
#[derive(Debug, Clone)]
pub struct Register {
    pub name: String,
    pub password: Rekey,
    pub identity: PublicIdentity,
    signature: [u8; SIGNATURE_LEN],
}

impl Register {
    pub fn new(identity: &Identity, server: &str, name: &str, password: Rekey) -> Result<Self, AccountError> {
        check_name(name)?;
        let mut register = Self {
            name: name.to_owned(),
            password,
            identity: identity.public(),
            signature: [0; SIGNATURE_LEN],
        };
        register.signature = sign(identity, labels::ACCOUNT_REGISTER, server, &register.signed_fields())?;
        Ok(register)
    }

    /// Whether the signature is the identity key's over these fields at `server`.
    pub fn verify(&self, server: &str) -> bool {
        verify(
            &self.identity,
            labels::ACCOUNT_REGISTER,
            server,
            &self.signed_fields(),
            &self.signature,
        )
    }

    fn signed_fields(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_name(&mut out, &self.name);
        self.password.encode(&mut out);
        out.extend_from_slice(self.identity.as_bytes());
        out
    }
}

/// `0x75 sign in` (§13.5).
#[derive(Debug, Clone)]
pub struct SignIn {
    pub name: String,
    pub auth_key: SecretBytes<AUTH_KEY_LEN>,
    pub identity: PublicIdentity,
    pub nonce: [u8; NONCE_LEN],
    /// New salt, parameters and auth key, when the account's parameters are not the server's.
    pub rekey: Option<Rekey>,
    signature: [u8; SIGNATURE_LEN],
}

impl SignIn {
    pub fn new(
        identity: &Identity,
        server: &str,
        name: &str,
        auth_key: SecretBytes<AUTH_KEY_LEN>,
        nonce: [u8; NONCE_LEN],
        rekey: Option<Rekey>,
    ) -> Result<Self, AccountError> {
        check_name(name)?;
        let mut sign_in = Self {
            name: name.to_owned(),
            auth_key,
            identity: identity.public(),
            nonce,
            rekey,
            signature: [0; SIGNATURE_LEN],
        };
        sign_in.signature = sign(identity, labels::ACCOUNT_SIGN_IN, server, &sign_in.signed_fields())?;
        Ok(sign_in)
    }

    pub fn verify(&self, server: &str) -> bool {
        verify(
            &self.identity,
            labels::ACCOUNT_SIGN_IN,
            server,
            &self.signed_fields(),
            &self.signature,
        )
    }

    fn signed_fields(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_name(&mut out, &self.name);
        out.extend_from_slice(self.auth_key.expose());
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.nonce);
        match &self.rekey {
            None => out.push(0),
            Some(rekey) => {
                out.push(1);
                rekey.encode(&mut out);
            }
        }
        out
    }
}

/// What a request on a session asks for (§13.6).
#[derive(Debug, Clone)]
pub enum Action {
    SignOut,
    /// Needs the password again.
    Delete {
        auth_key: SecretBytes<AUTH_KEY_LEN>,
    },
    ChangePassword {
        auth_key: SecretBytes<AUTH_KEY_LEN>,
        new: Rekey,
    },
    /// The account's newest static key, for lookups (§14.1).
    PublishStaticKey(SignedStaticKey),
    /// The hash of the account's delivery key (§14.4).
    SetDeliveryKey {
        hash: [u8; 32],
    },
    /// The first frame of a mailbox connection (§14.6).
    OpenMailbox,
}

/// `0x77 authorized` (§13.6). The server knows the identity key the token is bound to and checks
/// the signature with it.
#[derive(Debug, Clone)]
pub struct Authorized {
    pub token: SecretBytes<TOKEN_LEN>,
    pub nonce: [u8; NONCE_LEN],
    pub action: Action,
    signature: [u8; SIGNATURE_LEN],
}

impl Authorized {
    pub fn new(
        identity: &Identity,
        server: &str,
        token: SecretBytes<TOKEN_LEN>,
        nonce: [u8; NONCE_LEN],
        action: Action,
    ) -> Result<Self, AccountError> {
        let mut authorized = Self {
            token,
            nonce,
            action,
            signature: [0; SIGNATURE_LEN],
        };
        authorized.signature = sign(identity, labels::ACCOUNT_SESSION, server, &authorized.signed_fields())?;
        Ok(authorized)
    }

    pub fn verify(&self, identity: &PublicIdentity, server: &str) -> bool {
        verify(
            identity,
            labels::ACCOUNT_SESSION,
            server,
            &self.signed_fields(),
            &self.signature,
        )
    }

    fn signed_fields(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.token.expose());
        out.extend_from_slice(&self.nonce);
        match &self.action {
            Action::SignOut => out.push(1),
            Action::Delete { auth_key } => {
                out.push(2);
                out.extend_from_slice(auth_key.expose());
            }
            Action::ChangePassword { auth_key, new } => {
                out.push(3);
                out.extend_from_slice(auth_key.expose());
                new.encode(&mut out);
            }
            Action::PublishStaticKey(key) => {
                out.push(4);
                key.encode(&mut out);
            }
            Action::SetDeliveryKey { hash } => {
                out.push(5);
                out.extend_from_slice(hash);
            }
            Action::OpenMailbox => out.push(6),
        }
        out
    }
}

/// What a device sends its server.
#[derive(Debug, Clone)]
pub enum Request {
    Prelogin {
        name: String,
    },
    Register(Register),
    ChallengeRequest,
    SignIn(SignIn),
    Authorized(Authorized),
    /// §14.1
    Lookup {
        name: String,
    },
    /// §14.5: `mail` is 2048, 4096 or 16384 bytes.
    Deposit {
        name: String,
        delivery_key: SecretBytes<DELIVERY_KEY_LEN>,
        mail: Vec<u8>,
    },
    /// §14.5: `request` is [`mail::REQUEST_LEN`] bytes.
    DepositRequest {
        name: String,
        request: Vec<u8>,
    },
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let (kind, mut body) = match self {
            Self::Prelogin { name } => {
                let mut out = Vec::new();
                put_name(&mut out, name);
                (PRELOGIN, out)
            }
            Self::Register(register) => (REGISTER, register.signed_fields()),
            Self::ChallengeRequest => (CHALLENGE_REQUEST, Vec::new()),
            Self::SignIn(sign_in) => (SIGN_IN, sign_in.signed_fields()),
            Self::Authorized(authorized) => (AUTHORIZED, authorized.signed_fields()),
            Self::Lookup { name } => {
                let mut out = Vec::new();
                put_name(&mut out, name);
                (LOOKUP, out)
            }
            Self::Deposit {
                name,
                delivery_key,
                mail,
            } => {
                let mut out = Vec::new();
                put_name(&mut out, name);
                out.extend_from_slice(delivery_key.expose());
                out.extend_from_slice(mail);
                (DEPOSIT, out)
            }
            Self::DepositRequest { name, request } => {
                let mut out = Vec::new();
                put_name(&mut out, name);
                out.extend_from_slice(request);
                (DEPOSIT_REQUEST, out)
            }
        };
        match self {
            Self::Register(Register { signature, .. })
            | Self::SignIn(SignIn { signature, .. })
            | Self::Authorized(Authorized { signature, .. }) => body.extend_from_slice(signature),
            Self::Prelogin { .. }
            | Self::ChallengeRequest
            | Self::Lookup { .. }
            | Self::Deposit { .. }
            | Self::DepositRequest { .. } => {}
        }
        [&[VERSION, kind][..], &body].concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut reader = Reader(bytes);
        let kind = reader.header()?;
        let request = match kind {
            PRELOGIN => Self::Prelogin { name: reader.name()? },
            REGISTER => Self::Register(Register {
                name: reader.name()?,
                password: Rekey::decode(&mut reader)?,
                identity: PublicIdentity::from_bytes(reader.array()?),
                signature: reader.array()?,
            }),
            CHALLENGE_REQUEST => Self::ChallengeRequest,
            SIGN_IN => Self::SignIn(SignIn {
                name: reader.name()?,
                auth_key: reader.secret()?,
                identity: PublicIdentity::from_bytes(reader.array()?),
                nonce: reader.array()?,
                rekey: match reader.u8()? {
                    0 => None,
                    1 => Some(Rekey::decode(&mut reader)?),
                    _ => return Err(AccountError::Malformed),
                },
                signature: reader.array()?,
            }),
            AUTHORIZED => Self::Authorized(Authorized {
                token: reader.secret()?,
                nonce: reader.array()?,
                action: match reader.u8()? {
                    1 => Action::SignOut,
                    2 => Action::Delete {
                        auth_key: reader.secret()?,
                    },
                    3 => Action::ChangePassword {
                        auth_key: reader.secret()?,
                        new: Rekey::decode(&mut reader)?,
                    },
                    4 => Action::PublishStaticKey(
                        SignedStaticKey::decode(reader.take(mail::SIGNED_STATIC_KEY_LEN)?)
                            .ok_or(AccountError::Malformed)?,
                    ),
                    5 => Action::SetDeliveryKey { hash: reader.array()? },
                    6 => Action::OpenMailbox,
                    _ => return Err(AccountError::Malformed),
                },
                signature: reader.array()?,
            }),
            LOOKUP => Self::Lookup { name: reader.name()? },
            DEPOSIT => {
                let name = reader.name()?;
                let delivery_key = reader.secret()?;
                let mail = reader.rest();
                if !mail::MAIL_SIZES.contains(&mail.len()) {
                    return Err(AccountError::Malformed);
                }
                Self::Deposit {
                    name,
                    delivery_key,
                    mail: mail.to_vec(),
                }
            }
            DEPOSIT_REQUEST => {
                let name = reader.name()?;
                let request = reader.rest();
                if request.len() != mail::REQUEST_LEN {
                    return Err(AccountError::Malformed);
                }
                Self::DepositRequest {
                    name,
                    request: request.to_vec(),
                }
            }
            _ => return Err(AccountError::Malformed),
        };
        reader.end()?;
        Ok(request)
    }
}

/// Why a server refused a request (§13.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Malformed = 1,
    NameTaken = 2,
    WrongCredentials = 3,
    TooManyAttempts = 4,
    ChallengeExpired = 5,
    InvalidName = 6,
    ParamsRefused = 7,
    SessionRefused = 8,
    /// No such account, or a wrong delivery key (§14).
    Refused = 9,
}

impl Failure {
    fn from_code(code: u8) -> Result<Self, AccountError> {
        Ok(match code {
            1 => Self::Malformed,
            2 => Self::NameTaken,
            3 => Self::WrongCredentials,
            4 => Self::TooManyAttempts,
            5 => Self::ChallengeExpired,
            6 => Self::InvalidName,
            7 => Self::ParamsRefused,
            8 => Self::SessionRefused,
            9 => Self::Refused,
            _ => return Err(AccountError::Malformed),
        })
    }
}

/// What a server answers.
#[derive(Debug, Clone)]
pub enum Answer {
    Parameters {
        salt: [u8; SALT_LEN],
        params: Params,
    },
    Challenge {
        nonce: [u8; NONCE_LEN],
    },
    Session {
        token: SecretBytes<TOKEN_LEN>,
        replaced: bool,
    },
    Done,
    Failure {
        failure: Failure,
        retry_after: u32,
    },
    /// An account's keys (§14.1).
    Keys {
        identity: PublicIdentity,
        static_key: SignedStaticKey,
    },
}

impl Answer {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        match self {
            Self::Parameters { salt, params } => {
                out.push(PARAMETERS);
                out.extend_from_slice(salt);
                params.encode(&mut out);
            }
            Self::Challenge { nonce } => {
                out.push(CHALLENGE);
                out.extend_from_slice(nonce);
            }
            Self::Session { token, replaced } => {
                out.push(SESSION);
                out.extend_from_slice(token.expose());
                out.push(u8::from(*replaced));
            }
            Self::Done => out.push(DONE),
            Self::Failure { failure, retry_after } => {
                out.push(FAILURE);
                out.push(*failure as u8);
                out.extend_from_slice(&retry_after.to_be_bytes());
            }
            Self::Keys { identity, static_key } => {
                out.push(KEYS);
                out.extend_from_slice(identity.as_bytes());
                static_key.encode(&mut out);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut reader = Reader(bytes);
        let answer = match reader.header()? {
            PARAMETERS => Self::Parameters {
                salt: reader.array()?,
                params: Params::decode(&mut reader)?,
            },
            CHALLENGE => Self::Challenge { nonce: reader.array()? },
            SESSION => Self::Session {
                token: reader.secret()?,
                replaced: match reader.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(AccountError::Malformed),
                },
            },
            DONE => Self::Done,
            FAILURE => Self::Failure {
                failure: Failure::from_code(reader.u8()?)?,
                retry_after: reader.u32()?,
            },
            KEYS => Self::Keys {
                identity: PublicIdentity::from_bytes(reader.array()?),
                static_key: SignedStaticKey::decode(reader.take(mail::SIGNED_STATIC_KEY_LEN)?)
                    .ok_or(AccountError::Malformed)?,
            },
            _ => return Err(AccountError::Malformed),
        };
        reader.end()?;
        Ok(answer)
    }
}

pub(crate) fn put_name(out: &mut Vec<u8>, name: &str) {
    // Checked names are at most 253 bytes.
    out.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(name.as_bytes());
}

fn sign(identity: &Identity, label: &[u8], server: &str, fields: &[u8]) -> Result<[u8; SIGNATURE_LEN], AccountError> {
    check_server(server)?;
    let mut server_name = Vec::new();
    put_name(&mut server_name, server);
    Ok(*identity.sign(label, &[&server_name, fields]).as_bytes())
}

fn verify(
    identity: &PublicIdentity,
    label: &[u8],
    server: &str,
    fields: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    if check_server(server).is_err() {
        return false;
    }
    let mut server_name = Vec::new();
    put_name(&mut server_name, server);
    identity
        .verify(label, &[&server_name, fields], &Signature::from_bytes(*signature))
        .is_ok()
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], AccountError> {
        if self.0.len() < len {
            return Err(AccountError::Malformed);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, AccountError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, AccountError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], AccountError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn secret<const N: usize>(&mut self) -> Result<SecretBytes<N>, AccountError> {
        SecretBytes::from_slice(self.take(N)?).map_err(|_| AccountError::Malformed)
    }

    fn header(&mut self) -> Result<u8, AccountError> {
        if self.u8()? != VERSION {
            return Err(AccountError::Malformed);
        }
        self.u8()
    }

    /// A name: decoded as a name of §13.1, so nothing else gets through.
    pub(crate) fn name(&mut self) -> Result<String, AccountError> {
        let len = usize::from(self.u8()?);
        let bytes = self.take(len)?;
        let name = std::str::from_utf8(bytes).map_err(|_| AccountError::Malformed)?;
        check_name(name)?;
        Ok(name.to_owned())
    }

    /// A server's name (§13.1).
    pub(crate) fn server(&mut self) -> Result<String, AccountError> {
        let len = usize::from(self.u8()?);
        let bytes = self.take(len)?;
        let server = std::str::from_utf8(bytes).map_err(|_| AccountError::Malformed)?;
        check_server(server)?;
        Ok(server.to_owned())
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    pub(crate) fn end(&self) -> Result<(), AccountError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(AccountError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters for tests; a server would refuse them.
    const CHEAP: Params = Params {
        memory_kib: 256,
        iterations: 2,
        parallelism: 1,
    };

    fn identity(byte: u8) -> Identity {
        Identity::from_seed(SecretBytes::from_slice(&[byte; 32]).unwrap())
    }

    fn rekey(byte: u8) -> Rekey {
        Rekey {
            salt: [byte; SALT_LEN],
            params: Params::MIN,
            auth_key: SecretBytes::from_slice(&[byte; 32]).unwrap(),
        }
    }

    #[test]
    fn names() {
        for good in ["kasim", "k.t_9", "abc", "a".repeat(32).as_str()] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in [
            "ab",
            "Kasim",
            ".kasim",
            "kasim_",
            "ka..sim",
            "ka._sim",
            "kâsim",
            "ka sim",
            &"a".repeat(33),
        ] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        assert!(check_server("chat.example.org").is_ok());
        for bad in ["", "Example.org", "-a.org", "a..org", "a_b.org"] {
            assert!(check_server(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn params_in_range() {
        assert!(Params::MIN.accepted() && Params::MAX.accepted());
        assert!(!CHEAP.accepted());
        assert!(
            !Params {
                memory_kib: Params::MAX.memory_kib + 1,
                ..Params::MIN
            }
            .accepted()
        );
    }

    #[test]
    fn auth_key_is_bound_to_password_salt_server_and_name() {
        let salt = [7; SALT_LEN];
        let key = auth_key(b"correct horse", &salt, CHEAP, "a.org", "kasim").unwrap();
        let differs = |other: SecretBytes<32>| assert_ne!(key.expose(), other.expose());
        differs(auth_key(b"correct horsf", &salt, CHEAP, "a.org", "kasim").unwrap());
        differs(auth_key(b"correct horse", &[8; SALT_LEN], CHEAP, "a.org", "kasim").unwrap());
        differs(auth_key(b"correct horse", &salt, CHEAP, "b.org", "kasim").unwrap());
        differs(auth_key(b"correct horse", &salt, CHEAP, "a.org", "kasim2").unwrap());
        assert_eq!(
            key.expose(),
            auth_key(b"correct horse", &salt, CHEAP, "a.org", "kasim")
                .unwrap()
                .expose()
        );
    }

    #[test]
    fn fake_salt_is_stable_and_secret_bound() {
        assert_eq!(fake_salt(b"secret", "kasim"), fake_salt(b"secret", "kasim"));
        assert_ne!(fake_salt(b"secret", "kasim"), fake_salt(b"secret", "kasim2"));
        assert_ne!(fake_salt(b"secret", "kasim"), fake_salt(b"secreu", "kasim"));
    }

    fn round_trip(request: &Request) -> Request {
        let bytes = request.encode();
        let decoded = Request::decode(&bytes).unwrap();
        assert_eq!(decoded.encode(), bytes);
        decoded
    }

    #[test]
    fn requests_round_trip_and_signatures_hold_only_at_their_server() {
        let me = identity(1);
        let register = Register::new(&me, "a.org", "kasim", rekey(2)).unwrap();
        let Request::Register(decoded) = round_trip(&Request::Register(register)) else {
            panic!()
        };
        assert!(decoded.verify("a.org"));
        assert!(!decoded.verify("b.org"), "bound to the server");

        let sign_in = SignIn::new(&me, "a.org", "kasim", rekey(3).auth_key, [4; 32], Some(rekey(5))).unwrap();
        let Request::SignIn(decoded) = round_trip(&Request::SignIn(sign_in)) else {
            panic!()
        };
        assert!(decoded.verify("a.org"));
        let mut tampered = decoded.clone();
        tampered.rekey = None;
        assert!(!tampered.verify("a.org"), "the re-key is signed too");

        for action in [
            Action::SignOut,
            Action::Delete {
                auth_key: rekey(6).auth_key,
            },
            Action::ChangePassword {
                auth_key: rekey(6).auth_key,
                new: rekey(7),
            },
        ] {
            let authorized = Authorized::new(&me, "a.org", rekey(8).auth_key, [9; 32], action).unwrap();
            let Request::Authorized(decoded) = round_trip(&Request::Authorized(authorized)) else {
                panic!()
            };
            assert!(decoded.verify(&me.public(), "a.org"));
            assert!(!decoded.verify(&identity(2).public(), "a.org"), "only the bound key");
        }
        round_trip(&Request::Prelogin { name: "kasim".into() });
        round_trip(&Request::ChallengeRequest);
    }

    #[test]
    fn answers_round_trip() {
        for answer in [
            Answer::Parameters {
                salt: [1; 16],
                params: Params::MIN,
            },
            Answer::Challenge { nonce: [2; 32] },
            Answer::Session {
                token: rekey(3).auth_key,
                replaced: true,
            },
            Answer::Done,
            Answer::Failure {
                failure: Failure::TooManyAttempts,
                retry_after: 60,
            },
        ] {
            let bytes = answer.encode();
            assert_eq!(Answer::decode(&bytes).unwrap().encode(), bytes);
        }
    }

    /// `tests/vectors/account.json`; `check_account.py` re-derives it from docs/protocol.md §13.
    #[test]
    fn vector() {
        use crate::crypto::test_util::{check_vector, to_hex};
        let me = identity(1);
        let (server, name, salt) = ("chat.example.org", "kasim", [0x11; SALT_LEN]);
        let key = auth_key("parola şifre 123".as_bytes(), &salt, CHEAP, server, name).unwrap();
        let password = Rekey {
            salt,
            params: CHEAP,
            auth_key: key.clone(),
        };
        let register = Request::Register(Register::new(&me, server, name, password.clone()).unwrap());
        let sign_in = Request::SignIn(SignIn::new(&me, server, name, key.clone(), [0x22; 32], None).unwrap());
        let change = Request::Authorized(
            Authorized::new(
                &me,
                server,
                SecretBytes::from_slice(&[0x33; 32]).unwrap(),
                [0x44; 32],
                Action::ChangePassword {
                    auth_key: key.clone(),
                    new: Rekey {
                        salt: [0x55; SALT_LEN],
                        ..password
                    },
                },
            )
            .unwrap(),
        );
        check_vector(
            "account",
            &[
                ("identity_seed", to_hex(&[1; 32])),
                ("server", server.to_owned()),
                ("name", name.to_owned()),
                ("password", to_hex("parola şifre 123".as_bytes())),
                ("salt", to_hex(&salt)),
                (
                    "params",
                    to_hex(&{
                        let mut out = Vec::new();
                        CHEAP.encode(&mut out);
                        out
                    }),
                ),
                ("auth_key", to_hex(key.expose())),
                ("server_secret", to_hex(b"server secret")),
                ("fake_salt", to_hex(&fake_salt(b"server secret", "nobody"))),
                ("prelogin", to_hex(&Request::Prelogin { name: name.into() }.encode())),
                ("register", to_hex(&register.encode())),
                ("sign_in", to_hex(&sign_in.encode())),
                ("change_password", to_hex(&change.encode())),
            ],
        );
    }

    #[test]
    fn malformed_messages_are_refused() {
        let good = Request::Prelogin { name: "kasim".into() }.encode();
        for bad in [
            vec![],
            vec![0x01, PRELOGIN, 5, b'k', b'a', b's', b'i', b'm'],
            [&good[..], &[0]].concat(),
            good[..good.len() - 1].to_vec(),
            vec![0x00, PRELOGIN, 5, b'K', b'a', b's', b'i', b'm'],
            vec![0x00, 0x7e],
        ] {
            assert!(Request::decode(&bad).is_err(), "{bad:?}");
        }
    }
}
