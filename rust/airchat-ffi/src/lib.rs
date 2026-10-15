//! UniFFI interface of the AirChat core.
//!
//! Keep this layer thin: type conversions only, no protocol logic. Secrets that cross the boundary
//! (PIN, unlock secret) are wiped on the Rust side as soon as they are used; the platform must wipe
//! its own copies.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use airchat_core::{
    account::{self, AccountError},
    channel::ChannelError,
    chat::{self, ChatError, HotspotOffer as CoreHotspotOffer, MoveTarget as CoreMoveTarget},
    crypto::{SecretBytes, pin::PinParams},
    discovery::{
        self, AwareBeacon as CoreAwareBeacon, BleBeacon as CoreBleBeacon, PAIRING_TOKEN_LEN, PRESENCE_TOKEN_LEN,
        PairingBeacon as CoreBeacon,
    },
    group::GroupError,
    identity::{AirChatId, PublicIdentity},
    jitter,
    media::MediaError,
    node::{self, Node, NodeError},
    pairing::PairingError,
    path::{Class, Classes},
    storage::{self, ContactSummary, StoredMessage, VaultError, groups as stored_groups},
};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

fn stream_id(bytes: &[u8]) -> Result<chat::StreamId, CoreError> {
    bytes.try_into().map_err(|_| CoreError::NoSuchCall)
}

/// Version of the Rust core.
#[uniffi::export]
pub fn core_version() -> String {
    airchat_core::VERSION.to_owned()
}

/// Wire protocol version spoken by the Rust core.
#[uniffi::export]
pub fn protocol_version() -> u16 {
    airchat_core::PROTOCOL_VERSION
}

/// Largest file the core sends, in bytes.
#[uniffi::export]
pub fn max_file_size() -> u64 {
    chat::MAX_FILE_SIZE
}

/// The type of a voice message (an Ogg Opus file); see [`max_voice_bytes`].
#[uniffi::export]
pub fn voice_mime() -> String {
    airchat_core::storage::VOICE_MIME.to_owned()
}

/// Largest voice message, in bytes: one larger is an ordinary file.
#[uniffi::export]
pub fn max_voice_bytes() -> u64 {
    airchat_core::storage::MAX_VOICE_BYTES
}

/// How long a voice message that came in stays after it was first played, in ms.
#[uniffi::export]
pub fn voice_keep_ms() -> i64 {
    airchat_core::storage::VOICE_KEEP_MS
}

/// Largest thumbnail a file offer may carry, in bytes.
#[uniffi::export]
pub fn max_thumbnail_bytes() -> u32 {
    chat::MAX_THUMBNAIL_BYTES as u32
}

/// Shortest PIN the core accepts, so the UI can validate before calling in.
/// The name under which a group message's file is read and written (by `read_file`, `write_file`).
#[uniffi::export]
pub fn group_file(message_id: i64) -> i64 {
    stored_groups::group_file(message_id)
}

#[uniffi::export]
pub fn min_pin_length() -> u32 {
    account::MIN_PIN_LEN as u32
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    #[error("wrong PIN")]
    WrongCredential,
    #[error("PIN too short")]
    PinTooShort,
    #[error("invalid display name")]
    InvalidDisplayName,
    #[error("an account already exists")]
    AccountExists,
    #[error("no account on this device")]
    NoAccount,
    #[error("the key record is corrupted")]
    CorruptKeyRecord,
    #[error("not an AirChat QR code")]
    NotAnInvite,
    #[error("no such contact")]
    UnknownContact,
    #[error("a message must have 1 to 8192 bytes")]
    InvalidMessage,
    #[error("the app is locked")]
    Locked,
    #[error("no link to that contact")]
    NotLinked,
    #[error("the link runs over Bluetooth: move it to Wi-Fi first")]
    NeedsWifi,
    #[error("the link runs over an Air Provider path that does not carry that")]
    PathTooNarrow,
    #[error("no Air Provider around carries that")]
    NoProvider,
    #[error("the file cannot be sent: invalid name, type or thumbnail, or too large")]
    InvalidFile,
    #[error("no such file")]
    NoSuchFile,
    #[error("already in a call")]
    Busy,
    #[error("the contact is talking")]
    FloorTaken,
    #[error("no such call or talk")]
    NoSuchCall,
    #[error("a video frame is too large; lower the bitrate")]
    VideoFrameTooLarge,
    #[error("no such group, or no longer a member")]
    NoSuchGroup,
    #[error("only a group admin can do that")]
    NotGroupAdmin,
    #[error("a group needs a name of 1 to 64 characters and 2 to 32 members")]
    InvalidGroup,
    #[error("no such channel")]
    NoSuchChannel,
    #[error("not an AirChat channel code")]
    NotAChannel,
    #[error("a channel password needs at least 8 characters")]
    PasswordTooShort,
    #[error("a channel name needs 1 to 64 bytes")]
    InvalidChannelName,
    #[error("not an AirChat ID")]
    InvalidId,
    #[error("that is your own AirChat ID")]
    OwnId,
    #[error("that AirChat ID is a contact's already")]
    AlreadyContact,
    #[error("not in that group's call")]
    NotInCall,
    #[error("no such message, or it was not given up")]
    NoSuchMessage,
    #[error("{0}")]
    Internal(String),
}

impl From<NodeError> for CoreError {
    fn from(error: NodeError) -> Self {
        match error {
            NodeError::Account(e) => e.into(),
            NodeError::Pairing(PairingError::NotAnInvite | PairingError::UnsupportedVersion) => Self::NotAnInvite,
            NodeError::UnknownContact => Self::UnknownContact,
            NodeError::NotLinked => Self::NotLinked,
            NodeError::NeedsWifi => Self::NeedsWifi,
            NodeError::PathTooNarrow => Self::PathTooNarrow,
            NodeError::NoProvider => Self::NoProvider,
            NodeError::Sealed | NodeError::WrongAccount => Self::Locked,
            NodeError::NoSuchFile => Self::NoSuchFile,
            NodeError::Chat(ChatError::InvalidFile) => Self::InvalidFile,
            NodeError::Chat(_) => Self::InvalidMessage,
            NodeError::Media(MediaError::Busy) => Self::Busy,
            NodeError::Media(MediaError::FloorTaken) => Self::FloorTaken,
            NodeError::Media(MediaError::NoSuchStream) => Self::NoSuchCall,
            NodeError::Media(MediaError::FrameTooLarge) => Self::VideoFrameTooLarge,
            NodeError::NoSuchGroup => Self::NoSuchGroup,
            NodeError::NoSuchChannel => Self::NoSuchChannel,
            NodeError::Channel(ChannelError::NotAChannel) => Self::NotAChannel,
            NodeError::Channel(ChannelError::PasswordTooShort) => Self::PasswordTooShort,
            NodeError::Channel(ChannelError::InvalidName) => Self::InvalidChannelName,
            NodeError::NotGroupAdmin => Self::NotGroupAdmin,
            NodeError::Group(GroupError::InvalidName | GroupError::InvalidMembers) => Self::InvalidGroup,
            NodeError::Group(GroupError::Malformed) => Self::InvalidMessage,
            NodeError::InvalidId => Self::InvalidId,
            NodeError::OwnId => Self::OwnId,
            NodeError::AlreadyContact => Self::AlreadyContact,
            NodeError::NotInCall => Self::NotInCall,
            NodeError::NoSuchMessage => Self::NoSuchMessage,
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<AccountError> for CoreError {
    fn from(error: AccountError) -> Self {
        match error {
            AccountError::Vault(VaultError::WrongCredential) => Self::WrongCredential,
            AccountError::Vault(VaultError::CorruptRecord | VaultError::UnsupportedVersion) => Self::CorruptKeyRecord,
            AccountError::PinTooShort => Self::PinTooShort,
            AccountError::InvalidDisplayName => Self::InvalidDisplayName,
            AccountError::AlreadyExists => Self::AccountExists,
            AccountError::NotFound => Self::NoAccount,
            AccountError::NoSuchFile => Self::NoSuchFile,
            other => Self::Internal(other.to_string()),
        }
    }
}

#[uniffi::export]
pub fn account_exists(data_dir: String) -> bool {
    account::Account::exists(&PathBuf::from(data_dir))
}

#[derive(uniffi::Record)]
pub struct NewAccount {
    pub account: Arc<Account>,
    /// Must be stored by the platform (wrapped with a hardware-backed key); needed to unlock.
    pub pin_record: Vec<u8>,
}

/// Slow by design (Argon2id, ~1 s): never call on the UI thread.
#[uniffi::export]
pub fn create_account(data_dir: String, pin: Vec<u8>, display_name: String) -> Result<NewAccount, CoreError> {
    let pin = Zeroizing::new(pin);
    let (account, pin_record) =
        account::Account::create(&PathBuf::from(data_dir), &pin, &display_name, PinParams::DEFAULT)?;
    Ok(NewAccount {
        account: Account::wrap(account)?,
        pin_record,
    })
}

/// Slow by design (Argon2id, ~1 s): never call on the UI thread.
#[uniffi::export]
pub fn unlock_with_pin(data_dir: String, pin_record: Vec<u8>, pin: Vec<u8>) -> Result<Arc<Account>, CoreError> {
    let pin = Zeroizing::new(pin);
    let account = account::Account::unlock_with_pin(&PathBuf::from(data_dir), &pin_record, &pin)?;
    Account::wrap(account)
}

#[uniffi::export]
pub fn unlock_with_secret(
    data_dir: String,
    secret_record: Vec<u8>,
    secret: Vec<u8>,
) -> Result<Arc<Account>, CoreError> {
    let secret = Zeroizing::new(secret);
    let secret = SecretBytes::from_slice(&secret).map_err(|_| CoreError::CorruptKeyRecord)?;
    let account = account::Account::unlock_with_secret(&PathBuf::from(data_dir), &secret_record, &secret)?;
    Account::wrap(account)
}

#[derive(uniffi::Record)]
pub struct SecretUnlock {
    /// Must be stored only behind biometric authentication, then wiped.
    pub secret: Vec<u8>,
    pub record: Vec<u8>,
}

/// An unlocked account and its open connections. Dropping the last reference closes the database
/// and wipes the keys.
#[derive(uniffi::Object)]
pub struct Account(Mutex<Node>);

impl Account {
    fn wrap(account: account::Account) -> Result<Arc<Self>, CoreError> {
        Ok(Arc::new(Self(Mutex::new(Node::new(account)?))))
    }

    fn lock(&self) -> Result<MutexGuard<'_, Node>, CoreError> {
        self.0
            .lock()
            .map_err(|_| CoreError::Internal("account state poisoned".into()))
    }

    fn unseal(&self, account: account::Account) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.unseal(account)?;
        Ok(out(&mut node, actions))
    }

    /// Like [`Account::lock`] for calls that report failures as actions rather than errors.
    fn with_node(&self, f: impl FnOnce(&mut Node) -> Vec<node::Action>) -> Vec<Action> {
        match self.0.lock() {
            Ok(mut node) => {
                let actions = f(&mut node);
                out(&mut node, actions)
            }
            Err(_) => Vec::new(),
        }
    }
}

/// Actions for the platform. Every list leaving the core goes through [`Node::route`] first, so
/// frames for links over paths travel as path records (rust/airchat-protocol/docs/protocol.md §12.3).
fn out(node: &mut Node, actions: Vec<node::Action>) -> Vec<Action> {
    node.route(actions).into_iter().map(Action::from).collect()
}

#[uniffi::export]
impl Account {
    pub fn airchat_id(&self) -> Result<String, CoreError> {
        Ok(self.lock()?.account()?.airchat_id().to_string())
    }

    pub fn display_name(&self) -> Result<String, CoreError> {
        Ok(self.lock()?.account()?.display_name().to_owned())
    }

    pub fn set_display_name(&self, display_name: String) -> Result<(), CoreError> {
        Ok(self.lock()?.account_mut()?.set_display_name(&display_name)?)
    }

    /// Returns the new PIN record, which replaces the stored one. Slow (Argon2id).
    pub fn change_pin(&self, new_pin: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let new_pin = Zeroizing::new(new_pin);
        Ok(self.lock()?.account()?.change_pin(&new_pin, PinParams::DEFAULT)?)
    }

    pub fn create_secret_unlock(&self) -> Result<SecretUnlock, CoreError> {
        let unlock = self.lock()?.account()?.create_secret_unlock()?;
        Ok(SecretUnlock {
            secret: unlock.secret.expose().to_vec(),
            record: unlock.record,
        })
    }

    // Locking.

    /// Locks the account: closes the database and wipes its keys, but keeps links up so messages
    /// keep arriving (into the encrypted inbox). Carry out the returned actions.
    pub fn seal(&self) -> Vec<Action> {
        self.with_node(Node::seal)
    }

    pub fn is_locked(&self) -> bool {
        self.0.lock().map(|node| node.is_sealed()).unwrap_or(true)
    }

    /// Unlocks a locked account with the PIN. Slow (Argon2id). Returns what arrived while locked.
    pub fn unseal_with_pin(
        &self,
        data_dir: String,
        pin_record: Vec<u8>,
        pin: Vec<u8>,
    ) -> Result<Vec<Action>, CoreError> {
        let pin = Zeroizing::new(pin);
        let account = account::Account::unlock_with_pin(&PathBuf::from(data_dir), &pin_record, &pin)?;
        self.unseal(account)
    }

    pub fn unseal_with_secret(
        &self,
        data_dir: String,
        secret_record: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Vec<Action>, CoreError> {
        let secret = Zeroizing::new(secret);
        let secret = SecretBytes::from_slice(&secret).map_err(|_| CoreError::CorruptKeyRecord)?;
        let account = account::Account::unlock_with_secret(&PathBuf::from(data_dir), &secret_record, &secret)?;
        self.unseal(account)
    }

    // Contacts.

    pub fn contacts(&self) -> Result<Vec<Contact>, CoreError> {
        Ok(self
            .lock()?
            .account()?
            .contacts()?
            .into_iter()
            .map(Contact::from)
            .collect())
    }

    /// Deletes a contact's keys, and its conversation unless `keep_history`; carry out the
    /// returned actions to end its link.
    pub fn delete_contact(&self, id: i64, keep_history: bool) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.delete_contact(id, keep_history)?;
        Ok(out(&mut node, actions))
    }

    /// What this account's Android key attestation must carry as its challenge
    /// (rust/airchat-protocol/docs/protocol.md §6.10).
    pub fn attestation_challenge(&self) -> Result<Vec<u8>, CoreError> {
        Ok(self.lock()?.attestation_challenge()?.to_vec())
    }

    /// This account's attestation: the certificate chain of the attested key, that key's
    /// certificate first. Links up now ask for their proofs.
    pub fn set_attestation(&self, chain: Vec<Vec<u8>>) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.set_attestation(chain);
        Ok(out(&mut node, actions))
    }

    /// Trusts another signing certificate (its SHA-256) as an official build's; debug builds
    /// trust their own, to test verified builds between them.
    pub fn trust_signer(&self, digest: Vec<u8>) -> Result<(), CoreError> {
        let digest: [u8; 32] = digest.try_into().map_err(|_| CoreError::InvalidMessage)?;
        self.lock()?.trust_signer(digest);
        Ok(())
    }

    /// The attested key's signature over what [`Action::AttestationWanted`] asked for: the
    /// attestation goes to the contact.
    pub fn send_attestation(&self, contact_id: i64, proof: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.send_attestation(contact_id, proof);
        Ok(out(&mut node, actions))
    }

    /// The groups this device shares with a contact, as an emergency exit would treat them.
    pub fn groups_shared_with(&self, contact_id: i64) -> Result<Vec<Group>, CoreError> {
        Ok(self
            .lock()?
            .groups_shared_with(contact_id)?
            .into_iter()
            .map(Group::from)
            .collect())
    }

    /// Cuts a contact off (docs/threat-model.md, A5): blocks them, deletes the conversation here,
    /// removes them from the groups this device administers, and with `leave_groups` leaves the
    /// others shared with them. What was already sent to them stays with them.
    pub fn emergency_exit(&self, contact_id: i64, leave_groups: bool) -> Result<EmergencyExit, CoreError> {
        let mut node = self.lock()?;
        let (exit, actions) = node.emergency_exit(contact_id, leave_groups)?;
        Ok(EmergencyExit {
            removed_from: exit.removed_from,
            deleted: exit.deleted,
            left: exit.left,
            still_shared: exit.still_shared,
            actions: out(&mut node, actions),
        })
    }

    /// Blocks a contact; carry out the returned actions to end its link.
    pub fn block_contact(&self, id: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.block_contact(id)?;
        Ok(out(&mut node, actions))
    }

    pub fn unblock_contact(&self, id: i64) -> Result<(), CoreError> {
        Ok(self.lock()?.unblock_contact(id)?)
    }

    pub fn set_permissions(&self, id: i64, permissions: Permissions) -> Result<(), CoreError> {
        let permissions = storage::Permissions {
            messages: permissions.messages,
            ptt: permissions.ptt,
            auto_download: permissions.auto_download,
        };
        Ok(self.lock()?.set_permissions(id, permissions)?)
    }

    // Presence and links.

    /// The token to announce now (it changes every hour; re-announce when it does).
    pub fn presence_token(&self) -> Result<Vec<u8>, CoreError> {
        Ok(self.lock()?.presence_token(now_secs()).to_vec())
    }

    /// Whether a token seen on the network belongs to a contact, and whether to connect to it.
    pub fn recognize_presence(&self, token: Vec<u8>) -> Option<Recognized> {
        let token: [u8; PRESENCE_TOKEN_LEN] = token.try_into().ok()?;
        let recognized = self.0.lock().ok()?.recognize_presence(&token, now_secs())?;
        Some(recognized.into())
    }

    /// Opens a link with a contact on a new outgoing connection.
    pub fn connect_contact(&self, connection: u64, contact_id: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.connect_contact(connection, contact_id, now_secs())?;
        Ok(out(&mut node, actions))
    }

    /// Contacts with a link up right now.
    pub fn linked_contacts(&self) -> Vec<i64> {
        self.0.lock().map(|node| node.linked_contacts()).unwrap_or_default()
    }

    // Messages.

    /// Stores the message and sends it now if the contact is linked, otherwise later.
    /// Tries a message given up (not delivered within a day) again, from now: its row `id`.
    pub fn try_message_again(&self, id: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.try_message_again(id)?;
        Ok(out(&mut node, actions))
    }

    pub fn send_message(&self, contact_id: i64, text: String) -> Result<SentMessage, CoreError> {
        let mut node = self.lock()?;
        let (message, actions) = node.send_message(contact_id, &text)?;
        Ok(SentMessage {
            message: message.into(),
            actions: out(&mut node, actions),
        })
    }

    // Calls and push-to-talk. They work while locked too, except starting them.

    /// Calls a linked contact, as a video call or not; `CallReached`, then `CallAccepted` or
    /// `CallEnded` follow.
    pub fn start_call(&self, contact_id: i64, video: bool) -> Result<Started, CoreError> {
        let mut node = self.lock()?;
        let (id, actions) = node.start_call(contact_id, video)?;
        Ok(Started {
            id: id.to_vec(),
            actions: out(&mut node, actions),
        })
    }

    pub fn answer_call(&self, id: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.answer_call(stream_id(&id)?)?;
        Ok(out(&mut node, actions))
    }

    /// Hangs up, cancels, or declines a call ringing here.
    pub fn end_call(&self, id: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.end_call(stream_id(&id)?);
        Ok(out(&mut node, actions))
    }

    // Video in 1:1 calls: only while the link runs over Wi-Fi (LAN, Wi-Fi Aware, hotspot).

    /// This device's camera in a call; the contact hears of it once the call is answered.
    pub fn set_camera(&self, id: Vec<u8>, state: VideoState) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.set_camera(stream_id(&id)?, state.into())?;
        Ok(out(&mut node, actions))
    }

    /// One H.264 frame of this device's camera (Annex B; a key frame with SPS and PPS before it),
    /// shown upright after `rotation` quarter turns clockwise. Skip frames only before a key frame.
    pub fn send_video(
        &self,
        stream: Vec<u8>,
        key: bool,
        rotation: u8,
        width: u16,
        height: u16,
        frame: Vec<u8>,
    ) -> Result<Vec<Action>, CoreError> {
        let frame = Zeroizing::new(frame);
        let mut node = self.lock()?;
        let actions = node.send_video(stream_id(&stream)?, key, rotation, (width, height), &frame)?;
        Ok(out(&mut node, actions))
    }

    /// The contact's video cannot be decoded from here on (a new decoder, say): ask for a key frame.
    pub fn request_key_frame(&self, stream: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.request_key_frame(stream_id(&stream)?)?;
        Ok(out(&mut node, actions))
    }

    /// The video of `member` (its row, as [`Action::Video`] names it) in the group call cannot be
    /// decoded from here on: ask for a key frame.
    pub fn request_member_key_frame(&self, stream: Vec<u8>, member: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.request_member_key_frame(stream_id(&stream)?, member)?;
        Ok(out(&mut node, actions))
    }

    // Muting: until a time (Unix ms), `i64::MAX` for good, 0 to unmute.

    pub fn mute_contact(&self, contact_id: i64, until_ms: i64) -> Result<(), CoreError> {
        Ok(self.lock()?.mute_contact(contact_id, until_ms)?)
    }

    pub fn mute_group(&self, group: i64, until_ms: i64) -> Result<(), CoreError> {
        Ok(self.lock()?.mute_group(group, until_ms)?)
    }

    pub fn mute_channel(&self, channel_id: i64, until_ms: i64) -> Result<(), CoreError> {
        Ok(self.lock()?.mute_channel(channel_id, until_ms)?)
    }

    /// Whether a contact is muted now: its messages raise no notification. Works while locked.
    pub fn contact_muted(&self, contact_id: i64) -> bool {
        self.0.lock().is_ok_and(|node| node.contact_muted(contact_id))
    }

    /// Whether a group is muted now: no notification for its messages, its calls ring silently.
    /// Works while locked.
    pub fn group_muted(&self, group: i64) -> bool {
        self.0.lock().is_ok_and(|node| node.group_muted(group))
    }

    // Walkie-talkie channels (rust/airchat-protocol/docs/protocol.md §11).

    pub fn channels(&self) -> Result<Vec<WalkieChannel>, CoreError> {
        Ok(self.lock()?.channels()?.into_iter().map(WalkieChannel::from).collect())
    }

    /// A new channel with a random key; let others in with `channel_qr`.
    pub fn create_channel(&self, name: String) -> Result<WalkieChannel, CoreError> {
        Ok(self.lock()?.create_channel(&name)?.into())
    }

    /// The channel of a QR code someone shows.
    pub fn add_channel_from_qr(&self, qr_text: String) -> Result<WalkieChannel, CoreError> {
        Ok(self.lock()?.add_channel_from_qr(&qr_text)?.into())
    }

    /// The channel everyone typing `password` reaches. Takes about a second: call off the main thread.
    pub fn add_channel_from_password(&self, name: String, password: Vec<u8>) -> Result<WalkieChannel, CoreError> {
        let password = Zeroizing::new(password);
        let password = std::str::from_utf8(&password).map_err(|_| CoreError::PasswordTooShort)?;
        Ok(self.lock()?.add_channel_from_password(&name, password)?.into())
    }

    /// The text of a channel's QR code.
    pub fn channel_qr(&self, channel_id: i64) -> Result<String, CoreError> {
        Ok(self.lock()?.channel_qr(channel_id)?.to_string())
    }

    pub fn rename_channel(&self, channel_id: i64, name: String) -> Result<(), CoreError> {
        Ok(self.lock()?.rename_channel(channel_id, &name)?)
    }

    pub fn delete_channel(&self, channel_id: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.delete_channel(channel_id)?;
        Ok(out(&mut node, actions))
    }

    /// Tunes in to a channel, or to none (`None`).
    pub fn tune_channel(&self, channel_id: Option<i64>) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.tune_channel(channel_id)?;
        Ok(out(&mut node, actions))
    }

    /// The beacon to announce for the tuned channel; `None` when tuned to none. Works while locked.
    pub fn channel_token(&self) -> Option<Vec<u8>> {
        let mut node = self.0.lock().ok()?;
        node.channel_token(now_secs()).map(|t| t.to_vec())
    }

    /// Whether a channel beacon heard is a member of the tuned channel; connect like to a contact.
    pub fn recognize_channel(&self, token: Vec<u8>) -> Option<Recognized> {
        let token: [u8; 8] = token.try_into().ok()?;
        let mut node = self.0.lock().ok()?;
        node.recognize_channel(&token, now_secs())
            .map(Recognized::from)
            // A channel member's link is never moved to another transport: it is opened afresh.
            .map(|r| Recognized {
                may_replace: false,
                ..r
            })
    }

    /// A presence beacon heard over Wi-Fi that is no contact's or fellow member's: another AirChat
    /// device to link with for the mesh (rust/airchat-protocol/docs/protocol.md §10.2), with `connect_contact` on its id.
    pub fn recognize_stranger(&self, token: Vec<u8>) -> Option<Recognized> {
        let token: [u8; 8] = token.try_into().ok()?;
        let mut node = self.0.lock().ok()?;
        node.recognize_stranger(&token, now_secs())
            .map(Recognized::from)
            // A mesh link is opened afresh on another transport, not moved.
            .map(|r| Recognized {
                may_replace: false,
                ..r
            })
    }

    /// Links that carry mesh traffic now: Wi-Fi links to contacts and fellow members, and mesh links.
    pub fn mesh_neighbours(&self) -> u32 {
        self.0
            .lock()
            .map(|node| u32::try_from(node.mesh_neighbours()).unwrap_or(u32::MAX))
            .unwrap_or(0)
    }

    // Air Provider (rust/airchat-protocol/docs/protocol.md §12).

    /// What this device carries for others now, as Air Provider (requirements AP-1, AP-5); an
    /// empty list turns the mode off and closes the paths it carries.
    pub fn set_air_provider(&self, classes: Vec<PathClass>) -> Vec<Action> {
        let bits = classes.into_iter().fold(0, |bits, c| bits | Class::from(c).bit());
        self.with_node(|node| node.set_air_provider(Classes::from_bits(bits)))
    }

    /// Neighbours that carry `class` for others now: whether a path can be looked for.
    pub fn providers(&self, class: PathClass) -> u32 {
        self.0
            .lock()
            .map(|node| u32::try_from(node.providers(class.into())).unwrap_or(u32::MAX))
            .unwrap_or(0)
    }

    /// Looks for a path through Air Providers to a contact no direct Wi-Fi link reaches; a link
    /// over it comes up (`LinkUp`), or `PathFailed` follows. Nothing if a link carrying `class` is up.
    pub fn find_path(&self, contact_id: i64, class: PathClass) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.find_path(contact_id, class.into())?;
        Ok(out(&mut node, actions))
    }

    /// Looks for paths through Air Providers to the members of a group no link reaches now, so its
    /// next talk or call reaches them (group voice, rust/airchat-protocol/docs/protocol.md §9.6).
    pub fn reach_group(&self, group: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.reach_group(group)?;
        Ok(out(&mut node, actions))
    }

    /// Looks for a member of the tuned walkie-talkie channel through Air Providers (§11.5); a
    /// channel peer links over the path, or `PathFailed` follows. Nothing if one is linked.
    pub fn find_channel_path(&self) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.find_channel_path()?;
        Ok(out(&mut node, actions))
    }

    /// The path through Air Providers the link to a contact runs over; `None` for a direct link or none.
    pub fn link_path(&self, contact_id: i64) -> Option<LinkPath> {
        let (class, providers) = self.0.lock().ok()?.link_path(contact_id)?;
        Some(LinkPath {
            path_class: class.into(),
            providers,
        })
    }

    /// Bytes sent on a link over a path and not yet taken by the other end; `None` for other
    /// connections. Video holds back while it grows.
    pub fn path_backlog(&self, connection: u64) -> Option<u64> {
        let backlog = self.0.lock().ok()?.path_backlog(connection)?;
        Some(u64::try_from(backlog).unwrap_or(u64::MAX))
    }

    /// The members of the tuned channel linked now.
    pub fn channel_peers(&self) -> Result<Vec<ChannelPeer>, CoreError> {
        Ok(self
            .lock()?
            .channel_peers()
            .into_iter()
            .map(|p| ChannelPeer { id: p.id, name: p.name })
            .collect())
    }

    /// Talks to the members of the tuned channel linked now.
    pub fn start_channel_talk(&self) -> Result<Started, CoreError> {
        let mut node = self.lock()?;
        let (id, actions) = node.start_channel_talk()?;
        Ok(Started {
            id: id.to_vec(),
            actions: out(&mut node, actions),
        })
    }

    /// Talks to the members of a group linked now (push-to-talk).
    pub fn start_group_talk(&self, group: i64) -> Result<Started, CoreError> {
        let mut node = self.lock()?;
        let (id, actions) = node.start_group_talk(group)?;
        Ok(Started {
            id: id.to_vec(),
            actions: out(&mut node, actions),
        })
    }

    /// Calls a group; `GroupCallChanged` follows as members join. End it with `end_call`.
    pub fn start_group_call(&self, group: i64) -> Result<Started, CoreError> {
        let mut node = self.lock()?;
        let (id, actions) = node.start_group_call(group)?;
        Ok(Started {
            id: id.to_vec(),
            actions: out(&mut node, actions),
        })
    }

    /// Joins the group call ringing here.
    pub fn join_group_call(&self, id: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let id = stream_id(&id)?;
        let mut node = self.lock()?;
        let actions = node.join_group_call(id)?;
        Ok(out(&mut node, actions))
    }

    /// Whether a group's push-to-talk plays at once.
    pub fn set_group_ptt(&self, group: i64, allow: bool) -> Result<(), CoreError> {
        Ok(self.lock()?.set_group_ptt(group, allow)?)
    }

    /// Starts talking to a linked contact (push-to-talk).
    pub fn start_talk(&self, contact_id: i64) -> Result<Started, CoreError> {
        let mut node = self.lock()?;
        let (id, actions) = node.start_talk(contact_id)?;
        Ok(Started {
            id: id.to_vec(),
            actions: out(&mut node, actions),
        })
    }

    pub fn end_talk(&self, id: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.end_talk(stream_id(&id)?);
        Ok(out(&mut node, actions))
    }

    /// One encoded packet (20 ms of Opus) of this device's audio for a call or talk. Wiped once sent.
    pub fn send_audio(&self, stream: Vec<u8>, packet: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let packet = Zeroizing::new(packet);
        let mut node = self.lock()?;
        let actions = node.send_audio(stream_id(&stream)?, &packet);
        Ok(out(&mut node, actions))
    }

    // Moving a link.

    /// Asks a linked contact to open `target` so the link can move there.
    pub fn request_move(&self, contact_id: i64, target: MoveTarget) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.request_move(contact_id, target.into())?;
        Ok(out(&mut node, actions))
    }

    /// Answers `MoveRequested`: the hotspot is up and listening on `offer.port`.
    pub fn offer_hotspot(&self, contact_id: i64, offer: HotspotOffer) -> Result<Vec<Action>, CoreError> {
        let offer = CoreHotspotOffer {
            ssid: offer.ssid,
            passphrase: offer.passphrase,
            port: offer.port,
        };
        let mut node = self.lock()?;
        let actions = node.offer_hotspot(contact_id, offer)?;
        Ok(out(&mut node, actions))
    }

    pub fn decline_move(&self, contact_id: i64, target: MoveTarget) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.decline_move(contact_id, target.into())?;
        Ok(out(&mut node, actions))
    }

    // Files.

    /// Starts sending a file to a contact. Write its content in order with [`Account::write_file`],
    /// then call [`Account::finish_file`] (or [`Account::abort_file`]). Returns the file's id, which
    /// is also its message's id. `thumbnail` is a small JPEG shown before the file is fetched.
    pub fn begin_file(
        &self,
        contact_id: i64,
        name: String,
        mime: String,
        thumbnail: Option<Vec<u8>>,
    ) -> Result<i64, CoreError> {
        Ok(self.lock()?.begin_file(contact_id, &name, &mime, thumbnail)?)
    }

    /// The next part of a file being sent; parts may have any length. Wiped once written.
    pub fn write_file(&self, file: i64, data: Vec<u8>) -> Result<(), CoreError> {
        let data = Zeroizing::new(data);
        Ok(self.lock()?.write_file(file, &data)?)
    }

    /// Completes a file being sent; its offer goes out now if the contact is linked, otherwise later.
    pub fn finish_file(&self, file: i64) -> Result<SentMessage, CoreError> {
        let mut node = self.lock()?;
        let (message, actions) = node.finish_file(file)?;
        Ok(SentMessage {
            message: message.into(),
            actions: out(&mut node, actions),
        })
    }

    /// The user played voice message `file` (a group file named as [`group_file`] does); one that
    /// came in goes a quarter of an hour after its first play.
    pub fn voice_played(&self, file: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.voice_played(file)?;
        Ok(out(&mut node, actions))
    }

    /// Gives up a file being sent before it was finished.
    pub fn abort_file(&self, file: i64) -> Result<(), CoreError> {
        Ok(self.lock()?.abort_file(file)?)
    }

    /// Starts or retries fetching a file offered by a contact; it goes on whenever they are linked.
    pub fn download_file(&self, file: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.download(file)?;
        Ok(out(&mut node, actions))
    }

    /// Starts sending a file to a group; like [`Account::begin_file`], with
    /// [`Account::finish_group_file`] to complete it. Returns the file's name (see [`group_file`]).
    pub fn begin_group_file(
        &self,
        group: i64,
        name: String,
        mime: String,
        thumbnail: Option<Vec<u8>>,
    ) -> Result<i64, CoreError> {
        Ok(self.lock()?.begin_group_file(group, &name, &mime, thumbnail)?)
    }

    /// Completes a group file: its message goes to the members linked now, and later to the others.
    pub fn finish_group_file(&self, file: i64) -> Result<SentGroupMessage, CoreError> {
        let mut node = self.lock()?;
        let (message, actions) = node.finish_group_file(file)?;
        Ok(SentGroupMessage {
            message: message.into(),
            actions: out(&mut node, actions),
        })
    }

    /// Starts or retries fetching a group message's file from the members.
    pub fn download_group_file(&self, message_id: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.download_group_file(message_id)?;
        Ok(out(&mut node, actions))
    }

    /// Up to `len` bytes of a stored file from `offset`, to show or export it.
    pub fn read_file(&self, file: i64, offset: u64, len: u32) -> Result<Vec<u8>, CoreError> {
        let data = self.lock()?.read_file(file, offset, len as usize)?;
        Ok(data.to_vec())
    }

    /// The conversation with a contact, oldest first.
    pub fn messages(&self, contact_id: i64) -> Result<Vec<Message>, CoreError> {
        Ok(self
            .lock()?
            .messages(contact_id)?
            .into_iter()
            .map(Message::from)
            .collect())
    }

    // Groups.

    /// Groups this device is or was in (left or removed ones keep their history).
    pub fn groups(&self) -> Result<Vec<Group>, CoreError> {
        Ok(self.lock()?.groups()?.into_iter().map(Group::from).collect())
    }

    /// The chat list: every conversation's latest message and unread count, 1:1 and groups.
    pub fn chat_previews(&self) -> Result<Vec<ChatPreview>, CoreError> {
        let node = self.lock()?;
        let mut previews: Vec<ChatPreview> = node
            .contact_previews()?
            .into_iter()
            .map(|(contact, last, unread)| ChatPreview {
                contact_id: Some(contact),
                group_id: None,
                last: last.map(|m| LastMessage {
                    body: m.body,
                    voice: m
                        .attachment
                        .as_ref()
                        .is_some_and(|a| airchat_core::storage::is_voice(&a.mime, a.size)),
                    file_name: m.attachment.map(|a| a.name),
                    outgoing: m.outgoing,
                    sender_name: None,
                    status: match m.status {
                        storage::MessageStatus::Queued | storage::MessageStatus::Sent => PreviewStatus::Sending,
                        storage::MessageStatus::Delivered => PreviewStatus::Delivered,
                        storage::MessageStatus::Received => PreviewStatus::Received,
                        storage::MessageStatus::Refused => PreviewStatus::Refused,
                        storage::MessageStatus::Failed => PreviewStatus::Failed,
                    },
                    at_ms: m.stored_at_ms,
                }),
                unread,
            })
            .collect();
        for (group, last, unread) in node.group_previews()? {
            let last = last.map(|m| {
                // Who wrote it, as the group's members name themselves.
                let sender_name = (!m.outgoing).then(|| {
                    node.group_members(group)
                        .ok()
                        .and_then(|members| members.into_iter().find(|member| member.identity == m.sender))
                        .map(|member| member.name)
                        .unwrap_or_default()
                });
                LastMessage {
                    body: m.body,
                    voice: m
                        .attachment
                        .as_ref()
                        .is_some_and(|a| airchat_core::storage::is_voice(&a.mime, a.size)),
                    file_name: m.attachment.map(|a| a.name),
                    outgoing: m.outgoing,
                    sender_name,
                    status: match m.status {
                        stored_groups::GroupMessageStatus::Queued => PreviewStatus::Sending,
                        stored_groups::GroupMessageStatus::Sent => PreviewStatus::Sent,
                        stored_groups::GroupMessageStatus::Received => PreviewStatus::Received,
                        stored_groups::GroupMessageStatus::Failed => PreviewStatus::Failed,
                    },
                    at_ms: m.stored_at_ms,
                }
            });
            previews.push(ChatPreview {
                contact_id: None,
                group_id: Some(group),
                last,
                unread,
            });
        }
        Ok(previews)
    }

    /// The user has read the conversation with a contact up to its latest message.
    pub fn mark_contact_read(&self, contact_id: i64) -> Result<(), CoreError> {
        Ok(self.lock()?.mark_contact_read(contact_id)?)
    }

    /// The user has read a group up to its latest message.
    pub fn mark_group_read(&self, group: i64) -> Result<(), CoreError> {
        Ok(self.lock()?.mark_group_read(group)?)
    }

    pub fn group_members(&self, group: i64) -> Result<Vec<GroupMember>, CoreError> {
        Ok(self
            .lock()?
            .group_members(group)?
            .into_iter()
            .map(GroupMember::from)
            .collect())
    }

    /// A group's conversation, oldest first.
    pub fn group_messages(&self, group: i64) -> Result<Vec<GroupMessage>, CoreError> {
        Ok(self
            .lock()?
            .group_messages(group)?
            .into_iter()
            .map(GroupMessage::from)
            .collect())
    }

    /// Creates a group of this device (its admin) and some active contacts.
    pub fn create_group(&self, name: String, contact_ids: Vec<i64>) -> Result<ChangedGroup, CoreError> {
        let mut node = self.lock()?;
        let (group, actions) = node.create_group(&name, &contact_ids)?;
        Ok(ChangedGroup::new(group, out(&mut node, actions)))
    }

    /// Adds contacts to a group this device administers; `expires` (Unix seconds, 0 for never)
    /// makes them temporary members.
    pub fn add_group_members(
        &self,
        group: i64,
        contact_ids: Vec<i64>,
        expires: u64,
    ) -> Result<ChangedGroup, CoreError> {
        let mut node = self.lock()?;
        let (group, actions) = node.add_group_members(group, &contact_ids, expires)?;
        Ok(ChangedGroup::new(group, out(&mut node, actions)))
    }

    pub fn remove_group_member(&self, group: i64, identity: Vec<u8>) -> Result<ChangedGroup, CoreError> {
        let identity: [u8; 32] = identity.try_into().map_err(|_| CoreError::UnknownContact)?;
        let mut node = self.lock()?;
        let (group, actions) = node.remove_group_member(group, &PublicIdentity::from_bytes(identity))?;
        Ok(ChangedGroup::new(group, out(&mut node, actions)))
    }

    /// Adds contacts to a group this device administers for as long as it is in the group's call.
    pub fn add_group_members_for_call(&self, group: i64, contact_ids: Vec<i64>) -> Result<ChangedGroup, CoreError> {
        let mut node = self.lock()?;
        let (group, actions) = node.add_group_members_for_call(group, &contact_ids)?;
        Ok(ChangedGroup::new(group, out(&mut node, actions)))
    }

    /// Makes a member an admin of a group this device administers, or no longer one.
    pub fn set_group_admin(&self, group: i64, identity: Vec<u8>, admin: bool) -> Result<ChangedGroup, CoreError> {
        let identity = identity_of(identity)?;
        let mut node = self.lock()?;
        let (group, actions) = node.set_group_admin(group, &identity, admin)?;
        Ok(ChangedGroup::new(group, out(&mut node, actions)))
    }

    /// Asks `with`, linked now, to agree to a group of the two of you and another contact
    /// (rust/airchat-protocol/docs/protocol.md §9.8); `expires` (Unix seconds) ends that contact's membership, 0 never.
    pub fn propose_member(
        &self,
        with: i64,
        person: i64,
        group_name: String,
        expires: u64,
    ) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.propose_member(with, person, &group_name, expires)?;
        Ok(out(&mut node, actions))
    }

    pub fn answer_member_proposal(&self, from: i64, id: Vec<u8>, agree: bool) -> Result<Vec<Action>, CoreError> {
        let id: [u8; 16] = id.try_into().map_err(|_| CoreError::UnknownContact)?;
        let mut node = self.lock()?;
        let actions = node.answer_member_proposal(from, id, agree)?;
        Ok(out(&mut node, actions))
    }

    /// Leaves a group: its keys go, its history stays.
    pub fn leave_group(&self, group: i64) -> Result<ChangedGroup, CoreError> {
        let mut node = self.lock()?;
        let (group, actions) = node.leave_group(group)?;
        Ok(ChangedGroup::new(group, out(&mut node, actions)))
    }

    /// Deletes a group this device administers for every member: their devices delete its
    /// history too (rust/airchat-protocol/docs/protocol.md §9.2).
    pub fn delete_group_for_everyone(&self, group: i64) -> Result<ChangedGroup, CoreError> {
        let mut node = self.lock()?;
        let (group, actions) = node.delete_group_for_everyone(group)?;
        Ok(ChangedGroup::new(group, out(&mut node, actions)))
    }

    /// Deletes the conversation of a group this device left or was removed from, on this device.
    pub fn delete_group(&self, group: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.delete_group(group)?;
        Ok(out(&mut node, actions))
    }

    /// Stores the message and passes it to the members linked now, the others later.
    /// Tries one of this device's group messages given up (no member took it within a day) again,
    /// from now: its row.
    pub fn try_group_message_again(&self, row: i64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.try_group_message_again(row)?;
        Ok(out(&mut node, actions))
    }

    pub fn send_group_message(&self, group: i64, text: String) -> Result<SentGroupMessage, CoreError> {
        let mut node = self.lock()?;
        let (message, actions) = node.send_group_message(group, &text)?;
        Ok(SentGroupMessage {
            message: message.into(),
            actions: out(&mut node, actions),
        })
    }

    // Pairing.

    /// Opens "Add nearby"; announce the beacon's token and show its label.
    pub fn open_pairing(&self) -> Result<PairingBeacon, CoreError> {
        Ok(self.lock()?.open_pairing()?.into())
    }

    /// Closes "Add nearby"; carry out the returned actions to abandon unfinished pairings.
    pub fn close_pairing(&self) -> Vec<Action> {
        self.with_node(Node::close_pairing)
    }

    /// The text of a new QR invite, valid for ten minutes.
    pub fn create_invite(&self) -> Result<String, CoreError> {
        Ok(self.lock()?.create_invite(now_secs())?)
    }

    /// Starts Nearby Pairing on a new outgoing connection.
    pub fn pair_nearby(&self, connection: u64) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.pair_nearby(connection)?;
        Ok(out(&mut node, actions))
    }

    /// Starts pairing through a scanned QR code on a new outgoing connection.
    pub fn pair_with_invite(&self, connection: u64, qr_text: String) -> Result<Vec<Action>, CoreError> {
        let mut node = self.lock()?;
        let actions = node.pair_with_invite(connection, &qr_text)?;
        Ok(out(&mut node, actions))
    }

    pub fn confirm_pairing(&self, connection: u64) -> Vec<Action> {
        self.with_node(|node| node.confirm_pairing(connection))
    }

    pub fn reject_pairing(&self, connection: u64) -> Vec<Action> {
        self.with_node(|node| node.reject_pairing(connection))
    }

    // Adding by AirChat ID (rust/airchat-protocol/docs/protocol.md §4.8).

    /// Asks the owner of a typed AirChat ID to add this device, whenever the two meet; returns the
    /// ID as it is shown.
    pub fn request_contact(&self, airchat_id: String) -> Result<String, CoreError> {
        Ok(self.lock()?.request_contact(&airchat_id)?.to_string())
    }

    /// The IDs typed whose owners have not added this device yet.
    pub fn sent_requests(&self) -> Result<Vec<String>, CoreError> {
        Ok(self.lock()?.sent_requests()?.iter().map(ToString::to_string).collect())
    }

    pub fn cancel_contact_request(&self, airchat_id: String) -> Result<bool, CoreError> {
        let id = AirChatId::parse(&airchat_id).map_err(|_| CoreError::InvalidId)?;
        Ok(self.lock()?.cancel_contact_request(&id)?)
    }

    /// The request tokens to announce (8 bytes each), for this hour; none while locked.
    pub fn request_tokens(&self) -> Vec<Vec<u8>> {
        self.0.lock().map_or_else(
            |_| Vec::new(),
            |node| node.request_tokens(now_secs()).iter().map(|t| t.to_vec()).collect(),
        )
    }

    /// Whether the user lets others ask to be added (requirement C-4): requests seen nearby and
    /// paths through Air Providers are answered only while on. Off until set.
    pub fn set_accept_requests(&self, accept: bool) {
        if let Ok(mut node) = self.0.lock() {
            node.set_accept_requests(accept);
        }
    }

    /// Whether a request token seen nearby asks for this device's owner: then connect to its
    /// device and call [`Account::answer_request`].
    pub fn recognize_request(&self, token: Vec<u8>) -> bool {
        let Ok(token) = <[u8; discovery::REQUEST_TOKEN_LEN]>::try_from(token) else {
            return false;
        };
        self.0
            .lock()
            .is_ok_and(|mut node| node.recognize_request(&token, now_secs()))
    }

    /// Answers a request on a new outgoing connection to the device announcing it.
    pub fn answer_request(&self, connection: u64, token: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let token: [u8; discovery::REQUEST_TOKEN_LEN] = token
            .try_into()
            .map_err(|_| CoreError::Internal("a request token has 8 bytes".into()))?;
        let mut node = self.lock()?;
        let actions = node.answer_request(connection, &token)?;
        Ok(out(&mut node, actions))
    }

    /// Requests to be added not answered yet, newest first.
    pub fn contact_requests(&self) -> Result<Vec<ContactRequest>, CoreError> {
        Ok(self.lock()?.contact_requests()?.into_iter().map(Into::into).collect())
    }

    pub fn approve_contact_request(&self, identity: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let identity = identity_of(identity)?;
        let mut node = self.lock()?;
        let actions = node.approve_contact_request(&identity)?;
        Ok(out(&mut node, actions))
    }

    pub fn decline_contact_request(&self, identity: Vec<u8>) -> Result<Vec<Action>, CoreError> {
        let identity = identity_of(identity)?;
        let mut node = self.lock()?;
        let actions = node.decline_contact_request(&identity)?;
        Ok(out(&mut node, actions))
    }

    // Connections.

    /// Every frame received on any connection, incoming or outgoing.
    pub fn on_frame(&self, connection: u64, frame: Vec<u8>) -> Vec<Action> {
        self.with_node(|node| node.on_frame(connection, &frame, now_secs()))
    }

    /// Checks every link for signs of life; call every few seconds while the network runs. Pings
    /// silent links and closes those whose other end stopped answering.
    pub fn tick(&self) -> Vec<Action> {
        self.with_node(|node| node.tick(now_secs()))
    }

    pub fn connection_closed(&self, connection: u64) -> Vec<Action> {
        self.with_node(|node| node.connection_closed(connection))
    }

    /// The connection runs over Bluetooth, which carries discovery and setting up Wi-Fi only
    /// (rust/airchat-protocol/docs/protocol.md §7.3): a link on it moves to Wi-Fi before data flows. Before its first frame.
    pub fn mark_setup_only(&self, connection: u64) {
        if let Ok(mut node) = self.0.lock() {
            node.setup_only(connection);
        }
    }
}

/// The pairing token a QR invite's device announces (rust/airchat-protocol/docs/protocol.md §4.4): announce it while
/// showing the code; after scanning one, connect to the device announcing it. `None` if the text is
/// not a contact invite.
#[uniffi::export]
pub fn invite_beacon_token(qr_text: String) -> Option<Vec<u8>> {
    Some(
        airchat_core::pairing::ScannedInvite::parse(&qr_text)
            .ok()?
            .beacon_token()
            .to_vec(),
    )
}

/// The label of another device's pairing beacon, as its own screen shows it.
#[uniffi::export]
pub fn pairing_beacon_label(token: Vec<u8>) -> Option<String> {
    let token: [u8; PAIRING_TOKEN_LEN] = token.try_into().ok()?;
    Some(CoreBeacon::from_token(token).label())
}

/// The Wi-Fi Aware service AirChat devices publish and subscribe to.
#[uniffi::export]
pub fn aware_service_name() -> String {
    discovery::AWARE_SERVICE_NAME.to_owned()
}

/// The follow-up message that asks a publisher for a data path.
#[uniffi::export]
pub fn aware_connect_request() -> Vec<u8> {
    discovery::AWARE_CONNECT_REQUEST.to_vec()
}

/// A beacon published over Wi-Fi Aware.
#[derive(uniffi::Enum)]
pub enum AwareBeacon {
    Presence {
        token: Vec<u8>,
    },
    Pairing {
        token: Vec<u8>,
    },
    /// A walkie-talkie channel the device is tuned to.
    Channel {
        token: Vec<u8>,
    },
    /// A request to add the owner of an AirChat ID.
    Request {
        token: Vec<u8>,
    },
}

/// The service-specific information to publish; `None` if the token has the wrong length.
#[uniffi::export]
pub fn encode_aware_beacon(beacon: AwareBeacon) -> Option<Vec<u8>> {
    Some(
        match beacon {
            AwareBeacon::Presence { token } => CoreAwareBeacon::Presence(token.try_into().ok()?),
            AwareBeacon::Pairing { token } => CoreAwareBeacon::Pairing(token.try_into().ok()?),
            AwareBeacon::Channel { token } => CoreAwareBeacon::Channel(token.try_into().ok()?),
            AwareBeacon::Request { token } => CoreAwareBeacon::Request(token.try_into().ok()?),
        }
        .encode(),
    )
}

/// Reads a discovered publisher's service-specific information; `None` if it is not a beacon.
#[uniffi::export]
pub fn decode_aware_beacon(data: Vec<u8>) -> Option<AwareBeacon> {
    Some(match CoreAwareBeacon::decode(&data)? {
        CoreAwareBeacon::Presence(token) => AwareBeacon::Presence { token: token.to_vec() },
        CoreAwareBeacon::Pairing(token) => AwareBeacon::Pairing { token: token.to_vec() },
        CoreAwareBeacon::Channel(token) => AwareBeacon::Channel { token: token.to_vec() },
        CoreAwareBeacon::Request(token) => AwareBeacon::Request { token: token.to_vec() },
    })
}

/// The UUID under which BLE advertisements carry AirChat beacons as service data.
#[uniffi::export]
pub fn ble_service_uuid() -> String {
    discovery::BLE_SERVICE_UUID.to_owned()
}

/// A beacon in a BLE advertisement: the token and the L2CAP PSM to connect to.
#[derive(uniffi::Enum)]
pub enum BleBeacon {
    Presence {
        psm: u16,
        token: Vec<u8>,
    },
    Pairing {
        psm: u16,
        token: Vec<u8>,
    },
    /// A walkie-talkie channel the device is tuned to.
    Channel {
        psm: u16,
        token: Vec<u8>,
    },
    /// A request to add the owner of an AirChat ID.
    Request {
        psm: u16,
        token: Vec<u8>,
    },
}

/// The service data to advertise; `None` if the token has the wrong length or the PSM cannot be
/// announced.
#[uniffi::export]
pub fn encode_ble_beacon(beacon: BleBeacon) -> Option<Vec<u8>> {
    let beacon = match beacon {
        BleBeacon::Presence { psm, token } => CoreBleBeacon::Presence {
            psm,
            token: token.try_into().ok()?,
        },
        BleBeacon::Pairing { psm, token } => CoreBleBeacon::Pairing {
            psm,
            token: token.try_into().ok()?,
        },
        BleBeacon::Channel { psm, token } => CoreBleBeacon::Channel {
            psm,
            token: token.try_into().ok()?,
        },
        BleBeacon::Request { psm, token } => CoreBleBeacon::Request {
            psm,
            token: token.try_into().ok()?,
        },
    };
    beacon.encode()
}

/// Reads the service data of a scanned advertisement; `None` if it is not a valid beacon.
#[uniffi::export]
pub fn decode_ble_beacon(data: Vec<u8>) -> Option<BleBeacon> {
    Some(match CoreBleBeacon::decode(&data)? {
        CoreBleBeacon::Presence { psm, token } => BleBeacon::Presence {
            psm,
            token: token.to_vec(),
        },
        CoreBleBeacon::Pairing { psm, token } => BleBeacon::Pairing {
            psm,
            token: token.to_vec(),
        },
        CoreBleBeacon::Channel { psm, token } => BleBeacon::Channel {
            psm,
            token: token.to_vec(),
        },
        CoreBleBeacon::Request { psm, token } => BleBeacon::Request {
            psm,
            token: token.to_vec(),
        },
    })
}

/// Someone who asked to be added: its AirChat ID is proven, its name is its own claim.
#[derive(uniffi::Record)]
pub struct ContactRequest {
    pub identity: Vec<u8>,
    pub airchat_id: String,
    pub display_name: String,
    pub received_at_ms: i64,
}

impl From<storage::requests::ContactRequest> for ContactRequest {
    fn from(request: storage::requests::ContactRequest) -> Self {
        Self {
            identity: request.identity.as_bytes().to_vec(),
            airchat_id: request.identity.airchat_id().to_string(),
            display_name: request.display_name,
            received_at_ms: request.received_at_ms,
        }
    }
}

/// A contact's proposal to make a group of the two of you and someone else (rust/airchat-protocol/docs/protocol.md §9.8).
#[derive(uniffi::Record)]
pub struct MemberProposal {
    pub id: Vec<u8>,
    pub person_airchat_id: String,
    /// The contact's name for the person.
    pub person_name: String,
    pub group_name: String,
    /// Unix seconds when the person's membership would end; 0 for a permanent one.
    pub expires: u64,
}

fn identity_of(bytes: Vec<u8>) -> Result<PublicIdentity, CoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| CoreError::UnknownContact)?;
    Ok(PublicIdentity::from_bytes(bytes))
}

#[derive(uniffi::Record)]
pub struct PairingBeacon {
    pub token: Vec<u8>,
    pub label: String,
}

impl From<CoreBeacon> for PairingBeacon {
    fn from(beacon: CoreBeacon) -> Self {
        Self {
            token: beacon.token().to_vec(),
            label: beacon.label(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct Contact {
    pub id: i64,
    pub display_name: String,
    pub airchat_id: String,
    pub added_at_ms: i64,
    pub state: ContactState,
    pub permissions: Permissions,
    /// Until when (Unix ms) it is muted; 0 if not, `i64::MAX` for good.
    pub muted_until: i64,
    /// Its build was last attested as the official one on a verified phone (rust/airchat-protocol/docs/protocol.md §6.10).
    pub verified_build: bool,
    /// That phone's security patch level (YYYYMM or YYYYMMDD), 0 if not known.
    pub security_patch: u32,
}

impl From<ContactSummary> for Contact {
    fn from(contact: ContactSummary) -> Self {
        Self {
            id: contact.id,
            display_name: contact.display_name,
            airchat_id: contact.identity.airchat_id().to_string(),
            added_at_ms: contact.added_at_ms,
            state: match contact.state {
                storage::ContactState::Active => ContactState::Active,
                storage::ContactState::Blocked => ContactState::Blocked,
                storage::ContactState::Former => ContactState::Former,
                storage::ContactState::Peer => ContactState::Peer,
            },
            permissions: Permissions {
                messages: contact.permissions.messages,
                ptt: contact.permissions.ptt,
                auto_download: contact.permissions.auto_download,
            },
            muted_until: contact.muted_until,
            verified_build: contact.attested.is_some(),
            security_patch: contact.attested.map_or(0, |a| a.os_patch_level),
        }
    }
}

#[derive(uniffi::Enum)]
pub enum ContactState {
    Active,
    /// Neither recognised nor linked; they see this device as away.
    Blocked,
    /// Deleted with the conversation kept; pairing again makes them active.
    Former,
    /// Not a contact: met through a shared group.
    Peer,
}

/// What a contact may do.
#[derive(uniffi::Record)]
pub struct Permissions {
    /// Send messages and files, and call.
    pub messages: bool,
    /// Instant voice, which plays without accepting it.
    pub ptt: bool,
    /// Their files are fetched without asking.
    pub auto_download: bool,
}

#[derive(uniffi::Enum)]
pub enum Failure {
    Rejected,
    AuthenticationFailed,
    InvalidInvite,
    NotAccepting,
    ConnectionLost,
    /// Paired with someone this user blocked; they stay blocked.
    Blocked,
    Protocol,
}

#[derive(uniffi::Record)]
pub struct Recognized {
    pub contact_id: i64,
    /// Open a link now: none is up or being set up, and this device opens links to the contact.
    pub initiate: bool,
    /// A link is up and this device may open a second one to replace it, e.g. over a faster
    /// transport; the old one closes once the new one is up.
    pub may_replace: bool,
    /// The connection carrying the established link, if any.
    pub link_connection: Option<u64>,
}

#[derive(uniffi::Enum)]
pub enum MessageStatus {
    Queued,
    Sent,
    Delivered,
    Received,
    /// Turned down: the contact takes no messages from this user.
    Refused,
    /// Not delivered within a day of being sent (or tried again): sent no more until tried again.
    Failed,
}

/// A conversation in the chat list: a contact's or a group's, its latest message and how many
/// messages from others are unread.
#[derive(uniffi::Record)]
pub struct ChatPreview {
    pub contact_id: Option<i64>,
    pub group_id: Option<i64>,
    pub last: Option<LastMessage>,
    pub unread: u32,
}

/// The latest message of a conversation, as the chat list shows it.
#[derive(uniffi::Record)]
pub struct LastMessage {
    /// The text; empty for a file.
    pub body: String,
    pub file_name: Option<String>,
    /// The file is a voice message.
    pub voice: bool,
    pub outgoing: bool,
    /// In a group, who wrote it (empty if unknown); none for this device's own or 1:1.
    pub sender_name: Option<String>,
    pub status: PreviewStatus,
    /// This device's clock when it was written or arrived.
    pub at_ms: i64,
}

#[derive(uniffi::Enum)]
pub enum PreviewStatus {
    /// From someone else.
    Received,
    /// Not acknowledged yet.
    Sending,
    /// In a group: a member has it.
    Sent,
    Delivered,
    Refused,
    /// Not delivered within a day.
    Failed,
}

#[derive(uniffi::Enum)]
pub enum AttachmentState {
    /// Offered by the contact; not fetched unless asked.
    Offered,
    Downloading,
    /// All here and checked, or (outgoing) ready to be fetched.
    Complete,
    /// Arrived damaged and was discarded; can be fetched again.
    Failed,
    /// The sender no longer has it.
    Gone,
}

/// A file carried by a message.
#[derive(uniffi::Record)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub thumbnail: Option<Vec<u8>>,
    /// Bytes stored on this device so far.
    pub stored: u64,
    pub state: AttachmentState,
    /// When a voice message that came in was first played (Unix ms), 0 if not yet.
    pub played_at_ms: i64,
}

#[derive(uniffi::Record)]
pub struct Message {
    pub id: i64,
    pub contact_id: i64,
    pub outgoing: bool,
    /// Empty for a file.
    pub body: String,
    pub sent_at_ms: i64,
    pub stored_at_ms: i64,
    pub status: MessageStatus,
    pub attachment: Option<Attachment>,
}

impl From<StoredMessage> for Message {
    fn from(message: StoredMessage) -> Self {
        Self {
            id: message.id,
            contact_id: message.contact_id,
            outgoing: message.outgoing,
            body: message.body,
            sent_at_ms: message.sent_at_ms,
            stored_at_ms: message.stored_at_ms,
            status: match message.status {
                storage::MessageStatus::Queued => MessageStatus::Queued,
                storage::MessageStatus::Sent => MessageStatus::Sent,
                storage::MessageStatus::Delivered => MessageStatus::Delivered,
                storage::MessageStatus::Received => MessageStatus::Received,
                storage::MessageStatus::Refused => MessageStatus::Refused,
                storage::MessageStatus::Failed => MessageStatus::Failed,
            },
            attachment: message.attachment.map(Attachment::from),
        }
    }
}

impl From<storage::Attachment> for Attachment {
    fn from(a: storage::Attachment) -> Self {
        Self {
            name: a.name,
            mime: a.mime,
            size: a.size,
            thumbnail: a.thumbnail,
            stored: a.stored,
            state: match a.state {
                storage::AttachmentState::Offered => AttachmentState::Offered,
                storage::AttachmentState::Downloading => AttachmentState::Downloading,
                storage::AttachmentState::Complete => AttachmentState::Complete,
                // Never shown: unfinished outgoing files are not listed.
                storage::AttachmentState::Failed | storage::AttachmentState::Importing => AttachmentState::Failed,
                storage::AttachmentState::Gone => AttachmentState::Gone,
            },
            played_at_ms: a.played_at_ms,
        }
    }
}

#[derive(uniffi::Record)]
pub struct SentMessage {
    pub message: Message,
    pub actions: Vec<Action>,
}

#[derive(uniffi::Enum)]
pub enum Membership {
    Member,
    Left,
    /// An admin removed this device, or its temporary membership ran out.
    Removed,
    /// An admin deleted the group for everyone; it is gone from the list.
    Deleted,
    /// Everyone else left (or their time ran out); the history stays.
    Ended,
}

#[derive(uniffi::Record)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub members: u32,
    pub membership: Membership,
    /// This device may add and remove members.
    pub admin: bool,
    /// Push-to-talk from its members plays at once.
    pub instant_voice: bool,
    /// Until when (Unix ms) it is muted; 0 if not, `i64::MAX` for good.
    pub muted_until: i64,
}

impl From<stored_groups::GroupSummary> for Group {
    fn from(group: stored_groups::GroupSummary) -> Self {
        Self {
            id: group.row,
            name: group.name,
            members: group.members,
            membership: match group.membership {
                stored_groups::Membership::Member => Membership::Member,
                stored_groups::Membership::Left => Membership::Left,
                stored_groups::Membership::Removed => Membership::Removed,
                stored_groups::Membership::Deleted => Membership::Deleted,
                stored_groups::Membership::Ended => Membership::Ended,
            },
            admin: group.admin,
            instant_voice: group.instant_voice,
            muted_until: group.muted_until,
        }
    }
}

#[derive(uniffi::Record)]
pub struct GroupMember {
    /// The member's identity key, to remove them with.
    pub identity: Vec<u8>,
    pub airchat_id: String,
    /// The name the member gave themselves.
    pub name: String,
    pub admin: bool,
    /// Unix seconds when a temporary membership ends; 0 for a permanent one.
    pub expires: u64,
    pub me: bool,
    /// Their contact, if they are one.
    pub contact_id: Option<i64>,
    /// How voice actions name them (`contact_id`, or a fellow member's); none for this device.
    pub row_id: Option<i64>,
}

impl From<node::GroupMember> for GroupMember {
    fn from(member: node::GroupMember) -> Self {
        Self {
            identity: member.identity.as_bytes().to_vec(),
            airchat_id: member.identity.airchat_id().to_string(),
            name: member.name,
            admin: member.admin,
            expires: member.expires,
            me: member.me,
            contact_id: member.contact,
            row_id: member.row,
        }
    }
}

#[derive(uniffi::Enum)]
pub enum GroupMessageStatus {
    /// Outgoing, no member has it yet.
    Queued,
    /// Outgoing, a member has it and passes it on.
    Sent,
    Received,
    /// Outgoing, no member took it within a day of being sent (or tried again): sent no more until
    /// tried again.
    Failed,
}

#[derive(uniffi::Record)]
pub struct GroupMessage {
    pub id: i64,
    pub group_id: i64,
    /// The sender's identity key; match it with the group's members.
    pub sender: Vec<u8>,
    pub outgoing: bool,
    pub body: String,
    pub sent_at_ms: i64,
    pub stored_at_ms: i64,
    pub status: GroupMessageStatus,
    /// A file message's file; its content is read and written under `group_file(id)`.
    pub attachment: Option<Attachment>,
}

impl From<stored_groups::GroupMessage> for GroupMessage {
    fn from(message: stored_groups::GroupMessage) -> Self {
        Self {
            id: message.row,
            group_id: message.group,
            sender: message.sender.as_bytes().to_vec(),
            outgoing: message.outgoing,
            body: message.body,
            sent_at_ms: message.sent_at_ms,
            stored_at_ms: message.stored_at_ms,
            status: match message.status {
                stored_groups::GroupMessageStatus::Queued => GroupMessageStatus::Queued,
                stored_groups::GroupMessageStatus::Sent => GroupMessageStatus::Sent,
                stored_groups::GroupMessageStatus::Received => GroupMessageStatus::Received,
                stored_groups::GroupMessageStatus::Failed => GroupMessageStatus::Failed,
            },
            attachment: message.attachment.map(Attachment::from),
        }
    }
}

impl From<node::Recognized> for Recognized {
    fn from(recognized: node::Recognized) -> Self {
        Self {
            contact_id: recognized.contact,
            initiate: recognized.initiate(),
            may_replace: recognized.may_replace(),
            link_connection: recognized.link,
        }
    }
}

/// A walkie-talkie channel this device holds the key of.
#[derive(uniffi::Record)]
pub struct WalkieChannel {
    pub id: i64,
    pub name: String,
    /// Listened to now.
    pub tuned: bool,
    /// Until when (Unix ms) its talk does not play; 0 if not, `i64::MAX` for good.
    pub muted_until: i64,
}

impl From<storage::channels::ChannelSummary> for WalkieChannel {
    fn from(channel: storage::channels::ChannelSummary) -> Self {
        Self {
            id: channel.row,
            name: channel.name,
            tuned: channel.tuned,
            muted_until: channel.muted_until,
        }
    }
}

/// A member of the tuned channel linked now.
#[derive(uniffi::Record)]
pub struct ChannelPeer {
    pub id: i64,
    /// The name it chose to show; may be empty.
    pub name: String,
}

/// What an emergency exit did with the groups shared with the contact; carry out `actions`.
#[derive(uniffi::Record)]
pub struct EmergencyExit {
    pub removed_from: Vec<String>,
    pub deleted: Vec<String>,
    pub left: Vec<String>,
    pub still_shared: Vec<String>,
    pub actions: Vec<Action>,
}

#[derive(uniffi::Record)]
pub struct ChangedGroup {
    pub group: Group,
    pub actions: Vec<Action>,
}

impl ChangedGroup {
    fn new(group: stored_groups::GroupSummary, actions: Vec<Action>) -> Self {
        Self {
            group: group.into(),
            actions,
        }
    }
}

#[derive(uniffi::Record)]
pub struct SentGroupMessage {
    pub message: GroupMessage,
    pub actions: Vec<Action>,
}

/// What the platform must do after a call; carry them out in order.
#[derive(uniffi::Enum)]
pub enum Action {
    Send {
        connection: u64,
        bytes: Vec<u8>,
    },
    Close {
        connection: u64,
    },
    ShowSas {
        connection: u64,
        emoji: Vec<String>,
    },
    Paired {
        connection: u64,
        contact: Contact,
    },
    /// Someone who typed this device's AirChat ID asks to be added: ask the user, then approve or
    /// decline it.
    ContactRequest {
        connection: u64,
        request: ContactRequest,
    },
    /// A contact proposes a group of the two of you and someone else: ask the user.
    MemberProposed {
        contact_id: i64,
        proposal: MemberProposal,
    },
    /// The contact did not agree to the group this device proposed.
    MemberProposalDeclined {
        contact_id: i64,
    },
    Failed {
        connection: u64,
        reason: Failure,
    },
    LinkUp {
        connection: u64,
        contact_id: i64,
    },
    LinkDown {
        contact_id: i64,
    },
    MessageReceived {
        message: Message,
    },
    /// A message arrived while locked; notify without revealing anything about it.
    MessageArrived {
        contact_id: i64,
    },
    MessageUpdated {
        message: Message,
    },
    /// Something waits to be sent to the contact, whose link runs over Bluetooth: offer to move it
    /// to Wi-Fi (`request_move`).
    WaitingForWifi {
        contact_id: i64,
    },
    /// The contact asks for `target` so the link can move there: answer with `offer_hotspot` or
    /// `decline_move`.
    MoveRequested {
        contact_id: i64,
        target: MoveTarget,
    },
    /// Join this hotspot, connect to its gateway at `offer.port` and call `connect_contact` there.
    HotspotOffered {
        contact_id: i64,
        offer: HotspotOffer,
    },
    MoveDeclined {
        contact_id: i64,
        target: MoveTarget,
    },
    /// A contact calls: ring, then `answer_call` or `end_call`. Show no name while locked. A video
    /// call rings as one.
    CallRinging {
        id: Vec<u8>,
        contact_id: i64,
        video: bool,
    },
    /// This device's call rings on the contact's device.
    CallReached {
        id: Vec<u8>,
    },
    /// The contact answered: start sending and playing audio.
    CallAccepted {
        id: Vec<u8>,
    },
    CallEnded {
        id: Vec<u8>,
        reason: EndReason,
    },
    /// A contact talks (push-to-talk): play its audio at once.
    TalkStarted {
        id: Vec<u8>,
        contact_id: i64,
    },
    TalkEnded {
        id: Vec<u8>,
        reason: EndReason,
    },
    /// A packet of a call's or talk's audio from contact `from`: into that stream's jitter buffer
    /// for that sender (a group call has one per participant, mixed).
    Audio {
        stream: Vec<u8>,
        from: i64,
        seq: u32,
        packet: Vec<u8>,
    },
    /// The camera of `from` in call `id` went on, off or paused: the contact's in a 1:1 call, a
    /// participant's (by its row) in a group call.
    VideoStateChanged {
        id: Vec<u8>,
        from: i64,
        state: VideoState,
    },
    /// A frame of `from`'s video, for its decoder: H.264, Annex B; a key frame carries SPS and PPS.
    /// Show it turned `rotation` quarter turns clockwise. A group call has one stream per participant.
    Video {
        stream: Vec<u8>,
        from: i64,
        key: bool,
        rotation: u8,
        width: u16,
        height: u16,
        frame: Vec<u8>,
    },
    /// The contact cannot decode this device's video: make the next frame a key frame.
    KeyFrameRequested {
        id: Vec<u8>,
    },
    /// A member talks to a group (push-to-talk): play its audio at once.
    GroupTalkStarted {
        id: Vec<u8>,
        group_id: i64,
        contact_id: i64,
    },
    /// A member called a group: ring; join with `join_group_call`, decline with `end_call`.
    /// `CallEnded` ends it.
    GroupCallRinging {
        id: Vec<u8>,
        group_id: i64,
        contact_id: i64,
    },
    /// Who else is in the group call this device is in (contacts or fellow members).
    GroupCallChanged {
        id: Vec<u8>,
        contact_ids: Vec<i64>,
    },
    /// A member of the tuned walkie-talkie channel talks: play it at once. `contact_id` is the
    /// member's id in `channel_peers`.
    ChannelTalkStarted {
        id: Vec<u8>,
        channel_id: i64,
        contact_id: i64,
    },
    /// Members of the tuned channel came or went; read them with `channel_peers`.
    ChannelPeersChanged,
    /// Sign `message` with the attested key and pass the signature to
    /// [`Account::send_attestation`] for `contact_id` (rust/airchat-protocol/docs/protocol.md §6.10).
    AttestationWanted {
        contact_id: i64,
        message: Vec<u8>,
    },
    /// Whether a contact's build is verified changed: read the contacts again.
    AttestationChanged {
        contact_id: i64,
    },
    /// A group was created or changed members, or this device left it or was removed.
    GroupChanged {
        group: Group,
    },
    GroupMessageReceived {
        message: GroupMessage,
    },
    /// A group message arrived while locked; notify without revealing anything about it (unless
    /// its group, if known, is muted).
    GroupMessageArrived {
        group_id: Option<i64>,
    },
    /// An outgoing group message reached a member.
    GroupMessageUpdated {
        message: GroupMessage,
    },
    /// No path to the contact that carries `path_class` was found (`find_path`).
    PathFailed {
        contact_id: i64,
        path_class: PathClass,
    },
}

/// Why a call or talk ended.
#[derive(uniffi::Enum, Clone, Copy, Debug)]
pub enum EndReason {
    HungUp,
    Declined,
    Busy,
    /// The contact does not take calls (or instant voice) from this user.
    NotAllowed,
    NoAnswer,
    /// The link was gone for too long.
    Lost,
    /// Both talked at once and the other went first.
    Interrupted,
}

impl From<chat::EndReason> for EndReason {
    fn from(reason: chat::EndReason) -> Self {
        match reason {
            chat::EndReason::HungUp => Self::HungUp,
            chat::EndReason::Declined => Self::Declined,
            chat::EndReason::Busy => Self::Busy,
            chat::EndReason::NotAllowed => Self::NotAllowed,
            chat::EndReason::NoAnswer => Self::NoAnswer,
            chat::EndReason::Lost => Self::Lost,
            chat::EndReason::Interrupted => Self::Interrupted,
        }
    }
}

/// What a camera does in a call.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoState {
    Off,
    On,
    /// On, but nothing is sent: the link is too slow, or the camera cannot be used now.
    Paused,
}

impl From<chat::VideoState> for VideoState {
    fn from(state: chat::VideoState) -> Self {
        match state {
            chat::VideoState::Off => Self::Off,
            chat::VideoState::On => Self::On,
            chat::VideoState::Paused => Self::Paused,
        }
    }
}

impl From<VideoState> for chat::VideoState {
    fn from(state: VideoState) -> Self {
        match state {
            VideoState::Off => Self::Off,
            VideoState::On => Self::On,
            VideoState::Paused => Self::Paused,
        }
    }
}

/// What a path through Air Providers carries (rust/airchat-protocol/docs/protocol.md §12.1).
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    /// Messages, calls and push-to-talk.
    Voice,
    /// As voice, and video.
    Video,
    /// Messages and files.
    Files,
}

impl From<Class> for PathClass {
    fn from(class: Class) -> Self {
        match class {
            Class::Voice => Self::Voice,
            Class::Video => Self::Video,
            Class::Files => Self::Files,
        }
    }
}

/// A link's path through Air Providers.
#[derive(uniffi::Record)]
pub struct LinkPath {
    pub path_class: PathClass,
    /// How many providers it runs through.
    pub providers: u8,
}

impl From<PathClass> for Class {
    fn from(class: PathClass) -> Self {
        match class {
            PathClass::Voice => Self::Voice,
            PathClass::Video => Self::Video,
            PathClass::Files => Self::Files,
        }
    }
}

/// Connections of links over paths start here; the core carries them itself, so the platform
/// never opens or closes one. Its own connection ids stay below.
#[uniffi::export]
pub fn path_connection_base() -> u64 {
    node::PATH_CONNECTION_BASE
}

/// A call or talk just started: its id, and what to carry out.
#[derive(uniffi::Record)]
pub struct Started {
    pub id: Vec<u8>,
    pub actions: Vec<Action>,
}

/// Puts incoming audio packets back in order and paces them; one per call or talk.
#[derive(uniffi::Object)]
pub struct JitterBuffer(Mutex<jitter::JitterBuffer>);

#[derive(uniffi::Enum)]
pub enum Playout {
    /// Decode and play this packet.
    Packet { data: Vec<u8> },
    /// A packet is lost or late: conceal the gap.
    Missing,
    /// Nothing to play: play silence.
    Silence,
}

#[uniffi::export]
impl JitterBuffer {
    /// Holds `target` packets before playing; beyond `max`, drops the oldest.
    #[uniffi::constructor]
    pub fn new(target: u32, max: u32) -> Arc<Self> {
        Arc::new(Self(Mutex::new(jitter::JitterBuffer::new(
            target as usize,
            max as usize,
        ))))
    }

    pub fn push(&self, seq: u32, packet: Vec<u8>) {
        if let Ok(mut buffer) = self.0.lock() {
            buffer.push(seq, Zeroizing::new(packet));
        }
    }

    /// What to play for the next 20 ms frame.
    pub fn pop(&self) -> Playout {
        match self.0.lock().map(|mut buffer| buffer.pop()) {
            Ok(jitter::Playout::Packet(packet)) => Playout::Packet { data: packet.to_vec() },
            Ok(jitter::Playout::Missing) => Playout::Missing,
            _ => Playout::Silence,
        }
    }
}

/// Where a link can be moved on request.
#[derive(uniffi::Enum, Clone, Copy)]
pub enum MoveTarget {
    Hotspot,
}

impl From<CoreMoveTarget> for MoveTarget {
    fn from(target: CoreMoveTarget) -> Self {
        match target {
            CoreMoveTarget::Hotspot => Self::Hotspot,
        }
    }
}

impl From<MoveTarget> for CoreMoveTarget {
    fn from(target: MoveTarget) -> Self {
        match target {
            MoveTarget::Hotspot => Self::Hotspot,
        }
    }
}

#[derive(uniffi::Record)]
pub struct HotspotOffer {
    pub ssid: String,
    pub passphrase: String,
    pub port: u16,
}

impl From<CoreHotspotOffer> for HotspotOffer {
    fn from(offer: CoreHotspotOffer) -> Self {
        Self {
            ssid: offer.ssid,
            passphrase: offer.passphrase,
            port: offer.port,
        }
    }
}

impl From<node::Action> for Action {
    fn from(action: node::Action) -> Self {
        match action {
            node::Action::Send { connection, bytes } => Self::Send { connection, bytes },
            node::Action::Close { connection } => Self::Close { connection },
            node::Action::ShowSas { connection, sas } => Self::ShowSas {
                connection,
                emoji: sas.emoji().iter().map(|e| (*e).to_owned()).collect(),
            },
            node::Action::Paired { connection, contact } => Self::Paired {
                connection,
                contact: contact.into(),
            },
            node::Action::ContactRequest { connection, request } => Self::ContactRequest {
                connection,
                request: request.into(),
            },
            node::Action::MemberProposed { contact, proposal } => Self::MemberProposed {
                contact_id: contact,
                proposal: MemberProposal {
                    id: proposal.id.to_vec(),
                    person_airchat_id: proposal.person.airchat_id().to_string(),
                    person_name: proposal.person_name,
                    group_name: proposal.group_name,
                    expires: proposal.expires,
                },
            },
            node::Action::MemberProposalDeclined { contact } => Self::MemberProposalDeclined { contact_id: contact },
            node::Action::LinkUp { connection, contact } => Self::LinkUp {
                connection,
                contact_id: contact,
            },
            node::Action::LinkDown { contact } => Self::LinkDown { contact_id: contact },
            node::Action::MessageReceived { message } => Self::MessageReceived {
                message: message.into(),
            },
            node::Action::MessageArrived { contact } => Self::MessageArrived { contact_id: contact },
            node::Action::MessageUpdated { message } => Self::MessageUpdated {
                message: message.into(),
            },
            node::Action::Failed { connection, reason } => Self::Failed {
                connection,
                reason: match reason {
                    node::Failure::Rejected => Failure::Rejected,
                    node::Failure::AuthenticationFailed => Failure::AuthenticationFailed,
                    node::Failure::InvalidInvite => Failure::InvalidInvite,
                    node::Failure::NotAccepting => Failure::NotAccepting,
                    node::Failure::ConnectionLost => Failure::ConnectionLost,
                    node::Failure::Blocked => Failure::Blocked,
                    node::Failure::Protocol => Failure::Protocol,
                },
            },
            node::Action::WaitingForWifi { contact } => Self::WaitingForWifi { contact_id: contact },
            node::Action::MoveRequested { contact, target } => Self::MoveRequested {
                contact_id: contact,
                target: target.into(),
            },
            node::Action::HotspotOffered { contact, offer } => Self::HotspotOffered {
                contact_id: contact,
                offer: offer.into(),
            },
            node::Action::MoveDeclined { contact, target } => Self::MoveDeclined {
                contact_id: contact,
                target: target.into(),
            },
            node::Action::CallRinging { id, contact, video } => Self::CallRinging {
                id: id.to_vec(),
                contact_id: contact,
                video,
            },
            node::Action::VideoStateChanged { id, from, state } => Self::VideoStateChanged {
                id: id.to_vec(),
                from,
                state: state.into(),
            },
            node::Action::Video {
                stream,
                from,
                key,
                rotation,
                width,
                height,
                frame,
            } => Self::Video {
                stream: stream.to_vec(),
                from,
                key,
                rotation,
                width,
                height,
                frame: frame.to_vec(),
            },
            node::Action::KeyFrameRequested { id } => Self::KeyFrameRequested { id: id.to_vec() },
            node::Action::CallReached { id } => Self::CallReached { id: id.to_vec() },
            node::Action::CallAccepted { id } => Self::CallAccepted { id: id.to_vec() },
            node::Action::CallEnded { id, reason } => Self::CallEnded {
                id: id.to_vec(),
                reason: reason.into(),
            },
            node::Action::TalkStarted { id, contact } => Self::TalkStarted {
                id: id.to_vec(),
                contact_id: contact,
            },
            node::Action::TalkEnded { id, reason } => Self::TalkEnded {
                id: id.to_vec(),
                reason: reason.into(),
            },
            node::Action::Audio {
                stream,
                from,
                seq,
                packet,
            } => Self::Audio {
                stream: stream.to_vec(),
                from,
                seq,
                packet: packet.to_vec(),
            },
            node::Action::GroupTalkStarted { id, group, contact } => Self::GroupTalkStarted {
                id: id.to_vec(),
                group_id: group,
                contact_id: contact,
            },
            node::Action::GroupCallRinging { id, group, contact } => Self::GroupCallRinging {
                id: id.to_vec(),
                group_id: group,
                contact_id: contact,
            },
            node::Action::GroupCallChanged { id, participants } => Self::GroupCallChanged {
                id: id.to_vec(),
                contact_ids: participants,
            },
            node::Action::ChannelTalkStarted { id, channel, contact } => Self::ChannelTalkStarted {
                id: id.to_vec(),
                channel_id: channel,
                contact_id: contact,
            },
            node::Action::ChannelPeersChanged => Self::ChannelPeersChanged,
            node::Action::AttestationWanted { contact, message } => Self::AttestationWanted {
                contact_id: contact,
                message,
            },
            node::Action::AttestationChanged { contact } => Self::AttestationChanged { contact_id: contact },
            node::Action::GroupChanged { group } => Self::GroupChanged { group: group.into() },
            node::Action::GroupMessageReceived { message } => Self::GroupMessageReceived {
                message: message.into(),
            },
            node::Action::GroupMessageUpdated { message } => Self::GroupMessageUpdated {
                message: message.into(),
            },
            node::Action::GroupMessageArrived { group } => Self::GroupMessageArrived { group_id: group },
            node::Action::PathFailed { contact, class } => Self::PathFailed {
                contact_id: contact,
                path_class: class.into(),
            },
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
