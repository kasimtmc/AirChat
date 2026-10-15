//! Domain-separation labels.
//!
//! Every hash, KDF or signature input in the protocol starts with exactly one of these labels, so a
//! value computed for one purpose can never be mistaken for another. All labels live here so their
//! uniqueness is checked in one place. They are part of the wire protocol (docs/protocol.md): never
//! change one without bumping the protocol version.

/// Hash input for deriving an AirChat ID from an identity key (docs/protocol.md §4.2).
pub const AIRCHAT_ID: &[u8] = b"AirChat v1 airchat-id";

/// Hash input for the challenge an Android key attestation of this identity carries (§6.10).
pub const BUILD_ATTEST_CHALLENGE: &[u8] = b"AirChat v1 build-attest-challenge";
/// Signed by the attested key over a link's handshake hash (§6.10).
pub const BUILD_ATTEST_PROOF: &[u8] = b"AirChat v1 build-attest-proof";

/// Protocol name of the contact link handshake; the initial transcript hash (docs/protocol.md §6.3).
pub const LINK_CONTACT: &[u8] = b"AirChat v1 link-contact";
/// Key for the recognition tags one contact puts on links it opens to another (§6.2).
pub const LINK_TAG_KEY: &[u8] = b"AirChat v1 link-tag-key";
/// MAC input for a recognition tag (§6.2).
pub const LINK_TAG_MAC: &[u8] = b"AirChat v1 link-tag-mac";
/// Derives the next record key of a link session (§6.4).
pub const LINK_REKEY: &[u8] = b"AirChat v1 link-rekey";
/// The link key that follows a contact link handshake (§6.8).
pub const LINK_KEY_NEXT: &[u8] = b"AirChat v1 link-key-next";

/// Protocol name of pairing; the initial transcript hash (docs/protocol.md §4.3).
pub const PAIRING_PROTOCOL: &[u8] = b"AirChat v1 pairing-protocol";
/// Derives the public identifier of a QR invite from its secret (§4.4).
pub const PAIRING_INVITE_ID: &[u8] = b"AirChat v1 pairing-invite-id";
/// Derives the pre-shared key of a QR invite from its secret (§4.4).
pub const PAIRING_INVITE_PSK: &[u8] = b"AirChat v1 pairing-invite-psk";
/// Commitment to the responder's Nearby Pairing nonce (§4.5).
pub const PAIRING_COMMIT: &[u8] = b"AirChat v1 pairing-commit";
/// Derives the emoji sequence of Nearby Pairing (§4.5).
pub const PAIRING_SAS: &[u8] = b"AirChat v1 pairing-sas";
/// Derives the contacts' link pre-shared key at the end of pairing (§4.3).
pub const PAIRING_LINK_PSK: &[u8] = b"AirChat v1 pairing-link-psk";
/// Signature proving possession of an identity key in one pairing session (§4.6).
pub const PAIRING_PROOF: &[u8] = b"AirChat v1 pairing-proof";
/// Signature binding a static KEM key to an identity key (§4.6).
pub const CONTACT_CARD: &[u8] = b"AirChat v1 contact-card";
/// Signature binding a newer static KEM key and its version to an identity key (§6.9).
pub const STATIC_KEY: &[u8] = b"AirChat v1 static-key";
/// MAC input for a presence token (§5.2).
pub const PRESENCE_TOKEN: &[u8] = b"AirChat v1 presence-token";
/// Key of the beacons announcing a request to add the owner of an AirChat ID (§4.8).
pub const ID_REQUEST_KEY: &[u8] = b"AirChat v1 id-request-key";
/// MAC input for such a beacon's token.
pub const ID_REQUEST_TOKEN: &[u8] = b"AirChat v1 id-request-token";
/// Pre-shared key of the pairing that answers such a request: whoever knows the ID can derive it.
pub const ID_REQUEST_PSK: &[u8] = b"AirChat v1 id-request-psk";
/// Key of the tags and proofs of a path looked for to the owner of an AirChat ID (§12.2).
pub const ID_REQUEST_PATH_KEY: &[u8] = b"AirChat v1 id-request-path-key";

/// Key that seals a group's epoch key for one member (docs/protocol.md §9.2).
pub const GROUP_ENVELOPE: &[u8] = b"AirChat v1 group-envelope";
/// Key that seals a group's roster for an epoch (§9.2).
pub const GROUP_ROSTER: &[u8] = b"AirChat v1 group-roster";
/// Signature input of a group update (§9.2).
pub const GROUP_UPDATE: &[u8] = b"AirChat v1 group-update";
/// Key of a group's messages for an epoch, and their signature input (§9.3).
pub const GROUP_MESSAGE: &[u8] = b"AirChat v1 group-message";
/// Link key of two members who are not contacts (§9.4).
pub const GROUP_LINK: &[u8] = b"AirChat v1 group-link";

// Walkie-talkie channels (docs/protocol.md §11).
/// Salt source for a channel key derived from a password.
pub const CHANNEL_PASSWORD: &[u8] = b"AirChat v1 channel-password";
pub const CHANNEL_ID: &[u8] = b"AirChat v1 channel-id";
pub const CHANNEL_PRESENCE: &[u8] = b"AirChat v1 channel-presence";
pub const CHANNEL_TOKEN: &[u8] = b"AirChat v1 channel-token";
pub const CHANNEL_LINK_PSK: &[u8] = b"AirChat v1 channel-link-psk";
pub const CHANNEL_TAG_KEY: &[u8] = b"AirChat v1 channel-tag-key";
/// Key of the tags and proofs of paths to a channel's members (docs/protocol.md §11.5).
pub const CHANNEL_PATH_KEY: &[u8] = b"AirChat v1 channel-path-key";
pub const CHANNEL_CLUSTER: &[u8] = b"AirChat v1 channel-cluster";
/// Protocol name of the channel link handshake.
pub const LINK_CHANNEL: &[u8] = b"AirChat v1 link-channel";

// The mesh (docs/protocol.md §10).
pub const MESH_TAG_KEY: &[u8] = b"AirChat v1 mesh-tag-key";
pub const MESH_GROUP_TAG_KEY: &[u8] = b"AirChat v1 mesh-group-tag-key";
pub const MESH_TAG: &[u8] = b"AirChat v1 mesh-tag";
pub const MESH_SEAL: &[u8] = b"AirChat v1 mesh-seal";
pub const MESH_ENVELOPE: &[u8] = b"AirChat v1 mesh-envelope";
pub const MESH_DROP_SECRET: &[u8] = b"AirChat v1 mesh-drop-secret";
pub const MESH_DROP: &[u8] = b"AirChat v1 mesh-drop";
pub const MESH_FILE_PART: &[u8] = b"AirChat v1 mesh-file-part";
pub const MESH_FILE_TAG_KEY: &[u8] = b"AirChat v1 mesh-file-tag-key";
pub const MESH_UPDATE_TAG_KEY: &[u8] = b"AirChat v1 mesh-update-tag-key";
pub const MESH_UPDATE_KEY: &[u8] = b"AirChat v1 mesh-update-key";
pub const MESH_UPDATE_PART_KEY: &[u8] = b"AirChat v1 mesh-update-part-key";
pub const MESH_UPDATE_PART: &[u8] = b"AirChat v1 mesh-update-part";
pub const MESH_GROUP_FILE_TAG_KEY: &[u8] = b"AirChat v1 mesh-group-file-tag-key";
pub const MESH_GROUP_FILE_KEY: &[u8] = b"AirChat v1 mesh-group-file-key";
pub const MESH_GROUP_FILE_PART: &[u8] = b"AirChat v1 mesh-group-file-part";
/// Public "channel" the mesh link handshake runs under (§10.2): hashed into its id and psk.
pub const MESH_ID: &[u8] = b"AirChat v1 mesh-id";
pub const MESH_PSK: &[u8] = b"AirChat v1 mesh-psk";
/// Protocol name of the mesh link handshake.
pub const LINK_MESH: &[u8] = b"AirChat v1 link-mesh";

// Paths through Air Providers (docs/protocol.md §12).
pub const PATH_TAG: &[u8] = b"AirChat v1 path-tag";
pub const PATH_ANSWER: &[u8] = b"AirChat v1 path-answer";

// Local storage only; never sent to other devices.

/// Key that unwraps the master key, derived from the PIN's Argon2id output.
pub const VAULT_PIN_KEK: &[u8] = b"AirChat v1 vault pin-kek";
/// Key that unwraps the master key, derived from the biometric-protected unlock secret.
pub const VAULT_SECRET_KEK: &[u8] = b"AirChat v1 vault secret-kek";
/// Raw SQLCipher key for the database, derived from the master key.
pub const STORAGE_DATABASE_KEY: &[u8] = b"AirChat v1 storage database-key";
/// Key for attachment files at rest, derived from the master key.
pub const STORAGE_FILE_KEY: &[u8] = b"AirChat v1 storage file-key";
/// Associated data of one chunk of an attachment file at rest.
pub const STORAGE_FILE_CHUNK: &[u8] = b"AirChat v1 storage file-chunk";
/// Key of one entry in the locked-mode inbox, derived from its X-Wing shared secret.
pub const INBOX_ENTRY: &[u8] = b"AirChat v1 inbox-entry";

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[&[u8]] = &[
        AIRCHAT_ID,
        LINK_CONTACT,
        LINK_TAG_KEY,
        LINK_TAG_MAC,
        LINK_REKEY,
        LINK_KEY_NEXT,
        PAIRING_PROTOCOL,
        PAIRING_INVITE_ID,
        PAIRING_INVITE_PSK,
        PAIRING_COMMIT,
        PAIRING_SAS,
        PAIRING_LINK_PSK,
        PAIRING_PROOF,
        CONTACT_CARD,
        STATIC_KEY,
        PRESENCE_TOKEN,
        ID_REQUEST_KEY,
        ID_REQUEST_TOKEN,
        ID_REQUEST_PSK,
        ID_REQUEST_PATH_KEY,
        GROUP_ENVELOPE,
        GROUP_ROSTER,
        GROUP_UPDATE,
        GROUP_MESSAGE,
        GROUP_LINK,
        VAULT_PIN_KEK,
        VAULT_SECRET_KEK,
        STORAGE_DATABASE_KEY,
        STORAGE_FILE_KEY,
        STORAGE_FILE_CHUNK,
        INBOX_ENTRY,
        BUILD_ATTEST_CHALLENGE,
        BUILD_ATTEST_PROOF,
    ];

    #[test]
    fn labels_are_distinct_and_prefix_free() {
        for (i, a) in ALL.iter().enumerate() {
            assert!(a.starts_with(b"AirChat v1 "), "missing version prefix");
            for b in &ALL[i + 1..] {
                assert!(
                    !a.starts_with(b) && !b.starts_with(a),
                    "labels must not prefix each other"
                );
            }
        }
    }
}
