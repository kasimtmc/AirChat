//! Recognition tags (docs/protocol.md §6.2).
//!
//! The first bytes of a link are a tag that only the intended contact can recognise. It tells the
//! responder which contact is calling without either identity ever appearing on the air, and lets
//! the responder drop strangers before doing any public-key work. Every attempt carries a fresh
//! random nonce, so observers cannot link two connections, and the responder accepts each nonce once.

use std::collections::HashMap;

use super::LinkError;
use crate::{
    crypto::{
        SecretBytes,
        hash::{equal_in_constant_time, hmac_sha256},
        kdf,
    },
    identity::PublicIdentity,
    labels,
};

pub const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 16;
pub const TAG_LEN: usize = NONCE_LEN + MAC_LEN;
/// Tags are bound to hour-long epochs of Unix time.
pub const EPOCH_SECS: u64 = 3600;

pub type Nonce = [u8; NONCE_LEN];
pub type Tag = [u8; TAG_LEN];

pub fn epoch_at(unix_secs: u64) -> u64 {
    unix_secs / EPOCH_SECS
}

/// Key for the tags `sender` puts on links it opens to `receiver`.
pub struct TagKey(SecretBytes<32>);

impl TagKey {
    pub fn derive(
        link_psk: &SecretBytes<32>,
        sender: &PublicIdentity,
        receiver: &PublicIdentity,
    ) -> Result<Self, LinkError> {
        let info = [labels::LINK_TAG_KEY, sender.as_bytes(), receiver.as_bytes()].concat();
        Ok(Self(kdf::derive(&[], link_psk.expose(), &info)?))
    }

    /// Key for the tags on links between members of a walkie-talkie channel (§11): the same for
    /// every member and both directions.
    pub fn for_channel(link_psk: &SecretBytes<32>, channel_id: &[u8]) -> Result<Self, LinkError> {
        let info = [labels::CHANNEL_TAG_KEY, channel_id].concat();
        Ok(Self(kdf::derive(&[], link_psk.expose(), &info)?))
    }

    /// `nonce || MAC(epoch || nonce)`; the nonce must be fresh and random for every attempt.
    pub fn tag(&self, epoch: u64, nonce: &Nonce) -> Tag {
        let mut tag = [0; TAG_LEN];
        tag[..NONCE_LEN].copy_from_slice(nonce);
        tag[NONCE_LEN..].copy_from_slice(&self.mac(epoch, nonce));
        tag
    }

    fn mac(&self, epoch: u64, nonce: &[u8]) -> [u8; MAC_LEN] {
        let mac = hmac_sha256(self.0.expose(), &[labels::LINK_TAG_MAC, &epoch.to_be_bytes(), nonce]);
        mac.expose()[..MAC_LEN]
            .try_into()
            .expect("MAC is longer than its truncation")
    }

    fn made(&self, epoch: u64, tag: &Tag) -> bool {
        let (nonce, mac) = tag.split_at(NONCE_LEN);
        equal_in_constant_time(&self.mac(epoch, nonce), mac)
    }
}

/// The responder's side: finds the contact whose key made a tag, for the current epoch or its two
/// neighbours (clock skew), and accepts each nonce once.
#[derive(Default)]
pub struct TagChecker {
    /// Nonces accepted so far, with the epoch they were made for.
    used: HashMap<Nonce, u64>,
    /// The epoch `used` was last pruned for: pruning walks every nonce, so it runs once an epoch,
    /// not on every attempt, which anyone who can make tags (a channel's members) could repeat.
    pruned: u64,
}

impl TagChecker {
    /// The contact behind `tag`, unless no contact made it in the window or it was used before.
    /// Costs three MACs per contact; strangers cost no public-key work.
    pub fn claim<'a, C: Copy + 'a>(
        &mut self,
        tag: &Tag,
        epoch: u64,
        contacts: impl IntoIterator<Item = &'a (C, TagKey)>,
    ) -> Option<C> {
        // A nonce of an epoch that left the window can no longer verify, so it need not be kept.
        if epoch != self.pruned {
            self.used.retain(|_, made_in| made_in.saturating_add(1) >= epoch);
            self.pruned = epoch;
        }
        let nonce: Nonce = tag[..NONCE_LEN].try_into().expect("tag starts with its nonce");
        if self.used.contains_key(&nonce) {
            return None;
        }
        for (contact, key) in contacts {
            for e in epoch.saturating_sub(1)..=epoch.saturating_add(1) {
                if key.made(e, tag) {
                    self.used.insert(nonce, e);
                    return Some(*contact);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn key(sender: &PublicIdentity, receiver: &PublicIdentity) -> TagKey {
        TagKey::derive(&SecretBytes::from_slice(&[7; 32]).unwrap(), sender, receiver).unwrap()
    }

    #[test]
    fn tags_depend_on_direction_epoch_and_nonce() {
        let a = Identity::generate().unwrap().public();
        let b = Identity::generate().unwrap().public();
        let ab = key(&a, &b);
        let ba = key(&b, &a);
        assert_ne!(ab.tag(5, &[0; 16]), ba.tag(5, &[0; 16]));
        assert_ne!(ab.tag(5, &[0; 16]), ab.tag(6, &[0; 16]));
        assert_ne!(ab.tag(5, &[0; 16]), ab.tag(5, &[1; 16]));
        assert_eq!(ab.tag(5, &[0; 16]), key(&a, &b).tag(5, &[0; 16]));
        assert_eq!(ab.tag(5, &[9; 16])[..NONCE_LEN], [9; 16], "the nonce travels in clear");
    }

    #[test]
    fn checker_recognises_each_tag_once_within_the_skew_window() {
        let a = Identity::generate().unwrap().public();
        let b = Identity::generate().unwrap().public();
        let c = Identity::generate().unwrap().public();
        let contacts = [("carol", key(&c, &b)), ("alice", key(&a, &b))];
        let ab = &contacts[1].1;
        let mut checker = TagChecker::default();

        assert_eq!(checker.claim(&ab.tag(100, &[3; 16]), 100, &contacts), Some("alice"));
        assert_eq!(checker.claim(&ab.tag(100, &[3; 16]), 100, &contacts), None, "replay");
        assert_eq!(
            checker.claim(&ab.tag(99, &[4; 16]), 100, &contacts),
            Some("alice"),
            "slow clock"
        );
        assert_eq!(
            checker.claim(&ab.tag(101, &[5; 16]), 100, &contacts),
            Some("alice"),
            "fast clock"
        );
        assert_eq!(
            checker.claim(&ab.tag(102, &[6; 16]), 100, &contacts),
            None,
            "too far ahead"
        );
        assert_eq!(checker.claim(&ab.tag(98, &[7; 16]), 100, &contacts), None, "too old");
        assert_eq!(
            checker.claim(&key(&b, &a).tag(100, &[8; 16]), 100, &contacts),
            None,
            "wrong direction"
        );
        let mut forged = ab.tag(100, &[9; 16]);
        forged[TAG_LEN - 1] ^= 1;
        assert_eq!(checker.claim(&forged, 100, &contacts), None, "forged MAC");
    }

    #[test]
    fn any_number_of_attempts_per_epoch_is_accepted() {
        let a = Identity::generate().unwrap().public();
        let b = Identity::generate().unwrap().public();
        let contacts = [(1, key(&a, &b))];
        let mut checker = TagChecker::default();
        for n in 0..=u8::MAX {
            assert_eq!(
                checker.claim(&contacts[0].1.tag(100, &[n; 16]), 100, &contacts),
                Some(1)
            );
        }
    }

    #[test]
    fn used_nonces_are_forgotten_once_their_epoch_cannot_verify() {
        let a = Identity::generate().unwrap().public();
        let b = Identity::generate().unwrap().public();
        let contacts = [(1, key(&a, &b))];
        let ab = &contacts[0].1;
        let mut checker = TagChecker::default();
        assert!(checker.claim(&ab.tag(101, &[1; 16]), 100, &contacts).is_some());
        assert_eq!(
            checker.claim(&ab.tag(101, &[1; 16]), 102, &contacts),
            None,
            "still replay-protected"
        );
        assert_eq!(
            checker.claim(&ab.tag(101, &[2; 16]), 103, &contacts),
            None,
            "out of the window"
        );
        assert!(checker.used.is_empty());
    }

    #[test]
    fn used_nonces_are_pruned_once_an_epoch() {
        let a = Identity::generate().unwrap().public();
        let b = Identity::generate().unwrap().public();
        let contacts = [(1, key(&a, &b))];
        let ab = &contacts[0].1;
        let mut checker = TagChecker::default();
        assert!(checker.claim(&ab.tag(100, &[1; 16]), 100, &contacts).is_some());
        assert_eq!(checker.pruned, 100);
        // Planted after the pruning of epoch 100: stays for the rest of it, goes with the next.
        checker.used.insert([9; 16], 10);
        assert!(checker.claim(&ab.tag(100, &[2; 16]), 100, &contacts).is_some());
        assert!(checker.used.contains_key(&[9; 16]));
        assert!(checker.claim(&ab.tag(101, &[3; 16]), 101, &contacts).is_some());
        assert!(!checker.used.contains_key(&[9; 16]));
        assert_eq!(checker.used.len(), 3);
    }
}
