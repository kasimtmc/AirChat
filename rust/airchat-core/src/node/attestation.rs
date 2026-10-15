//! Verified builds (rust/airchat-protocol/docs/protocol.md §6.10): this device's Android key attestation goes to each
//! contact it links with, signed for that link; a contact's is verified and its result kept.

use super::{Action, ConnectionState, Node, NodeError, Store};
use crate::{
    attest::{self, Trust},
    chat::ChatMessage,
    storage::ContactId,
};

/// This device's attestation, as the platform made it.
#[derive(Default)]
pub(crate) struct OwnAttestation {
    /// The certificate chain, the attested certificate first; empty without one.
    chain: Vec<Vec<u8>>,
    /// Signing certificates trusted besides the official one (debug builds, testing).
    extra_signers: Vec<[u8; 32]>,
}

impl Node {
    /// The challenge this account's attestation must carry.
    pub fn attestation_challenge(&self) -> Result<[u8; 32], NodeError> {
        Ok(attest::challenge(&self.account()?.identity().public()))
    }

    /// The platform's attestation of this account (its chain, the attested certificate first);
    /// the links up now are asked to sign it.
    pub fn set_attestation(&mut self, chain: Vec<Vec<u8>>) -> Vec<Action> {
        if chain.is_empty() || chain.len() > attest::MAX_CERTS || chain.iter().any(|c| c.len() > attest::MAX_CERT_LEN) {
            return Vec::new();
        }
        self.attestation.chain = chain;
        let linked: Vec<ContactId> = self.links.keys().copied().collect();
        linked.into_iter().filter_map(|c| self.attestation_wanted(c)).collect()
    }

    /// Trusts another signing certificate as an official build's: debug builds trust their own,
    /// to test verified builds between them.
    pub fn trust_signer(&mut self, digest: [u8; 32]) {
        if !self.attestation.extra_signers.contains(&digest) {
            self.attestation.extra_signers.push(digest);
        }
    }

    /// The attested key's signature over `contact`'s link, from the platform: the attestation
    /// goes out on it.
    pub fn send_attestation(&mut self, contact: ContactId, proof: Vec<u8>) -> Vec<Action> {
        let Some(&connection) = self.links.get(&contact) else {
            return Vec::new();
        };
        if self.attestation.chain.is_empty() || self.setup_only.contains(&connection) {
            return Vec::new();
        }
        let record = ChatMessage::BuildAttestation {
            certs: self.attestation.chain.clone(),
            proof,
        };
        self.seal_on(connection, vec![record], false)
    }

    /// When a link to a contact comes up: what the attested key is to sign on it.
    pub(super) fn attestation_wanted(&self, contact: ContactId) -> Option<Action> {
        if self.attestation.chain.is_empty() || !self.is_contact(contact) {
            return None;
        }
        let connection = *self.links.get(&contact)?;
        if self.setup_only.contains(&connection) {
            return None;
        }
        let ConnectionState::Linked { session, .. } = self.connections.get(&connection)? else {
            return None;
        };
        Some(Action::AttestationWanted {
            contact,
            message: attest::proof_message(session.handshake_hash()),
        })
    }

    /// A contact's attestation over the link whose handshake hash is `handshake_hash`: verified,
    /// and the result kept with the contact.
    pub(super) fn take_attestation(
        &mut self,
        contact: ContactId,
        certs: &[Vec<u8>],
        proof: &[u8],
        handshake_hash: &[u8; 32],
    ) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let Ok(Some(summary)) = account.db().contact_summary(contact) else {
            return Vec::new();
        };
        let trust = Trust::google(&self.attestation.extra_signers);
        let attested = attest::verify(certs, &summary.identity, handshake_hash, proof, &trust).ok();
        if summary.attested == attested || account.db().set_attested(contact, attested).is_err() {
            return Vec::new();
        }
        vec![Action::AttestationChanged { contact }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attest::{Attested, SecurityLevel},
        crypto::test_util::{hex, vector_field},
        node::groups::tests::Net,
    };

    const AYSE: usize = 0;
    const BURAK: usize = 1;

    fn chain() -> Vec<Vec<u8>> {
        ["official_leaf", "official_intermediate"]
            .iter()
            .map(|key| hex(&vector_field("attestation", key)))
            .collect()
    }

    #[test]
    fn each_link_asks_for_a_proof_and_carries_the_attestation() {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        net.pair(AYSE, BURAK);
        let (burak, ayse) = (net.contact(AYSE, BURAK), net.contact(BURAK, AYSE));
        assert!(net.node(AYSE).set_attestation(chain()).is_empty(), "nobody linked yet");
        // Burak once saw Ayşe's build verified.
        let seen = Attested {
            level: SecurityLevel::TrustedEnvironment,
            os_patch_level: 202609,
        };
        net.devices[BURAK]
            .node
            .account()
            .unwrap()
            .db()
            .set_attested(ayse, Some(seen))
            .unwrap();

        net.link(AYSE, BURAK);
        let message = net.devices[AYSE]
            .shown
            .iter()
            .find_map(|a| match a {
                Action::AttestationWanted { contact, message } if *contact == burak => Some(message.clone()),
                _ => None,
            })
            .expect("asked to sign the link");
        let hash = {
            let node = &net.devices[AYSE].node;
            let ConnectionState::Linked { session, .. } = &node.connections[&node.links[&burak]] else {
                panic!("linked")
            };
            *session.handshake_hash()
        };
        assert_eq!(message, attest::proof_message(&hash));
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .all(|a| !matches!(a, Action::AttestationWanted { .. }))
        );

        // This chain is under the test root, not Google's: Burak finds it unverified, and says so.
        let actions = net.node(AYSE).send_attestation(burak, vec![0x30, 0x00]);
        assert!(actions.iter().any(|a| matches!(a, Action::Send { .. })));
        net.run(AYSE, actions);
        let contact = net.devices[BURAK]
            .node
            .account()
            .unwrap()
            .db()
            .contact_summary(ayse)
            .unwrap()
            .unwrap();
        assert_eq!(contact.attested, None);
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::AttestationChanged { contact } if *contact == ayse))
        );
    }
}
