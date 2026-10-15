//! The emergency exit from a contact (docs/threat-model.md, A5): everything this device can do on
//! its own to cut a contact off, whatever that contact's device does. What was sent to them stays
//! with them; nothing here reaches into their device.

use super::{Action, Node, NodeError};
use crate::storage::{
    ContactId, ContactState,
    groups::{GroupSummary, Membership},
};

/// What an emergency exit did with the groups shared with the contact.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EmergencyExit {
    /// Groups this device administers that the contact was removed from (a new key each).
    pub removed_from: Vec<String>,
    /// Groups of two with the contact, deleted for both.
    pub deleted: Vec<String>,
    /// Groups this device left, not being an admin there.
    pub left: Vec<String>,
    /// Groups still shared, not being an admin there and not asked to leave.
    pub still_shared: Vec<String>,
}

impl Node {
    /// The groups this device is in with `contact`, as the exit would treat them.
    pub fn groups_shared_with(&self, contact: ContactId) -> Result<Vec<GroupSummary>, NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        let identity = account
            .db()
            .contact_summary(contact)?
            .ok_or(NodeError::UnknownContact)?
            .identity;
        Ok(account
            .db()
            .member_groups()?
            .iter()
            .filter(|g| g.roster.member(&identity).is_some())
            .map(|g| g.summary(&me))
            .collect())
    }

    /// Cuts `contact` off: blocks them (their links end and fail from now on, and this device's
    /// presence key changes, so they no longer see it nearby), deletes the conversation's messages
    /// and files here, removes them from the groups this device administers (deleting a group of
    /// two), and with `leave_groups` leaves the other groups shared with them.
    pub fn emergency_exit(
        &mut self,
        contact: ContactId,
        leave_groups: bool,
    ) -> Result<(EmergencyExit, Vec<Action>), NodeError> {
        let account = self.account()?;
        let summary = account
            .db()
            .contact_summary(contact)?
            .filter(|c| matches!(c.state, ContactState::Active | ContactState::Blocked))
            .ok_or(NodeError::UnknownContact)?;
        let shared = self.groups_shared_with(contact)?;
        let mut exit = EmergencyExit::default();
        let mut actions = Vec::new();
        // Groups first, while the contact's keys still seal their removal to them.
        for group in shared {
            if group.membership != Membership::Member {
                continue;
            }
            if group.admin && group.members > 2 {
                actions.extend(self.remove_group_member(group.row, &summary.identity)?.1);
                exit.removed_from.push(group.name);
            } else if group.admin {
                actions.extend(self.delete_group_for_everyone(group.row)?.1);
                exit.deleted.push(group.name);
            } else if leave_groups {
                actions.extend(self.leave_group(group.row)?.1);
                exit.left.push(group.name);
            } else {
                exit.still_shared.push(group.name);
            }
        }
        if summary.state != ContactState::Blocked {
            actions.extend(self.block_contact(contact)?);
        }
        self.imports.retain(|_, import| import.contact != contact);
        self.downloads.retain(|_, download| download.contact != contact);
        self.account()?.delete_history(contact)?;
        Ok((exit, actions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::groups::tests::Net;

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Ayşe, contact of Burak and Cem, makes "Kamp" of the three and "İkimiz" with Burak; Burak
    /// writes to her.
    fn net() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let (burak, cem) = (net.contact(AYSE, BURAK), net.contact(AYSE, CEM));
        let (_, actions) = net.node(AYSE).create_group("Kamp", &[burak, cem]).unwrap();
        net.run(AYSE, actions);
        let (_, actions) = net.node(AYSE).create_group("İkimiz", &[burak]).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        let ayse = net.contact(BURAK, AYSE);
        let (_, actions) = net.node(BURAK).send_message(ayse, "merhaba").unwrap();
        net.run(BURAK, actions);
        net
    }

    fn groups(net: &Net, at: usize) -> Vec<(String, u32, Membership)> {
        let mut groups: Vec<_> = net.devices[at]
            .node
            .groups()
            .unwrap()
            .into_iter()
            .map(|g| (g.name, g.members, g.membership))
            .collect();
        groups.sort_by(|a, b| a.0.cmp(&b.0));
        groups
    }

    #[test]
    fn an_admin_cuts_a_contact_off_everywhere() {
        let mut net = net();
        let burak = net.contact(AYSE, BURAK);
        assert_eq!(net.devices[AYSE].node.messages(burak).unwrap().len(), 1);
        assert_eq!(net.devices[AYSE].node.groups_shared_with(burak).unwrap().len(), 2);
        let (exit, actions) = net.node(AYSE).emergency_exit(burak, false).unwrap();
        net.run(AYSE, actions);
        assert_eq!(exit.removed_from, ["Kamp"]);
        assert_eq!(exit.deleted, ["İkimiz"]);
        assert!(exit.left.is_empty() && exit.still_shared.is_empty());
        // Blocked, the conversation gone, the link down.
        let node = &net.devices[AYSE].node;
        assert!(node.messages(burak).unwrap().is_empty());
        let contact = node.account().unwrap().db().contact_summary(burak).unwrap().unwrap();
        assert_eq!(contact.state, ContactState::Blocked);
        assert!(!node.is_linked(burak));
        // Kamp goes on with a new key, without Burak.
        assert_eq!(groups(&net, AYSE), [("Kamp".to_owned(), 2, Membership::Member)]);
        assert!(groups(&net, BURAK).iter().all(|(_, _, m)| *m != Membership::Member));
        assert_eq!(groups(&net, CEM), [("Kamp".to_owned(), 2, Membership::Member)]);
    }

    #[test]
    fn a_member_leaves_what_it_cannot_change_if_asked() {
        let mut net = net();
        let ayse = net.contact(BURAK, AYSE);
        let (exit, actions) = net.node(BURAK).emergency_exit(ayse, false).unwrap();
        net.run(BURAK, actions);
        assert_eq!(exit.still_shared.len(), 2);
        assert!(net.devices[BURAK].node.messages(ayse).unwrap().is_empty());
        // Again, now leaving: the blocked contact stays blocked.
        let (exit, actions) = net.node(BURAK).emergency_exit(ayse, true).unwrap();
        net.run(BURAK, actions);
        let mut left = exit.left.clone();
        left.sort();
        assert_eq!(left, ["Kamp", "İkimiz"]);
        assert!(groups(&net, BURAK).iter().all(|(_, _, m)| *m == Membership::Left));
    }
}
