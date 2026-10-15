//! Adding people to conversations (requirement M-3): a third person to a conversation of two,
//! which the other of the two must agree to (rust/airchat-protocol/docs/protocol.md §9.8), and members of a group added
//! for as long as the group's call lasts.

use std::collections::HashMap;

use super::{Action, Node, NodeError, Store, now_secs};
use crate::{
    chat::ChatMessage,
    crypto::random,
    group::{self, GroupId, Role, Roster},
    identity::PublicIdentity,
    storage::{ContactId, ContactState, groups::GroupSummary},
};

/// A membership "until this call ends" ends after this long at the latest, should the device that
/// added it not be there to end it.
const CALL_MEMBERSHIP_SECS: u64 = 12 * 3600;
/// Proposals made or received are forgotten after this long unanswered.
const PROPOSAL_SECS: u64 = 15 * 60;

/// A proposal to make a group of this device, a contact, and another contact.
struct Proposed {
    with: ContactId,
    person: ContactId,
    group_name: String,
    expires: u64,
    made_at: u64,
}

/// A proposal from a contact to make a group of the two of them and someone else, as the user
/// sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberProposal {
    pub id: [u8; 16],
    /// Whom the contact would add: its name for them, and their identity (for the AirChat ID).
    pub person: PublicIdentity,
    pub person_name: String,
    pub group_name: String,
    /// Unix seconds when the person's membership would end; 0 for a permanent one.
    pub expires: u64,
}

#[derive(Default)]
pub(super) struct Additions {
    /// Proposals this device made, by id.
    proposed: HashMap<[u8; 16], Proposed>,
    /// Proposals made to this device, by id: who made them, and when.
    received: HashMap<[u8; 16], (ContactId, u64)>,
    /// Members this device added to a group for the call it is in, by group.
    for_call: HashMap<GroupId, Vec<PublicIdentity>>,
}

impl Node {
    /// Asks `with`, linked now, to agree to a group of the two of them and `person`, another
    /// contact; once it agrees, this device makes the group, with both of them as its admins.
    pub fn propose_member(
        &mut self,
        with: ContactId,
        person: ContactId,
        group_name: &str,
        expires: u64,
    ) -> Result<Vec<Action>, NodeError> {
        let account = self.account()?;
        let active = |id| {
            account
                .contact(id)
                .ok()
                .flatten()
                .filter(|c| c.state == ContactState::Active)
        };
        let (Some(_), Some(added)) = (active(with), active(person)) else {
            return Err(NodeError::UnknownContact);
        };
        if with == person {
            return Err(NodeError::UnknownContact);
        }
        let group_name = group_name.trim();
        if group_name.is_empty() || group_name.chars().count() > group::MAX_NAME_CHARS {
            return Err(group::GroupError::InvalidName.into());
        }
        let id = random::array()?;
        let record = ChatMessage::MemberProposal {
            id,
            person: added.identity,
            person_name: group::member_name(&added.display_name),
            group_name: group::member_name(group_name),
            expires,
        };
        let actions = self.send_on_link(with, &record)?;
        self.additions.proposed.insert(
            id,
            Proposed {
                with,
                person,
                group_name: group_name.to_owned(),
                expires,
                made_at: now_secs(),
            },
        );
        Ok(actions)
    }

    /// The user answers a contact's proposal.
    pub fn answer_member_proposal(
        &mut self,
        from: ContactId,
        id: [u8; 16],
        agree: bool,
    ) -> Result<Vec<Action>, NodeError> {
        match self.additions.received.remove(&id) {
            Some((contact, _)) if contact == from => {}
            _ => return Err(NodeError::UnknownContact),
        }
        self.send_on_link(from, &ChatMessage::MemberProposalAnswer { id, agree })
    }

    /// A contact proposes a group of the two of them and someone else: the user is asked.
    pub(super) fn member_proposed(&mut self, contact: ContactId, proposal: MemberProposal) -> Vec<Action> {
        if !self.is_contact(contact) || self.additions.received.len() >= 16 {
            return Vec::new();
        }
        self.additions.received.insert(proposal.id, (contact, now_secs()));
        vec![Action::MemberProposed { contact, proposal }]
    }

    /// The contact answered a proposal of this device's: on yes, the group is made.
    pub(super) fn member_proposal_answered(&mut self, contact: ContactId, id: [u8; 16], agree: bool) -> Vec<Action> {
        let Some(proposed) = self.additions.proposed.remove(&id).filter(|p| p.with == contact) else {
            return Vec::new();
        };
        if !agree {
            return vec![Action::MemberProposalDeclined { contact }];
        }
        match self.group_of_three(&proposed) {
            Ok((_, actions)) => actions,
            Err(_) => vec![Action::MemberProposalDeclined { contact }],
        }
    }

    fn group_of_three(&mut self, proposed: &Proposed) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let mut with = self.contact_as_member(proposed.with, 0)?;
        with.role = Role::Admin;
        let members = vec![
            self.me_as_member(Role::Admin, 0)?,
            with,
            self.contact_as_member(proposed.person, proposed.expires)?,
        ];
        let roster = Roster::new(random::array()?, 0, &proposed.group_name, members)?;
        self.start_epoch(roster, &[])
    }

    /// Adds contacts to a group this device administers, for as long as this device is in the
    /// group's call (12 hours at most).
    pub fn add_group_members_for_call(
        &mut self,
        group: i64,
        contacts: &[ContactId],
    ) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let stored = self.administered(group)?;
        if self.media.group_call() != Some((stored.group_id, true)) {
            return Err(NodeError::NotInCall);
        }
        let account = self.account()?;
        let mut added = Vec::new();
        for &contact in contacts {
            let summary = account.contact(contact)?.ok_or(NodeError::UnknownContact)?;
            if stored.roster.member(&summary.identity).is_none() {
                added.push(summary.identity);
            }
        }
        let result = self.add_group_members(group, contacts, now_secs() + CALL_MEMBERSHIP_SECS)?;
        self.additions
            .for_call
            .entry(stored.group_id)
            .or_default()
            .extend(added);
        Ok(result)
    }

    /// Ends the memberships for a call this device is no longer in, and forgets stale proposals.
    pub(super) fn additions_tick(&mut self, now: u64) -> Vec<Action> {
        self.additions
            .proposed
            .retain(|_, p| now.saturating_sub(p.made_at) < PROPOSAL_SECS);
        self.additions
            .received
            .retain(|_, (_, at)| now.saturating_sub(*at) < PROPOSAL_SECS);
        if !matches!(self.store, Store::Open(_)) {
            return Vec::new();
        }
        let in_call = self.media.group_call().filter(|(_, joined)| *joined).map(|(g, _)| g);
        let ended: Vec<GroupId> = self
            .additions
            .for_call
            .keys()
            .filter(|group| Some(**group) != in_call)
            .copied()
            .collect();
        let mut actions = Vec::new();
        for group_id in ended {
            let gone = self.additions.for_call.remove(&group_id).unwrap_or_default();
            let Ok(account) = self.account() else {
                break;
            };
            let Some(stored) = account.db().group_by_id(&group_id).ok().flatten() else {
                continue;
            };
            let still: Vec<PublicIdentity> = gone
                .into_iter()
                .filter(|member| stored.roster.member(member).is_some())
                .collect();
            if still.is_empty() || stored.roster.members().len() - still.len() < group::MIN_MEMBERS {
                continue;
            }
            if let Ok((_, removed)) = self.remove_group_members(stored.row, &still) {
                actions.extend(removed);
            }
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::groups::tests::Net;

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Ayşe, a contact of both Burak and Cem, linked with Burak.
    fn three() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        net.link(AYSE, BURAK);
        net
    }

    fn proposal(net: &Net) -> MemberProposal {
        net.devices[BURAK]
            .shown
            .iter()
            .find_map(|a| match a {
                Action::MemberProposed { proposal, .. } => Some(proposal.clone()),
                _ => None,
            })
            .expect("Burak is asked")
    }

    fn roles(net: &mut Net, at: usize) -> Vec<(String, bool)> {
        let group = net.group(at);
        let mut members: Vec<(String, bool)> = net
            .node(at)
            .group_members(group.row)
            .unwrap()
            .into_iter()
            .map(|m| (m.name, m.admin))
            .collect();
        members.sort();
        members
    }

    #[test]
    fn a_third_person_joins_a_conversation_of_two_once_the_other_agrees() {
        let mut net = three();
        let (burak, cem) = (net.contact(AYSE, BURAK), net.contact(AYSE, CEM));
        let actions = net.node(AYSE).propose_member(burak, cem, "Üçümüz", 0).unwrap();
        net.run(AYSE, actions);
        let asked = proposal(&net);
        assert_eq!(
            (asked.person_name.as_str(), asked.group_name.as_str()),
            ("Cem", "Üçümüz")
        );
        assert_eq!(asked.person, net.identity(CEM));
        assert!(
            net.node(BURAK).groups().unwrap().is_empty(),
            "nothing before Burak agrees"
        );

        let ayse = net.contact(BURAK, AYSE);
        let actions = net.node(BURAK).answer_member_proposal(ayse, asked.id, true).unwrap();
        net.run(BURAK, actions);
        let expected = vec![("Ayşe".into(), true), ("Burak".into(), true), ("Cem".into(), false)];
        assert_eq!(roles(&mut net, AYSE), expected, "both of the two are admins");
        assert_eq!(roles(&mut net, BURAK), expected);
        net.link(AYSE, CEM);
        assert_eq!(net.group(CEM).name, "Üçümüz");
    }

    #[test]
    fn declining_makes_no_group() {
        let mut net = three();
        let (burak, cem) = (net.contact(AYSE, BURAK), net.contact(AYSE, CEM));
        let actions = net.node(AYSE).propose_member(burak, cem, "Üçümüz", 0).unwrap();
        net.run(AYSE, actions);
        let asked = proposal(&net);
        let ayse = net.contact(BURAK, AYSE);
        let actions = net.node(BURAK).answer_member_proposal(ayse, asked.id, false).unwrap();
        net.run(BURAK, actions);
        assert!(
            net.devices[AYSE]
                .shown
                .iter()
                .any(|a| matches!(a, Action::MemberProposalDeclined { contact } if *contact == burak))
        );
        assert!(net.node(AYSE).groups().unwrap().is_empty());
        assert!(
            net.node(BURAK).answer_member_proposal(ayse, asked.id, true).is_err(),
            "answered once"
        );
    }

    #[test]
    fn members_added_for_a_call_leave_when_it_ends() {
        let mut net = three();
        let burak = net.contact(AYSE, BURAK);
        let (group, actions) = net.node(AYSE).create_group("Kamp", &[burak]).unwrap();
        net.run(AYSE, actions);
        let cem = net.contact(AYSE, CEM);
        assert!(matches!(
            net.node(AYSE).add_group_members_for_call(group.row, &[cem]),
            Err(NodeError::NotInCall)
        ));
        let (call, actions) = net.node(AYSE).start_group_call(group.row).unwrap();
        net.run(AYSE, actions);
        let (_, actions) = net.node(AYSE).add_group_members_for_call(group.row, &[cem]).unwrap();
        net.run(AYSE, actions);
        let names = |net: &mut Net| -> Vec<String> {
            let mut names: Vec<String> = net
                .node(AYSE)
                .group_members(group.row)
                .unwrap()
                .into_iter()
                .map(|m| m.name)
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(&mut net), ["Ayşe", "Burak", "Cem"]);
        let now = net.now;
        assert!(net.node(AYSE).additions_tick(now).is_empty(), "the call goes on");

        let actions = net.node(AYSE).end_call(call);
        net.run(AYSE, actions);
        let actions = net.node(AYSE).additions_tick(now);
        net.run(AYSE, actions);
        assert_eq!(
            names(&mut net),
            ["Ayşe", "Burak"],
            "Cem's membership ended with the call"
        );
    }

    #[test]
    fn admins_hand_the_group_on_and_the_last_one_leaving_names_another() {
        let mut net = three();
        net.link(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (group, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        let burak = net.identity(BURAK);
        let (_, actions) = net.node(AYSE).set_group_admin(group.row, &burak, true).unwrap();
        net.run(AYSE, actions);
        assert!(roles(&mut net, BURAK).contains(&("Burak".into(), true)));
        let (_, actions) = net.node(AYSE).set_group_admin(group.row, &burak, false).unwrap();
        net.run(AYSE, actions);
        assert!(roles(&mut net, BURAK).contains(&("Burak".into(), false)));

        // Ayşe, the only admin, leaves: the member with the smallest identity key takes over and
        // removes her.
        let heir = if net.identity(BURAK).as_bytes() < net.identity(CEM).as_bytes() {
            BURAK
        } else {
            CEM
        };
        let other = BURAK + CEM - heir;
        let (_, actions) = net.node(AYSE).leave_group(group.row).unwrap();
        net.run(AYSE, actions);
        net.link(BURAK, CEM);
        let roles_at = roles(&mut net, other);
        let heir_name = net.devices[heir].node.account().unwrap().display_name().to_owned();
        let other_name = net.devices[other].node.account().unwrap().display_name().to_owned();
        let mut expected = vec![(heir_name, true), (other_name, false)];
        expected.sort();
        assert_eq!(roles_at, expected, "the group goes on without Ayşe");
    }
}
