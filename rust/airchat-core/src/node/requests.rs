//! Adding contacts by AirChat ID in the node (rust/airchat-protocol/docs/protocol.md §4.8). The user who typed an ID
//! makes this device announce a request token for it; the device whose ID it is answers by pairing
//! in request mode, proving it owns the ID before the other shows its card, and shows its own card
//! only once its user approved. An approval given after the connection ended takes effect the next
//! time the two meet. Requests meet their owners directly, by beacon, or over a path through Air
//! Providers (§12.2, in `paths.rs`).

use super::{Action, ConnectionId, ConnectionState, Node, NodeError, Store, now_ms};
use crate::{
    crypto::hash::equal_in_constant_time,
    discovery::{RequestToken, request_token},
    identity::{AirChatId, PublicIdentity},
    link::epoch_at,
    pairing::{Event, Pairing, Requester},
    storage::{
        ContactState,
        requests::{ContactRequest, RequestState},
    },
};

/// A device answers the same request token at most this often.
const ANSWER_EVERY_SECS: u64 = 60;

impl Node {
    /// The user typed someone's AirChat ID: this device asks to be added whenever it meets them.
    pub fn request_contact(&mut self, id_text: &str) -> Result<AirChatId, NodeError> {
        let id = AirChatId::parse(id_text).map_err(|_| NodeError::InvalidId)?;
        let account = self.account()?;
        if id.belongs_to(&account.identity().public()) {
            return Err(NodeError::OwnId);
        }
        let contacts = account.contacts()?;
        if contacts
            .iter()
            .any(|c| c.state == ContactState::Active && id.belongs_to(&c.identity))
        {
            return Err(NodeError::AlreadyContact);
        }
        account.db().add_sent_request(&id, now_ms())?;
        // Looked for through Air Providers at the next tick, not minutes later (§4.8).
        self.paths.search_requests_soon();
        Ok(id)
    }

    /// The AirChat IDs typed whose owners have not added this device yet.
    pub fn sent_requests(&self) -> Result<Vec<AirChatId>, NodeError> {
        Ok(self.account()?.db().sent_requests()?)
    }

    pub fn cancel_contact_request(&mut self, id: &AirChatId) -> Result<bool, NodeError> {
        Ok(self.account()?.db().delete_sent_request(id)?)
    }

    /// What to announce for the IDs typed, this epoch; nothing while locked.
    pub fn request_tokens(&self, now_secs: u64) -> Vec<RequestToken> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let epoch = epoch_at(now_secs);
        account
            .db()
            .sent_requests()
            .unwrap_or_default()
            .iter()
            .filter_map(|id| request_token(id, epoch).ok())
            .collect()
    }

    /// The tokens of the epochs around now of each ID typed, to accept the pairing that answers one.
    pub(super) fn request_table(&self, now_secs: u64) -> Vec<(RequestToken, AirChatId)> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let epoch = epoch_at(now_secs);
        let ids = account.db().sent_requests().unwrap_or_default();
        ids.iter()
            .flat_map(|id| {
                (epoch.saturating_sub(1)..=epoch.saturating_add(1))
                    .filter_map(move |e| request_token(id, e).ok().map(|token| (token, *id)))
            })
            .collect()
    }

    /// Whether the user lets others ask to be added (requirement C-4); off until the platform says.
    pub fn set_accept_requests(&mut self, accept: bool) {
        self.accept_requests = accept;
    }

    /// Whether `token`, seen on the network, asks for this device's owner: then connect to the
    /// device announcing it and call [`Node::answer_request`]. At most once a minute per token, and
    /// never while locked or with requests turned off.
    pub fn recognize_request(&mut self, token: &RequestToken, now_secs: u64) -> bool {
        let Store::Open(account) = &self.store else {
            return false;
        };
        let id = account.airchat_id();
        let epoch = epoch_at(now_secs);
        let ours = (epoch.saturating_sub(1)..=epoch.saturating_add(1))
            .filter_map(|e| request_token(&id, e).ok())
            .any(|own| equal_in_constant_time(&own, token));
        ours && self.answering_request(token, now_secs)
    }

    /// Whether this device answers a request for its owner with `token` now, on a beacon or over a
    /// path, and if so notes it: at most once a minute per token, never while locked or with
    /// requests turned off.
    pub(super) fn answering_request(&mut self, token: &RequestToken, now_secs: u64) -> bool {
        if !self.accept_requests || !matches!(self.store, Store::Open(_)) {
            return false;
        }
        self.answered_requests
            .retain(|_, at| now_secs.saturating_sub(*at) < ANSWER_EVERY_SECS);
        if self.answered_requests.contains_key(token) {
            return false;
        }
        self.answered_requests.insert(*token, now_secs);
        true
    }

    /// Answers a request for this device's owner on a new outgoing connection to the requester.
    pub fn answer_request(&mut self, connection: ConnectionId, token: &RequestToken) -> Result<Vec<Action>, NodeError> {
        let (pairing, message) = Pairing::start_request(&self.account()?.airchat_id(), token)?;
        self.open(connection, ConnectionState::Pairing(Box::new(pairing)), message)
    }

    /// Requests not answered yet, newest first.
    pub fn contact_requests(&self) -> Result<Vec<ContactRequest>, NodeError> {
        Ok(self.account()?.db().contact_requests()?)
    }

    /// The user adds the requester: at once if the two are still connected, else the next time.
    pub fn approve_contact_request(&mut self, identity: &PublicIdentity) -> Result<Vec<Action>, NodeError> {
        if !self
            .account()?
            .db()
            .answer_contact_request(identity, RequestState::Approved)?
        {
            return Err(NodeError::UnknownContact);
        }
        let Some((connection, mut pairing)) = self.waiting_request(identity) else {
            return Ok(Vec::new());
        };
        let Store::Open(account) = &self.store else {
            return Err(NodeError::Sealed);
        };
        let events = pairing.approve(&account.profile())?;
        let actions = self.pairing_events(connection, pairing, events);
        Ok(self.closing_on(actions))
    }

    /// The user turns the requester away, now and later; it is not told.
    pub fn decline_contact_request(&mut self, identity: &PublicIdentity) -> Result<Vec<Action>, NodeError> {
        if !self
            .account()?
            .db()
            .answer_contact_request(identity, RequestState::Declined)?
        {
            return Err(NodeError::UnknownContact);
        }
        let Some((connection, mut pairing)) = self.waiting_request(identity) else {
            return Ok(Vec::new());
        };
        let mut actions: Vec<Action> = pairing
            .reject()
            .map(|bytes| Action::Send { connection, bytes })
            .into_iter()
            .collect();
        actions.push(Action::Close { connection });
        Ok(self.closing_on(actions))
    }

    /// The open pairing in which `identity` waits for the user's answer, taken out of the table.
    fn waiting_request(&mut self, identity: &PublicIdentity) -> Option<(ConnectionId, Box<Pairing>)> {
        let connection = self.connections.iter().find_map(|(connection, state)| match state {
            ConnectionState::Pairing(pairing) if pairing.requester().as_ref() == Some(identity) => Some(*connection),
            _ => None,
        })?;
        match self.connections.remove(&connection) {
            Some(ConnectionState::Pairing(pairing)) => Some((connection, pairing)),
            _ => None,
        }
    }

    /// Someone asks to be added in an open pairing: added at once if the user approved before (or
    /// it is a contact already), turned away if declined, else the user is asked. `Ok` holds the
    /// pairing's next events and what to tell the platform; `Err` what ends the pairing.
    pub(super) fn requested(
        &mut self,
        connection: ConnectionId,
        pairing: &mut Pairing,
        requester: Requester,
    ) -> Result<(Vec<Event>, Vec<Action>), Vec<Action>> {
        let turn_away = |pairing: &mut Pairing| {
            let mut actions: Vec<Action> = pairing
                .reject()
                .map(|bytes| Action::Send { connection, bytes })
                .into_iter()
                .collect();
            actions.push(Action::Close { connection });
            actions
        };
        let Store::Open(account) = &self.store else {
            return Err(turn_away(pairing));
        };
        let db = account.db();
        let known = db
            .contact_by_identity(&requester.identity)
            .ok()
            .flatten()
            .map(|c| c.state);
        if known == Some(ContactState::Blocked) {
            return Err(turn_away(pairing));
        }
        let state = if known == Some(ContactState::Active) {
            RequestState::Approved
        } else {
            match db.note_contact_request(&requester.identity, &requester.display_name, now_ms()) {
                Ok(state) => state,
                Err(_) => return Err(turn_away(pairing)),
            }
        };
        match state {
            RequestState::Approved => match pairing.approve(&account.profile()) {
                Ok(events) => Ok((events, Vec::new())),
                Err(_) => Err(turn_away(pairing)),
            },
            RequestState::Declined => Err(turn_away(pairing)),
            RequestState::Pending => {
                let request = ContactRequest {
                    identity: requester.identity,
                    display_name: requester.display_name,
                    received_at_ms: now_ms(),
                };
                Ok((Vec::new(), vec![Action::ContactRequest { connection, request }]))
            }
        }
    }

    /// Pairing with `identity` finished: no request between the two is left.
    pub(super) fn request_answered(&mut self, identity: &PublicIdentity) {
        if let Store::Open(account) = &self.store {
            let _ = account.db().delete_contact_request(identity);
            let _ = account.db().delete_sent_request(&identity.airchat_id());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::groups::tests::Net;

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Ayşe and Burak, Ayşe taking requests.
    fn ayse_and_burak() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        net.node(AYSE).set_accept_requests(true);
        net
    }

    fn id_of(net: &mut Net, at: usize) -> AirChatId {
        net.node(at).account().unwrap().airchat_id()
    }

    /// Burak's device announces its request; Ayşe's sees it and answers on a new connection.
    fn meet(net: &mut Net) -> bool {
        let now = net.now;
        let Some(token) = net.node(BURAK).request_tokens(now).first().copied() else {
            return false;
        };
        if !net.node(AYSE).recognize_request(&token, now) {
            return false;
        }
        let (id, _) = net.wire(AYSE, BURAK);
        let actions = net.node(AYSE).answer_request(id, &token).unwrap();
        net.run(AYSE, actions);
        true
    }

    fn names(net: &mut Net, at: usize) -> Vec<String> {
        let contacts = net.node(at).account().unwrap().contacts().unwrap();
        contacts.into_iter().map(|c| c.display_name).collect()
    }

    fn asked(net: &Net) -> bool {
        net.devices[AYSE]
            .shown
            .iter()
            .any(|a| matches!(a, Action::ContactRequest { request, .. } if request.display_name == "Burak"))
    }

    #[test]
    fn a_typed_id_becomes_a_contact_once_its_owner_approves() {
        let mut net = ayse_and_burak();
        let ayse = id_of(&mut net, AYSE).to_string();
        net.node(BURAK).request_contact(&ayse.to_lowercase()).unwrap();
        assert!(meet(&mut net));
        assert!(asked(&net), "Ayşe is asked");
        assert!(names(&mut net, AYSE).is_empty() && names(&mut net, BURAK).is_empty());
        let burak = net.identity(BURAK);
        assert_eq!(net.node(AYSE).contact_requests().unwrap()[0].identity, burak);

        let actions = net.node(AYSE).approve_contact_request(&burak).unwrap();
        net.run(AYSE, actions);
        assert_eq!(names(&mut net, AYSE), ["Burak"]);
        assert_eq!(names(&mut net, BURAK), ["Ayşe"]);
        assert!(net.node(BURAK).sent_requests().unwrap().is_empty());
        assert!(net.node(AYSE).contact_requests().unwrap().is_empty());
        net.link(AYSE, BURAK);
    }

    #[test]
    fn an_approval_after_they_parted_takes_effect_when_they_meet_again() {
        let mut net = ayse_and_burak();
        let ayse = id_of(&mut net, AYSE).to_string();
        net.node(BURAK).request_contact(&ayse).unwrap();
        assert!(meet(&mut net));
        assert!(!meet(&mut net), "a token is answered once a minute");
        // The connection ends before Ayşe answers.
        let wires: Vec<_> = net.wires.clone();
        for ((a, a_id), (b, b_id)) in wires {
            net.node(a).connection_closed(a_id);
            net.node(b).connection_closed(b_id);
        }
        let burak = net.identity(BURAK);
        assert!(net.node(AYSE).approve_contact_request(&burak).unwrap().is_empty());
        assert!(names(&mut net, AYSE).is_empty());

        net.now += 61;
        assert!(meet(&mut net));
        assert_eq!(names(&mut net, AYSE), ["Burak"]);
        assert_eq!(names(&mut net, BURAK), ["Ayşe"]);
    }

    #[test]
    fn a_declined_request_is_turned_away_unseen() {
        let mut net = ayse_and_burak();
        let ayse = id_of(&mut net, AYSE).to_string();
        net.node(BURAK).request_contact(&ayse).unwrap();
        assert!(meet(&mut net));
        let burak = net.identity(BURAK);
        let actions = net.node(AYSE).decline_contact_request(&burak).unwrap();
        net.run(AYSE, actions);
        net.devices[AYSE].shown.clear();
        net.now += 61;
        assert!(meet(&mut net));
        assert!(!asked(&net), "not asked again");
        assert!(names(&mut net, AYSE).is_empty() && names(&mut net, BURAK).is_empty());
        assert!(net.node(AYSE).contact_requests().unwrap().is_empty());
    }

    #[test]
    fn typed_ids_are_checked() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        let own = id_of(&mut net, AYSE).to_string();
        let cem = id_of(&mut net, CEM).to_string();
        assert!(matches!(net.node(AYSE).request_contact(&own), Err(NodeError::OwnId)));
        assert!(matches!(
            net.node(AYSE).request_contact(&cem),
            Err(NodeError::AlreadyContact)
        ));
        assert!(matches!(
            net.node(AYSE).request_contact("AIR-12345"),
            Err(NodeError::InvalidId)
        ));
        // Only Ayşe's own requests are hers to answer, and Burak answers only once he takes them.
        let burak = id_of(&mut net, BURAK).to_string();
        net.node(CEM).request_contact(&burak).unwrap();
        let now = net.now;
        let token = net.node(CEM).request_tokens(now)[0];
        net.node(AYSE).set_accept_requests(true);
        assert!(!net.node(AYSE).recognize_request(&token, now));
        assert!(!net.node(BURAK).recognize_request(&token, now), "requests off");
        net.node(BURAK).set_accept_requests(true);
        assert!(net.node(BURAK).recognize_request(&token, now));
    }
}
