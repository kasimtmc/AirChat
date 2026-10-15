//! Group push-to-talk and group calls (rust/airchat-protocol/docs/protocol.md §9.6, §9.9). Voice goes over the links to
//! the members this device is linked with. Push-to-talk is not passed on; a group call is: every
//! participant repeats the presence, audio and video it takes to its other links, so a participant
//! hears (and sees) everyone linked to it through others.

use std::collections::{BTreeMap, HashMap, HashSet};

use zeroize::Zeroizing;

use super::{
    Effects, IncomingVideo, KEY_FRAME_RETRY_SECS, Media, MediaError, RING_SECS, TALK_SILENCE_SECS, frame_parts,
};
use crate::{
    chat::{CallOrigin, ChatMessage, EndReason, StreamId, VIDEO_PART_LEN, VideoHeader, VideoState},
    crypto::random,
    group::GroupId,
    identity::PublicIdentity,
    node::Action,
    storage::ContactId,
};

/// A group call participant sends its presence this often; one not renewed this long is gone, and
/// a member gone without leaving is looked for again for a minute (§9.6).
pub(crate) const PRESENCE_EVERY_SECS: u64 = 5;
pub(crate) const PRESENCE_GONE_SECS: u64 = 15;
const LOST_KEEP_SECS: u64 = 60;
/// Origins of audio kept track of without a presence, at most (a forged origin costs nothing).
const MAX_ORIGINS: usize = 64;
/// Frames of each origin's video whose parts are remembered, so each part is passed on once.
const SEEN_FRAMES: u32 = 16;
/// Key frame requests remembered, by nonce, so each is passed on once; for this long at most.
const MAX_KEY_REQUESTS: usize = 256;
const KEY_REQUEST_KEEP_SECS: u64 = 60;

/// What the node knows about a group a record names, as far as voice is concerned.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GroupVoice {
    /// The group's row, for the platform.
    pub row: i64,
    /// The sender is a member, and so is this device.
    pub member: bool,
    /// The user plays this group's push-to-talk at once.
    pub instant_voice: bool,
    /// A walkie-talkie channel (rust/airchat-protocol/docs/protocol.md §11.4) rather than a group.
    pub channel: bool,
}

pub(super) struct GroupTalkOut {
    id: StreamId,
    /// The members it goes to; those who turn it down leave the list.
    to: Vec<ContactId>,
    next_seq: u32,
}

pub(super) struct GroupTalkIn {
    id: StreamId,
    contact: ContactId,
    /// When audio was last heard; 0 until the next tick notes the time.
    heard_at: u64,
}

/// This device in a group call: the origin of its presence and audio, and its identity key.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CallSelf {
    pub origin: CallOrigin,
    pub identity: PublicIdentity,
}

/// A participant heard in a group call (directly or through others), by its origin.
struct Heard {
    /// The member it is: its row, and its identity key as its presence names it.
    member: ContactId,
    identity: PublicIdentity,
    count: u32,
    /// Its camera, as its latest presence says.
    camera: VideoState,
    /// When its presence last grew; 0 until the next tick.
    heard_at: u64,
}

/// One origin's video in a group call: the parts taken (each is passed on once), and the frame
/// this device puts together to show.
struct OriginVideo {
    /// Of the newest frames, a bit for each part taken.
    seen: BTreeMap<u32, u64>,
    incoming: IncomingVideo,
}

impl OriginVideo {
    /// A video joined in the middle cannot be shown before a key frame.
    fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
            incoming: IncomingVideo {
                awaiting_key: true,
                ..IncomingVideo::default()
            },
        }
    }

    /// Whether part `part` of frame `frame` is new; it is seen from now on.
    fn take(&mut self, frame: u32, part: u8) -> bool {
        if self
            .seen
            .last_key_value()
            .is_some_and(|(&newest, _)| frame.saturating_add(SEEN_FRAMES) <= newest)
        {
            return false;
        }
        let bits = self.seen.entry(frame).or_default();
        let bit = 1u64 << part;
        if *bits & bit != 0 {
            return false;
        }
        *bits |= bit;
        if let Some((&newest, _)) = self.seen.last_key_value() {
            self.seen.retain(|&f, _| f.saturating_add(SEEN_FRAMES) > newest);
        }
        true
    }
}

/// The audio sequence numbers seen from one origin: the largest, and the 64 below it.
#[derive(Default)]
struct Window {
    top: Option<u32>,
    below: u64,
    /// When audio last came; 0 until the next tick.
    heard_at: u64,
}

impl Window {
    /// Whether `seq` is new; it is seen from now on.
    fn take(&mut self, seq: u32) -> bool {
        self.heard_at = 0;
        let Some(top) = self.top else {
            self.top = Some(seq);
            return true;
        };
        if seq > top {
            let shift = seq - top;
            self.below = if shift >= 64 {
                0
            } else {
                (self.below << shift) | (1 << (shift - 1))
            };
            self.top = Some(seq);
            return true;
        }
        let back = top - seq;
        if back == 0 || back > 64 {
            return false;
        }
        let bit = 1u64 << (back - 1);
        let new = self.below & bit == 0;
        self.below |= bit;
        new
    }
}

pub(super) struct GroupCall {
    id: StreamId,
    group: GroupId,
    row: i64,
    /// This device is in it (started or joined), not just ringing.
    joined: bool,
    /// This device's origin and identity, once it is in it.
    me: Option<CallSelf>,
    /// How far this device's presence count has gone, and when it last sent it.
    count: u32,
    presence_at: u64,
    /// The members linked to this device that are in the call: what it sends goes to them.
    links: HashSet<ContactId>,
    /// Everyone heard in the call, by origin.
    heard: HashMap<CallOrigin, Heard>,
    /// What audio came from each origin.
    windows: HashMap<CallOrigin, Window>,
    /// Members gone without leaving, and since when (0 until the next tick): looked for (§9.6).
    lost: HashMap<ContactId, u64>,
    /// Someone else was in it with this device: once they all leave, it is over.
    met: bool,
    /// When it started ringing here, or when this device started it; 0 until the next tick.
    since: u64,
    next_seq: u32,
    /// This device's camera, told in its presence (§9.9), and its next frame's number.
    camera: VideoState,
    next_frame: u32,
    /// The video of each origin heard.
    videos: HashMap<CallOrigin, OriginVideo>,
    /// Key frame requests passed on, by nonce, with when (0 until the next tick).
    key_requests: HashMap<[u8; 8], u64>,
}

impl GroupCall {
    fn new(id: StreamId, group: GroupId, row: i64) -> Self {
        Self {
            id,
            group,
            row,
            joined: false,
            me: None,
            count: 0,
            presence_at: 0,
            links: HashSet::new(),
            heard: HashMap::new(),
            windows: HashMap::new(),
            lost: HashMap::new(),
            met: false,
            since: 0,
            next_seq: 0,
            camera: VideoState::Off,
            next_frame: 0,
            videos: HashMap::new(),
            key_requests: HashMap::new(),
        }
    }

    /// The members heard in it, for the platform.
    fn changed(&self) -> Action {
        let mut participants: Vec<ContactId> = self.heard.values().map(|h| h.member).collect();
        participants.sort_unstable();
        participants.dedup();
        Action::GroupCallChanged {
            id: self.id,
            participants,
        }
    }

    /// This device's presence, counted on, for its links.
    fn presence(&mut self) -> Option<ChatMessage> {
        let me = self.me?;
        let record = ChatMessage::CallPresence {
            stream: self.id,
            origin: me.origin,
            member: me.identity,
            count: self.count,
            camera: self.camera,
        };
        self.count = self.count.wrapping_add(1);
        Some(record)
    }

    /// The latest presence of everyone heard, for a participant that just linked.
    fn presences_heard(&self) -> Vec<ChatMessage> {
        self.heard
            .iter()
            .map(|(origin, heard)| ChatMessage::CallPresence {
                stream: self.id,
                origin: *origin,
                member: heard.identity,
                count: heard.count,
                camera: heard.camera,
            })
            .collect()
    }

    /// This device's presence, at once to every link: a change (its camera) goes round now.
    fn presence_now(&mut self) -> Effects {
        let mut effects = Effects::default();
        if let Some(presence) = self.presence() {
            for &link in &self.links {
                effects = effects.send(link, presence.clone());
            }
        }
        effects
    }

    /// Asks every link for a key frame of `origin`'s video, under a new nonce.
    fn ask_key_frame(&mut self, origin: CallOrigin) -> Effects {
        let Ok(nonce) = random::array() else {
            return Effects::default();
        };
        self.key_requests.insert(nonce, 0);
        let request = ChatMessage::CallKeyFrameRequest {
            stream: self.id,
            origin,
            nonce,
        };
        let mut effects = Effects::default();
        for &link in &self.links {
            effects = effects.send(link, request.clone());
        }
        effects
    }

    /// The origin `member` is heard under, if it is.
    fn origin_of(&self, member: ContactId) -> Option<CallOrigin> {
        self.heard.iter().find(|(_, h)| h.member == member).map(|(o, _)| *o)
    }
}

impl Media {
    /// The group call under way or ringing here, and whether this device is in it.
    pub fn group_call(&self) -> Option<(GroupId, bool)> {
        self.group_call.as_ref().map(|call| (call.group, call.joined))
    }

    /// Talks to the members of a group this device is linked with (`members`).
    pub fn start_group_talk(
        &mut self,
        group: GroupId,
        id: StreamId,
        members: &[ContactId],
    ) -> Result<Effects, MediaError> {
        if self.in_call() {
            return Err(MediaError::Busy);
        }
        if self.group_talks_in.contains_key(&group) {
            return Err(MediaError::FloorTaken);
        }
        let mut effects = Effects::default();
        if let Some(old) = self.group_talks_out.remove(&group) {
            effects.extend(talk_end_to(&old.to, old.id, EndReason::HungUp));
        }
        for &member in members {
            effects = effects.send(member, ChatMessage::GroupTalkStart { id, group_id: group });
        }
        self.group_talks_out.insert(
            group,
            GroupTalkOut {
                id,
                to: members.to_vec(),
                next_seq: 0,
            },
        );
        Ok(effects)
    }

    /// Starts a call with the members of a group this device is linked with (`members`), as `me`.
    pub fn start_group_call(
        &mut self,
        group: GroupId,
        row: i64,
        id: StreamId,
        members: &[ContactId],
        me: CallSelf,
    ) -> Result<Effects, MediaError> {
        if self.call.is_some() || self.group_call.is_some() {
            return Err(MediaError::Busy);
        }
        let mut effects = self.end_talks(EndReason::Interrupted);
        let mut call = GroupCall::new(id, group, row);
        call.joined = true;
        call.me = Some(me);
        for &member in members {
            effects = effects.send(member, ChatMessage::GroupCall { id, group_id: group });
        }
        effects = effects.action(call.changed());
        self.group_call = Some(call);
        Ok(effects)
    }

    /// Joins the group call ringing here as `me`; `members` are the group's members linked now.
    pub fn join_group_call(
        &mut self,
        id: StreamId,
        members: &[ContactId],
        me: CallSelf,
    ) -> Result<Effects, MediaError> {
        if !self.group_call.as_ref().is_some_and(|c| c.id == id && !c.joined) {
            return Err(MediaError::NoSuchStream);
        }
        let mut effects = self.end_talks(EndReason::Interrupted);
        let call = self.group_call.as_mut().expect("checked above");
        call.joined = true;
        call.me = Some(me);
        call.met = !call.links.is_empty();
        call.since = 0;
        for &member in members {
            effects = effects.send(
                member,
                ChatMessage::GroupCall {
                    id,
                    group_id: call.group,
                },
            );
        }
        // Those that rang it here are in it: they hear of this device at once.
        if let Some(presence) = call.presence() {
            for &link in &call.links {
                effects = effects.send(link, presence.clone());
            }
        }
        Ok(effects.action(call.changed()))
    }

    /// Leaves the group call, or stops it ringing here.
    pub(super) fn leave_group_call(&mut self, id: StreamId, reason: EndReason) -> Option<Effects> {
        let call = self.group_call.take_if(|c| c.id == id)?;
        let mut effects = Effects::default();
        if call.joined {
            for &contact in &call.links {
                effects = effects.send(contact, ChatMessage::GroupCallLeave { id });
            }
        }
        // Left (or given up): it does not ring here again.
        self.left_group_call = Some(id);
        Some(effects.action(Action::CallEnded { id, reason }))
    }

    /// Group voice records from a contact; `group` describes the group a record names.
    pub fn receive_group(&mut self, contact: ContactId, message: ChatMessage, group: Option<GroupVoice>) -> Effects {
        let effects = Effects::default();
        match message {
            ChatMessage::GroupTalkStart { id, group_id } => {
                let refuse = |reason| Effects::default().send(contact, ChatMessage::TalkEnd { id, reason });
                let Some(group) = group.filter(|g| g.member) else {
                    return refuse(EndReason::NotAllowed);
                };
                if !group.instant_voice {
                    return refuse(EndReason::NotAllowed);
                }
                if self.in_call() {
                    return refuse(EndReason::Busy);
                }
                // One talk per group: the smaller id goes on, here as everywhere.
                let mut effects = effects;
                if let Some(ours) = self.group_talks_out.get(&group_id) {
                    if ours.id < id {
                        return refuse(EndReason::Interrupted);
                    }
                    let ours = self.group_talks_out.remove(&group_id).expect("just found");
                    effects.extend(talk_end_to(&ours.to, ours.id, EndReason::Interrupted));
                    effects = effects.action(Action::TalkEnded {
                        id: ours.id,
                        reason: EndReason::Interrupted,
                    });
                }
                if let Some(heard) = self.group_talks_in.get(&group_id) {
                    if heard.id == id {
                        return effects;
                    }
                    if heard.id < id {
                        return refuse(EndReason::Interrupted);
                    }
                    let heard = self.group_talks_in.remove(&group_id).expect("just found");
                    effects = effects
                        .send(
                            heard.contact,
                            ChatMessage::TalkEnd {
                                id: heard.id,
                                reason: EndReason::Interrupted,
                            },
                        )
                        .action(Action::TalkEnded {
                            id: heard.id,
                            reason: EndReason::Interrupted,
                        });
                }
                self.group_talks_in.insert(
                    group_id,
                    GroupTalkIn {
                        id,
                        contact,
                        heard_at: 0,
                    },
                );
                effects.action(if group.channel {
                    Action::ChannelTalkStarted {
                        id,
                        channel: group.row,
                        contact,
                    }
                } else {
                    Action::GroupTalkStarted {
                        id,
                        group: group.row,
                        contact,
                    }
                })
            }
            ChatMessage::GroupCall { id, group_id } => {
                let Some(group) = group.filter(|g| g.member) else {
                    return effects;
                };
                // In another call, or one this device left: it does not ring here.
                if self.call.is_some() || self.left_group_call == Some(id) {
                    return effects;
                }
                match self.group_call.as_mut() {
                    Some(call) if call.id == id => {
                        let new = call.links.insert(contact);
                        if call.joined && new {
                            // Tell the newcomer this device is in it too.
                            let mut effects = effects.send(
                                contact,
                                ChatMessage::GroupCall {
                                    id,
                                    group_id: call.group,
                                },
                            );
                            if let Some(presence) = call.presence() {
                                effects = effects.send(contact, presence);
                            }
                            // And of everyone it hears, so the newcomer knows them at once.
                            for presence in call.presences_heard() {
                                effects = effects.send(contact, presence);
                            }
                            return effects;
                        }
                        effects
                    }
                    Some(_) => effects,
                    None => {
                        let mut call = GroupCall::new(id, group_id, group.row);
                        call.links.insert(contact);
                        self.group_call = Some(call);
                        effects.action(Action::GroupCallRinging {
                            id,
                            group: group.row,
                            contact,
                        })
                    }
                }
            }
            ChatMessage::GroupCallLeave { id } => self.participant_gone(contact, id, EndReason::HungUp),
            _ => effects,
        }
    }

    /// `contact`, linked, left the group call `id`: its presence goes at once; over for this
    /// device too once nobody is left.
    fn participant_gone(&mut self, contact: ContactId, id: StreamId, reason: EndReason) -> Effects {
        let Some(call) = self.group_call.as_mut().filter(|c| c.id == id) else {
            return Effects::default();
        };
        let linked = call.links.remove(&contact);
        let origin = call.origin_of(contact);
        if let Some(origin) = origin {
            call.heard.remove(&origin);
        }
        call.lost.remove(&contact);
        if !linked && origin.is_none() {
            return Effects::default();
        }
        self.call_over_check(reason)
    }

    /// Ends the group call here if everyone else in it has gone (and nobody gone without leaving
    /// may still be found again); else tells the platform who is in it.
    fn call_over_check(&mut self, reason: EndReason) -> Effects {
        let Some(call) = self.group_call.as_ref() else {
            return Effects::default();
        };
        let alone = call.heard.is_empty() && call.lost.is_empty();
        let over = if call.joined {
            call.met && alone
        } else {
            alone && call.links.is_empty()
        };
        if over {
            let id = call.id;
            let joined = call.joined;
            self.group_call = None;
            if !joined {
                self.left_group_call = Some(id);
            }
            return Effects::default().action(Action::CallEnded { id, reason });
        }
        Effects::default().action(call.changed())
    }

    /// A participant's presence in group call `stream`, from linked `contact`; `member` is the row
    /// of the member it names (a member of the group: the node checked). Passed on to the other
    /// links when new.
    pub fn receive_call_presence(&mut self, contact: ContactId, member: ContactId, record: ChatMessage) -> Effects {
        let ChatMessage::CallPresence {
            stream,
            origin,
            count,
            member: identity,
            camera,
        } = &record
        else {
            return Effects::default();
        };
        let Some(call) = self.group_call.as_mut().filter(|c| c.id == *stream && c.joined) else {
            return Effects::default();
        };
        if call.me.is_some_and(|me| me.origin == *origin) {
            return Effects::default();
        }
        // Linked to it, the member is in the call (its records go there from now on).
        call.links.insert(contact);
        let mut effects = Effects::default();
        let new = match call.heard.get_mut(origin) {
            Some(heard) if *count <= heard.count => return Effects::default(),
            Some(heard) => {
                heard.count = *count;
                heard.heard_at = 0;
                if heard.camera != *camera {
                    heard.camera = *camera;
                    effects = effects.action(Action::VideoStateChanged {
                        id: *stream,
                        from: member,
                        state: *camera,
                    });
                }
                false
            }
            None => {
                call.heard.insert(
                    *origin,
                    Heard {
                        member,
                        identity: *identity,
                        count: *count,
                        camera: *camera,
                        heard_at: 0,
                    },
                );
                if *camera != VideoState::Off {
                    effects = effects.action(Action::VideoStateChanged {
                        id: *stream,
                        from: member,
                        state: *camera,
                    });
                }
                true
            }
        };
        // Off or paused: what was being put together will not be finished.
        if *camera != VideoState::On
            && let Some(video) = call.videos.get_mut(origin)
        {
            video.incoming.frame = None;
        }
        call.lost.remove(&member);
        call.met = true;
        for &link in call.links.iter().filter(|&&l| l != contact) {
            effects = effects.send(link, record.clone());
        }
        if new {
            effects = effects.action(call.changed());
        }
        effects
    }

    /// This device's camera in the group call under way (§9.9): everyone hears of it in its
    /// presence, sent at once.
    pub fn set_group_camera(&mut self, id: StreamId, state: VideoState) -> Result<Effects, MediaError> {
        let call = self
            .group_call
            .as_mut()
            .filter(|c| c.id == id && c.joined)
            .ok_or(MediaError::NoSuchStream)?;
        if call.camera == state {
            return Ok(Effects::default());
        }
        call.camera = state;
        Ok(call.presence_now())
    }

    /// An encoded frame of this device's camera for group call `stream`, as records for its links:
    /// `None` if that is not the group call this device is in; nothing while the camera is not on.
    pub(super) fn group_video_out(
        &mut self,
        stream: StreamId,
        key: bool,
        rotation: u8,
        size: (u16, u16),
        frame: &[u8],
    ) -> Option<Result<Vec<(ContactId, ChatMessage)>, MediaError>> {
        let call = self.group_call.as_mut().filter(|c| c.id == stream && c.joined)?;
        let (Some(me), VideoState::On) = (call.me, call.camera) else {
            return Some(Err(MediaError::NoSuchStream));
        };
        let parts = match frame_parts(frame) {
            Ok(parts) => parts,
            Err(error) => return Some(Err(error)),
        };
        let header = VideoHeader {
            frame: call.next_frame,
            key,
            rotation,
            width: size.0,
            height: size.1,
        };
        call.next_frame = call.next_frame.wrapping_add(1);
        let mut records = Vec::new();
        for (part, data) in frame.chunks(VIDEO_PART_LEN).enumerate() {
            let record = ChatMessage::CallVideo {
                stream,
                origin: me.origin,
                header,
                part: part as u8,
                parts,
                data: Zeroizing::new(data.to_vec()),
            };
            records.extend(call.links.iter().map(|&link| (link, record.clone())));
        }
        Some(Ok(records))
    }

    /// A part of group call video from linked `contact`: passed on to the other links once, and put
    /// together to show, if its origin's presence is held (§9.9).
    pub fn receive_call_video(&mut self, contact: ContactId, record: ChatMessage) -> Effects {
        let ChatMessage::CallVideo {
            stream,
            origin,
            header,
            part,
            parts,
            data,
        } = &record
        else {
            return Effects::default();
        };
        let Some(call) = self.group_call.as_mut().filter(|c| c.id == *stream && c.joined) else {
            return Effects::default();
        };
        let Some(member) = call.heard.get(origin).map(|h| h.member) else {
            return Effects::default();
        };
        if !call.videos.contains_key(origin) && call.videos.len() >= MAX_ORIGINS {
            return Effects::default();
        }
        let joined_now = !call.videos.contains_key(origin);
        let video = call.videos.entry(*origin).or_insert_with(OriginVideo::new);
        if !video.take(header.frame, *part) {
            return Effects::default();
        }
        let mut effects = Effects::default();
        for &link in call.links.iter().filter(|&&l| l != contact) {
            effects = effects.send(link, record.clone());
        }
        let (frame, ask) = video.incoming.part(*header, *part, *parts, data.clone());
        if let Some((header, frame)) = frame {
            effects = effects.action(Action::Video {
                stream: *stream,
                from: member,
                key: header.key,
                rotation: header.rotation,
                width: header.width,
                height: header.height,
                frame,
            });
        }
        // Joined in the middle of it, or a frame went missing: a key frame is asked for.
        if ask || (joined_now && !header.key) {
            effects.extend(call.ask_key_frame(*origin));
        }
        effects
    }

    /// A request for a key frame of some participant's video from linked `contact`: passed on to
    /// the other links once; when it is for this device's video, its next frame is a key frame.
    pub fn receive_call_key_frame_request(&mut self, contact: ContactId, record: ChatMessage) -> Effects {
        let ChatMessage::CallKeyFrameRequest { stream, origin, nonce } = &record else {
            return Effects::default();
        };
        let Some(call) = self.group_call.as_mut().filter(|c| c.id == *stream && c.joined) else {
            return Effects::default();
        };
        if call.key_requests.contains_key(nonce) || call.key_requests.len() >= MAX_KEY_REQUESTS {
            return Effects::default();
        }
        call.key_requests.insert(*nonce, 0);
        if call.me.is_some_and(|me| me.origin == *origin) {
            return match call.camera {
                VideoState::On => Effects::default().action(Action::KeyFrameRequested { id: *stream }),
                _ => Effects::default(),
            };
        }
        let mut effects = Effects::default();
        for &link in call.links.iter().filter(|&&l| l != contact) {
            effects = effects.send(link, record.clone());
        }
        effects
    }

    /// The platform cannot decode `member`'s video in the group call from here on: frames are
    /// skipped until a key frame, which is asked for.
    pub fn request_member_key_frame(&mut self, stream: StreamId, member: ContactId) -> Result<Effects, MediaError> {
        let call = self
            .group_call
            .as_mut()
            .filter(|c| c.id == stream && c.joined)
            .ok_or(MediaError::NoSuchStream)?;
        let origin = call.origin_of(member).ok_or(MediaError::NoSuchStream)?;
        let video = call.videos.entry(origin).or_insert_with(OriginVideo::new);
        video.incoming.lose();
        video.incoming.asked_at = 0;
        Ok(call.ask_key_frame(origin))
    }

    /// A packet of group call audio from linked `contact`: played if its origin's presence is held,
    /// and passed on to the other links, once.
    pub fn receive_call_audio(&mut self, contact: ContactId, record: ChatMessage) -> Effects {
        let ChatMessage::CallAudio {
            stream,
            origin,
            seq,
            packet,
        } = &record
        else {
            return Effects::default();
        };
        let Some(call) = self.group_call.as_mut().filter(|c| c.id == *stream && c.joined) else {
            return Effects::default();
        };
        if call.me.is_some_and(|me| me.origin == *origin) {
            return Effects::default();
        }
        if !call.windows.contains_key(origin) && call.windows.len() >= MAX_ORIGINS {
            return Effects::default();
        }
        if !call.windows.entry(*origin).or_default().take(*seq) {
            return Effects::default();
        }
        let mut effects = Effects::default();
        for &link in call.links.iter().filter(|&&l| l != contact) {
            effects = effects.send(link, record.clone());
        }
        if let Some(heard) = call.heard.get(origin) {
            effects = effects.action(Action::Audio {
                stream: *stream,
                from: heard.member,
                seq: *seq,
                packet: packet.clone(),
            });
        }
        effects
    }

    /// Members of the group call under way gone without leaving in the last minute: a path to one
    /// may bring them back (§9.6).
    pub fn lost_call_members(&self) -> Vec<ContactId> {
        self.group_call
            .as_ref()
            .filter(|c| c.joined)
            .map(|c| c.lost.keys().copied().collect())
            .unwrap_or_default()
    }

    /// A member of the group of the call under way linked: it hears of the call (and rings).
    pub fn member_linked(&mut self, contact: ContactId) -> Effects {
        match self.group_call.as_ref().filter(|c| c.joined) {
            Some(call) => Effects::default().send(
                contact,
                ChatMessage::GroupCall {
                    id: call.id,
                    group_id: call.group,
                },
            ),
            None => Effects::default(),
        }
    }

    pub(super) fn in_group_call(&self) -> bool {
        self.group_call.as_ref().is_some_and(|c| c.joined)
    }

    pub(super) fn group_active_with(&self, contact: ContactId) -> bool {
        self.group_call
            .as_ref()
            .is_some_and(|c| c.joined && c.links.contains(&contact))
            || self.group_talks_out.values().any(|t| t.to.contains(&contact))
            || self.group_talks_in.values().any(|t| t.contact == contact)
    }

    /// This device's group talk `id` ends.
    pub(super) fn end_group_talk(&mut self, id: StreamId) -> Option<Effects> {
        let group = *self.group_talks_out.iter().find(|(_, t)| t.id == id)?.0;
        let talk = self.group_talks_out.remove(&group)?;
        Some(talk_end_to(&talk.to, id, EndReason::HungUp).action(Action::TalkEnded {
            id,
            reason: EndReason::HungUp,
        }))
    }

    /// A talk end from `contact` about a group talk: the end of one heard, or a member turning
    /// down (or interrupting) this device's.
    pub(super) fn group_talk_end(&mut self, contact: ContactId, id: StreamId, reason: EndReason) -> Option<Effects> {
        if let Some(group) = self
            .group_talks_in
            .iter()
            .find(|(_, t)| t.id == id && t.contact == contact)
            .map(|(g, _)| *g)
        {
            self.group_talks_in.remove(&group);
            return Some(Effects::default().action(Action::TalkEnded { id, reason }));
        }
        let group = *self.group_talks_out.iter().find(|(_, t)| t.id == id)?.0;
        let talk = self.group_talks_out.get_mut(&group)?;
        talk.to.retain(|&c| c != contact);
        // Someone else's talk goes first, or nobody is left to hear this one.
        if reason == EndReason::Interrupted || talk.to.is_empty() {
            let talk = self.group_talks_out.remove(&group)?;
            return Some(talk_end_to(&talk.to, id, reason).action(Action::TalkEnded { id, reason }));
        }
        Some(Effects::default())
    }

    /// Where a packet of this device's audio goes in a group talk or call, as records.
    pub(super) fn group_audio_out(&mut self, stream: StreamId, packet: &[u8]) -> Option<Vec<(ContactId, ChatMessage)>> {
        if let Some(call) = self.group_call.as_mut().filter(|c| c.id == stream && c.joined) {
            let origin = call.me?.origin;
            let seq = call.next_seq;
            call.next_seq = seq.wrapping_add(1);
            let record = ChatMessage::CallAudio {
                stream,
                origin,
                seq,
                packet: Zeroizing::new(packet.to_vec()),
            };
            return Some(call.links.iter().map(|&link| (link, record.clone())).collect());
        }
        let (to, seq): (Vec<ContactId>, &mut u32) = {
            let talk = self.group_talks_out.values_mut().find(|t| t.id == stream)?;
            (talk.to.clone(), &mut talk.next_seq)
        };
        let records = to
            .into_iter()
            .map(|contact| {
                let record = ChatMessage::Audio {
                    stream,
                    seq: *seq,
                    packet: Zeroizing::new(packet.to_vec()),
                };
                (contact, record)
            })
            .collect();
        *seq = seq.wrapping_add(1);
        Some(records)
    }

    /// Whether audio from `contact` for `stream` belongs to a group talk heard.
    pub(super) fn group_audio_in(&mut self, contact: ContactId, stream: StreamId) -> bool {
        if let Some(talk) = self
            .group_talks_in
            .values_mut()
            .find(|t| t.id == stream && t.contact == contact)
        {
            talk.heard_at = 0;
            return true;
        }
        false
    }

    /// A link came (back): in a call, the member is told of it when the node sees it is one.
    pub(super) fn group_linked(&mut self, _contact: ContactId) {}

    /// The link to `contact` is gone: talks with it end; in a call it gets a while to come back.
    pub(super) fn group_unlinked(&mut self, contact: ContactId) -> Effects {
        let mut effects = Effects::default();
        // In a call, its records go no more; its presence (and those it passed on) times out.
        if let Some(call) = self.group_call.as_mut() {
            call.links.remove(&contact);
        }
        for talk in self.group_talks_out.values_mut() {
            talk.to.retain(|&c| c != contact);
        }
        let heard: Vec<GroupId> = self
            .group_talks_in
            .iter()
            .filter(|(_, t)| t.contact == contact)
            .map(|(g, _)| *g)
            .collect();
        for group in heard {
            if let Some(talk) = self.group_talks_in.remove(&group) {
                effects = effects.action(Action::TalkEnded {
                    id: talk.id,
                    reason: EndReason::Lost,
                });
            }
        }
        effects
    }

    /// Ends everything with `contact` (blocked, deleted, no longer a member).
    pub(super) fn group_forget(&mut self, contact: ContactId) -> Effects {
        let mut effects = self.group_unlinked(contact);
        if let Some(id) = self.group_call.as_ref().map(|c| c.id) {
            effects.extend(self.participant_gone(contact, id, EndReason::HungUp));
        }
        effects
    }

    /// Ends this device's group talks and those it hears.
    pub(super) fn end_group_talks(&mut self, reason: EndReason) -> Effects {
        let mut effects = Effects::default();
        for (_, talk) in self.group_talks_out.drain() {
            effects.extend(talk_end_to(&talk.to, talk.id, reason));
            effects.actions.push(Action::TalkEnded { id: talk.id, reason });
        }
        for (_, talk) in self.group_talks_in.drain() {
            effects.actions.push(Action::TalkEnded { id: talk.id, reason });
        }
        effects
    }

    /// Gives up a group call nobody answers or that rings too long, sends this device's presence
    /// on, lets go of participants whose presence stopped, and ends talks gone silent.
    pub(super) fn group_tick(&mut self, stamp: &dyn Fn(&mut u64) -> u64) -> Effects {
        let mut effects = Effects::default();
        if let Some(call) = self.group_call.as_mut() {
            let waited = stamp(&mut call.since);
            let id = call.id;
            if !call.met && waited >= RING_SECS {
                // Rang here unanswered, or nobody joined this device's call.
                effects.extend(self.leave_group_call(id, EndReason::NoAnswer).unwrap_or_default());
            } else {
                if call.joined && stamp(&mut call.presence_at) >= PRESENCE_EVERY_SECS {
                    call.presence_at = 0;
                    stamp(&mut call.presence_at);
                    if let Some(presence) = call.presence() {
                        for &link in &call.links {
                            effects = effects.send(link, presence.clone());
                        }
                    }
                }
                let gone: Vec<CallOrigin> = call
                    .heard
                    .iter_mut()
                    .filter_map(|(origin, heard)| (stamp(&mut heard.heard_at) >= PRESENCE_GONE_SECS).then_some(*origin))
                    .collect();
                for origin in &gone {
                    if let Some(heard) = call.heard.remove(origin) {
                        call.lost.insert(heard.member, 0);
                    }
                }
                let lost_before = call.lost.len();
                call.lost.retain(|_, at| stamp(at) < LOST_KEEP_SECS);
                let heard = &call.heard;
                call.windows.retain(|origin, window| {
                    heard.contains_key(origin) || stamp(&mut window.heard_at) < PRESENCE_GONE_SECS
                });
                call.videos.retain(|origin, _| heard.contains_key(origin));
                call.key_requests.retain(|_, at| stamp(at) < KEY_REQUEST_KEEP_SECS);
                // Key frames still awaited are asked for again every second.
                let awaited: Vec<CallOrigin> = call
                    .videos
                    .iter_mut()
                    .filter(|(origin, video)| {
                        heard.get(*origin).is_some_and(|h| h.camera == VideoState::On) && video.incoming.awaiting_key
                    })
                    .filter_map(|(origin, video)| {
                        (stamp(&mut video.incoming.asked_at) >= KEY_FRAME_RETRY_SECS).then(|| {
                            video.incoming.asked_at = 0;
                            *origin
                        })
                    })
                    .collect();
                for origin in awaited {
                    effects.extend(call.ask_key_frame(origin));
                }
                if !gone.is_empty() || call.lost.len() != lost_before {
                    effects.extend(self.call_over_check(EndReason::Lost));
                }
            }
        }
        let silent: Vec<GroupId> = self
            .group_talks_in
            .iter_mut()
            .filter_map(|(group, talk)| (stamp(&mut talk.heard_at) >= TALK_SILENCE_SECS).then_some(*group))
            .collect();
        for group in silent {
            if let Some(talk) = self.group_talks_in.remove(&group) {
                effects.actions.push(Action::TalkEnded {
                    id: talk.id,
                    reason: EndReason::Lost,
                });
            }
        }
        effects
    }

    /// The row of the group whose call `id` is.
    /// The talk heard in a group (or channel) now, and the link it comes over.
    pub fn group_talk_in(&self, group: &GroupId) -> Option<(StreamId, ContactId)> {
        self.group_talks_in.get(group).map(|talk| (talk.id, talk.contact))
    }

    /// This device's own talk to a group (or channel) now.
    pub fn own_group_talk(&self, group: &GroupId) -> Option<StreamId> {
        self.group_talks_out.get(group).map(|talk| talk.id)
    }

    pub fn group_call_row(&self, id: StreamId) -> Option<i64> {
        self.group_call.as_ref().filter(|c| c.id == id).map(|c| c.row)
    }
}

fn talk_end_to(to: &[ContactId], id: StreamId, reason: EndReason) -> Effects {
    let mut effects = Effects::default();
    for &contact in to {
        effects = effects.send(contact, ChatMessage::TalkEnd { id, reason });
    }
    effects
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::Allowed;

    #[test]
    fn each_part_of_a_participants_video_is_taken_once() {
        let mut video = OriginVideo::new();
        assert!(video.incoming.awaiting_key, "joined in the middle");
        assert!(video.take(5, 0));
        assert!(!video.take(5, 0), "seen");
        assert!(video.take(5, 1));
        assert!(video.take(4, 0), "an earlier frame still in reach");
        assert!(video.take(30, 63));
        assert!(!video.take(5, 2), "too old by now");
        assert!(video.take(20, 0));
        assert!(video.seen.len() <= SEEN_FRAMES as usize);
    }

    const GROUP: GroupId = [6; 16];
    const ROW: i64 = 4;
    const PLAYS: Option<GroupVoice> = Some(GroupVoice {
        row: ROW,
        member: true,
        instant_voice: true,
        channel: false,
    });
    const SILENT: Option<GroupVoice> = Some(GroupVoice {
        row: ROW,
        member: true,
        instant_voice: false,
        channel: false,
    });

    /// Three devices; each one's contact row for the others: Ayşe 1, Burak 2, Cem 3 everywhere.
    fn devices() -> [Media; 3] {
        [Media::default(), Media::default(), Media::default()]
    }

    /// Device `at` in a group call: its origin and identity key say its row (`at + 1`).
    fn me(at: usize) -> CallSelf {
        CallSelf {
            origin: [at as u8 + 1; 8],
            identity: PublicIdentity::from_bytes([at as u8 + 1; 32]),
        }
    }

    /// Delivers `effects` from device `from` (row `from + 1` for the others), with `voice` as what
    /// each receiver knows of the group; returns the actions each receiver shows.
    fn deliver(
        devices: &mut [Media; 3],
        from: usize,
        effects: Effects,
        voice: [Option<GroupVoice>; 3],
    ) -> Vec<Vec<Action>> {
        let mut shown: Vec<Vec<Action>> = vec![Vec::new(), Vec::new(), Vec::new()];
        let mut queue: Vec<(usize, ContactId, ChatMessage)> = effects
            .send
            .into_iter()
            .map(|(to, m)| (to as usize - 1, from as ContactId + 1, m))
            .collect();
        while !queue.is_empty() {
            let (at, sender, message) = queue.remove(0);
            let effects = match message {
                m @ (ChatMessage::GroupTalkStart { .. }
                | ChatMessage::GroupCall { .. }
                | ChatMessage::GroupCallLeave { .. }) => devices[at].receive_group(sender, m, voice[at]),
                m @ ChatMessage::CallPresence { member, .. } => {
                    devices[at].receive_call_presence(sender, member.as_bytes()[0] as ContactId, m)
                }
                m @ ChatMessage::CallAudio { .. } => devices[at].receive_call_audio(sender, m),
                m => devices[at].receive(
                    sender,
                    m,
                    Allowed {
                        calls: true,
                        instant_voice: true,
                    },
                ),
            };
            queue.extend(
                effects
                    .send
                    .into_iter()
                    .map(|(to, m)| (to as usize - 1, at as ContactId + 1, m)),
            );
            shown[at].extend(effects.actions);
        }
        shown
    }

    #[test]
    fn a_group_talk_plays_where_allowed_and_goes_on_for_the_others() {
        let mut d = devices();
        let id = [1; 16];
        let start = d[0].start_group_talk(GROUP, id, &[2, 3]).unwrap();
        let shown = deliver(&mut d, 0, start, [None, PLAYS, SILENT]);
        assert!(matches!(
            shown[1][..],
            [Action::GroupTalkStarted {
                group: ROW,
                contact: 1,
                ..
            }]
        ));
        assert!(shown[2].is_empty(), "Cem does not play it");
        assert!(shown[0].is_empty(), "Ayşe talks on to Burak");

        let audio = d[0].audio(id, b"opus");
        assert_eq!(
            audio.iter().map(|(to, _)| *to).collect::<Vec<_>>(),
            [2],
            "only to who plays it"
        );
        let heard = d[1].receive(
            1,
            audio[0].1.clone(),
            Allowed {
                calls: true,
                instant_voice: false,
            },
        );
        assert!(matches!(heard.actions[..], [Action::Audio { from: 1, seq: 0, .. }]));

        let end = d[0].end_talk(id);
        assert!(matches!(
            end.actions[..],
            [Action::TalkEnded {
                reason: EndReason::HungUp,
                ..
            }]
        ));
        let shown = deliver(&mut d, 0, end, [None, PLAYS, SILENT]);
        assert!(matches!(shown[1][..], [Action::TalkEnded { .. }]));
        assert!(!d[1].active_with(1));
    }

    #[test]
    fn of_two_group_talks_at_once_the_smaller_id_goes_on() {
        let mut d = devices();
        let (burak, cem) = ([5; 16], [3; 16]);
        let burak_starts = d[1].start_group_talk(GROUP, burak, &[1, 3]).unwrap();
        let cem_starts = d[2].start_group_talk(GROUP, cem, &[1, 2]).unwrap();
        let voice = [PLAYS, PLAYS, PLAYS];
        // Ayşe hears Burak first, then Cem's smaller id takes over; Burak learns it from Cem
        // (whose own talk goes first) and from Ayşe.
        let first = deliver(&mut d, 1, burak_starts, voice);
        assert!(
            first[0]
                .iter()
                .any(|a| matches!(a, Action::GroupTalkStarted { contact: 2, .. }))
        );
        let then = deliver(&mut d, 2, cem_starts, voice);
        assert!(
            then[0]
                .iter()
                .any(|a| matches!(a, Action::GroupTalkStarted { contact: 3, .. }))
        );
        assert!(
            first[1]
                .iter()
                .chain(&then[1])
                .any(|a| matches!(a, Action::TalkEnded { id, reason: EndReason::Interrupted } if *id == burak)),
            "Burak's own talk stops"
        );
        assert!(d[1].audio(burak, b"x").is_empty());
        assert_eq!(d[2].audio(cem, b"x").len(), 2, "Cem is heard by both");
        assert!(matches!(
            d[1].start_group_talk(GROUP, [9; 16], &[1, 3]),
            Err(MediaError::FloorTaken)
        ));
    }

    #[test]
    fn a_group_call_rings_members_who_join_and_leave() {
        let mut d = devices();
        let id = [2; 16];
        let voice = [PLAYS, PLAYS, PLAYS];
        let start = d[0].start_group_call(GROUP, ROW, id, &[2, 3], me(0)).unwrap();
        assert!(
            matches!(&start.actions[..], [Action::GroupCallChanged { participants, .. }] if participants.is_empty())
        );
        let shown = deliver(&mut d, 0, start, voice);
        for at in [1, 2] {
            assert!(matches!(
                shown[at][..],
                [Action::GroupCallRinging {
                    group: ROW,
                    contact: 1,
                    ..
                }]
            ));
        }
        assert!(d[0].audio(id, b"x").is_empty(), "nobody in it yet");

        let join = d[1].join_group_call(id, &[1, 3], me(1)).unwrap();
        let shown = deliver(&mut d, 1, join, voice);
        assert!(matches!(&shown[0][..], [Action::GroupCallChanged { participants, .. }] if participants == &[2]));
        assert!(shown[2].is_empty(), "Cem still rings");
        assert_eq!(d[0].audio(id, b"x").iter().map(|(to, _)| *to).collect::<Vec<_>>(), [2]);

        let join = d[2].join_group_call(id, &[1, 2], me(2)).unwrap();
        deliver(&mut d, 2, join, voice);
        for (at, others) in [(0, vec![2, 3]), (1, vec![1, 3]), (2, vec![1, 2])] {
            let mut to: Vec<ContactId> = d[at].audio(id, b"x").iter().map(|(to, _)| *to).collect();
            to.sort_unstable();
            assert_eq!(to, others, "device {at} sends to everyone else");
        }
        let packet = d[1].audio(id, b"opus").remove(0).1;
        let heard = d[0].receive_call_audio(2, packet);
        assert!(matches!(heard.actions[..], [Action::Audio { from: 2, .. }]));

        let leave = d[1].hang_up(id);
        assert!(matches!(
            leave.actions[..],
            [Action::CallEnded {
                reason: EndReason::HungUp,
                ..
            }]
        ));
        let shown = deliver(&mut d, 1, leave, voice);
        assert!(matches!(&shown[0][..], [Action::GroupCallChanged { participants, .. }] if participants == &[3]));
        let leave = d[0].hang_up(id);
        let shown = deliver(&mut d, 0, leave, voice);
        assert!(
            matches!(shown[2][..], [Action::CallEnded { .. }]),
            "Cem is left alone: over"
        );
        assert!(d.iter().all(|m| m.group_call().is_none()));
    }

    #[test]
    fn group_calls_ring_only_members_and_give_up_unanswered() {
        let mut d = devices();
        let id = [2; 16];
        let start = d[0].start_group_call(GROUP, ROW, id, &[2, 3], me(0)).unwrap();
        let outsider = Some(GroupVoice {
            row: ROW,
            member: false,
            instant_voice: true,
            channel: false,
        });
        let shown = deliver(&mut d, 0, start, [None, None, outsider]);
        assert!(shown[1].is_empty() && shown[2].is_empty());

        let mut d = devices();
        let start = d[0].start_group_call(GROUP, ROW, id, &[2], me(0)).unwrap();
        deliver(&mut d, 0, start, [PLAYS, PLAYS, PLAYS]);
        for m in &mut d[..2] {
            assert!(m.tick(1_000).actions.is_empty());
        }
        for m in &mut d[..2] {
            let ended = m.tick(1_000 + RING_SECS);
            assert!(matches!(
                ended.actions[..],
                [Action::CallEnded {
                    reason: EndReason::NoAnswer,
                    ..
                }]
            ));
        }
        // A 1:1 call is refused meanwhile, and a group call does not ring during one.
        let mut d = devices();
        d[1].start_call(1, [7; 16], false).unwrap();
        let start = d[0].start_group_call(GROUP, ROW, id, &[2], me(0)).unwrap();
        let shown = deliver(&mut d, 0, start, [PLAYS, PLAYS, PLAYS]);
        assert!(shown[1].is_empty());
    }

    #[test]
    fn a_participant_whose_presence_stops_is_looked_for_then_dropped() {
        let mut d = devices();
        let id = [2; 16];
        let voice = [PLAYS, PLAYS, PLAYS];
        let start = d[0].start_group_call(GROUP, ROW, id, &[2], me(0)).unwrap();
        deliver(&mut d, 0, start, voice);
        let join = d[1].join_group_call(id, &[1], me(1)).unwrap();
        deliver(&mut d, 1, join, voice);
        d[0].unlinked(2);
        assert!(d[0].tick(1_000).actions.is_empty());
        let gone = d[0].tick(1_000 + PRESENCE_GONE_SECS);
        assert!(
            matches!(&gone.actions[..], [Action::GroupCallChanged { participants, .. }] if participants.is_empty())
        );
        assert_eq!(d[0].lost_call_members(), [2], "looked for, not given up yet");
        assert!(d[0].group_call().is_some());
        let ended = d[0].tick(1_000 + PRESENCE_GONE_SECS + 60);
        assert!(matches!(
            ended.actions[..],
            [Action::CallEnded {
                reason: EndReason::Lost,
                ..
            }]
        ));
    }

    #[test]
    fn a_call_passes_through_a_participant_to_one_out_of_the_callers_reach() {
        // Ayşe — Burak — Cem: Ayşe and Cem are not linked.
        let mut d = devices();
        let id = [3; 16];
        let voice = [PLAYS, PLAYS, PLAYS];
        let start = d[0].start_group_call(GROUP, ROW, id, &[2], me(0)).unwrap();
        deliver(&mut d, 0, start, voice);
        let join = d[1].join_group_call(id, &[1, 3], me(1)).unwrap();
        let shown = deliver(&mut d, 1, join, voice);
        assert!(
            matches!(shown[2][..], [Action::GroupCallRinging { contact: 2, .. }]),
            "Burak rings Cem"
        );
        let join = d[2].join_group_call(id, &[2], me(2)).unwrap();
        let shown = deliver(&mut d, 2, join, voice);
        assert!(
            matches!(&shown[0][..], [Action::GroupCallChanged { participants, .. }] if participants == &[2, 3]),
            "Ayşe hears of Cem through Burak"
        );
        let audio = d[0].audio(id, b"opus");
        assert_eq!(
            audio.iter().map(|(to, _)| *to).collect::<Vec<_>>(),
            [2],
            "to Burak only"
        );
        let shown = deliver(
            &mut d,
            0,
            Effects {
                send: audio,
                actions: Vec::new(),
            },
            voice,
        );
        assert!(matches!(shown[1][..], [Action::Audio { from: 1, .. }]));
        assert!(
            matches!(shown[2][..], [Action::Audio { from: 1, .. }]),
            "Cem hears Ayşe through Burak"
        );
    }

    #[test]
    fn audio_coming_round_plays_once_and_never_back_to_its_speaker() {
        let mut d = devices();
        let id = [4; 16];
        let voice = [PLAYS, PLAYS, PLAYS];
        let start = d[0].start_group_call(GROUP, ROW, id, &[2, 3], me(0)).unwrap();
        deliver(&mut d, 0, start, voice);
        for at in [1, 2] {
            let others: Vec<ContactId> = [1, 2, 3].into_iter().filter(|c| *c != at as ContactId + 1).collect();
            let join = d[at].join_group_call(id, &others, me(at)).unwrap();
            deliver(&mut d, at, join, voice);
        }
        for _ in 0..3 {
            let audio = d[0].audio(id, b"opus");
            let shown = deliver(
                &mut d,
                0,
                Effects {
                    send: audio,
                    actions: Vec::new(),
                },
                voice,
            );
            let played = |at: usize| shown[at].iter().filter(|a| matches!(a, Action::Audio { .. })).count();
            assert_eq!((played(0), played(1), played(2)), (0, 1, 1));
        }
    }

    #[test]
    fn a_window_takes_each_sequence_number_once() {
        let mut window = Window::default();
        assert!(window.take(10));
        assert!(!window.take(10));
        assert!(window.take(12) && window.take(11), "late but new");
        assert!(!window.take(11));
        assert!(window.take(200));
        assert!(!window.take(12), "too far behind");
        assert!(window.take(150) && !window.take(150));
    }
}
