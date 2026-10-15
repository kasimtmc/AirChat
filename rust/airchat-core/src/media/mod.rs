//! Voice and video calls and push-to-talk with linked contacts (rust/airchat-protocol/docs/protocol.md §8.5, §8.6).
//!
//! Signalling and audio travel as records of the link session, so they are end-to-end encrypted,
//! padded, and follow the contact when the link moves to another transport. Nothing here touches
//! the database, so calls ring and talks play while the app is locked too.
//!
//! One call at a time. Push-to-talk is half duplex per contact: while a contact talks to this
//! device, it does not talk back; when both start at once, the turn with the smaller id goes first.
//! Video: either side of an answered 1:1 call sends its camera's H.264 frames, in parts; the
//! receiving side puts them back together and asks for a key frame when one went missing.
//! Groups (voice and video): see [`group`].

mod group;

use std::collections::HashMap;

use zeroize::Zeroizing;

pub(crate) use self::group::{CallSelf, GroupVoice};
use crate::{
    chat::{ChatMessage, EndReason, MAX_VIDEO_PARTS, StreamId, VIDEO_PART_LEN, VideoHeader, VideoState},
    group::GroupId,
    node::Action,
    storage::ContactId,
};

/// How long an outgoing call rings before it is given up.
pub const RING_SECS: u64 = 45;
/// How long a call survives without a link to the contact (it goes on over the next link).
pub const LINK_GRACE_SECS: u64 = 20;
/// An incoming talk that has been silent this long is over (its end was lost with the link).
pub const TALK_SILENCE_SECS: u64 = 5;
/// While no key frame came after one was asked for, the request is repeated this often.
pub const KEY_FRAME_RETRY_SECS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    #[error("already in a call")]
    Busy,
    #[error("the contact is talking")]
    FloorTaken,
    #[error("no such call or talk")]
    NoSuchStream,
    #[error("a video frame is larger than {} bytes", MAX_VIDEO_PARTS as usize * VIDEO_PART_LEN)]
    FrameTooLarge,
}

/// What the media logic wants done: records to send to contacts, and actions for the platform.
#[derive(Default)]
pub(crate) struct Effects {
    pub send: Vec<(ContactId, ChatMessage)>,
    pub actions: Vec<Action>,
}

impl Effects {
    fn send(mut self, contact: ContactId, message: ChatMessage) -> Self {
        self.send.push((contact, message));
        self
    }

    fn action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    fn extend(&mut self, other: Effects) {
        self.send.extend(other.send);
        self.actions.extend(other.actions);
    }
}

struct Call {
    id: StreamId,
    contact: ContactId,
    outgoing: bool,
    answered: bool,
    /// When it started ringing; 0 until the next tick notes the time.
    ringing_since: u64,
    /// When the link to the contact went away; `Some(0)` until the next tick notes the time.
    unlinked_since: Option<u64>,
    next_seq: u32,
    /// This device's camera; the contact hears of it once the call is answered.
    camera: VideoState,
    next_frame: u32,
    incoming: IncomingVideo,
}

/// The contact's video in a call: the frame being put together, and whether frames are skipped
/// until a key frame.
#[derive(Default)]
struct IncomingVideo {
    frame: Option<Assembly>,
    last_frame: Option<u32>,
    /// A frame went missing: later frames cannot be decoded before a key frame.
    awaiting_key: bool,
    /// When a key frame was last asked for; 0 until the next tick notes the time.
    asked_at: u64,
}

/// A frame put back together: its header and its H.264 bytes.
type Frame = (VideoHeader, Zeroizing<Vec<u8>>);

struct Assembly {
    header: VideoHeader,
    parts: u8,
    next_part: u8,
    data: Zeroizing<Vec<u8>>,
}

impl Call {
    fn new(id: StreamId, contact: ContactId, outgoing: bool) -> Self {
        Self {
            id,
            contact,
            outgoing,
            answered: false,
            ringing_since: 0,
            unlinked_since: None,
            next_seq: 0,
            camera: VideoState::Off,
            next_frame: 0,
            incoming: IncomingVideo::default(),
        }
    }

    /// Records that tell the contact about this device's camera, once the call is answered.
    fn camera_news(&self) -> Option<ChatMessage> {
        (self.answered && self.camera != VideoState::Off).then_some(ChatMessage::VideoState {
            id: self.id,
            state: self.camera,
        })
    }
}

impl IncomingVideo {
    /// Drops what is being put together and skips frames until a key frame. Returns whether to
    /// ask for one now (not again while waiting; the tick repeats the request).
    fn lose(&mut self) -> bool {
        self.frame = None;
        let ask = !self.awaiting_key;
        if ask {
            self.awaiting_key = true;
            self.asked_at = 0;
        }
        ask
    }

    /// One part of a frame; returns the frame once complete, and whether to ask for a key frame.
    fn part(&mut self, header: VideoHeader, part: u8, parts: u8, data: Zeroizing<Vec<u8>>) -> (Option<Frame>, bool) {
        let mut ask = false;
        if part == 0 {
            // A new frame: one still unfinished is lost, and so are skipped frames before a
            // frame that is not a key frame.
            let skipped = self.last_frame.is_some_and(|last| header.frame != last.wrapping_add(1));
            if self.frame.is_some() || (skipped && !header.key) {
                ask = self.lose();
            }
            if header.key {
                self.awaiting_key = false;
            }
            if self.awaiting_key {
                return (None, ask);
            }
            self.frame = Some(Assembly {
                header,
                parts,
                next_part: 0,
                data: Zeroizing::new(Vec::with_capacity(usize::from(parts) * VIDEO_PART_LEN)),
            });
        }
        let Some(frame) = self
            .frame
            .as_mut()
            .filter(|f| f.header == header && f.parts == parts && f.next_part == part)
        else {
            // A part out of place: its frame is lost (unless frames are skipped anyway).
            if !self.awaiting_key {
                ask |= self.lose();
            }
            return (None, ask);
        };
        frame.data.extend_from_slice(&data);
        frame.next_part += 1;
        if frame.next_part < frame.parts {
            return (None, ask);
        }
        let frame = self.frame.take().expect("just put together");
        self.last_frame = Some(frame.header.frame);
        (Some((frame.header, frame.data)), ask)
    }
}

/// How many parts a frame travels in (§8.6).
fn frame_parts(frame: &[u8]) -> Result<u8, MediaError> {
    u8::try_from(frame.len().div_ceil(VIDEO_PART_LEN).max(1))
        .ok()
        .filter(|p| *p <= MAX_VIDEO_PARTS)
        .ok_or(MediaError::FrameTooLarge)
}

struct TalkOut {
    id: StreamId,
    contact: ContactId,
    next_seq: u32,
}

struct TalkIn {
    id: StreamId,
    /// When audio was last heard; 0 until the next tick notes the time.
    heard_at: u64,
}

#[derive(Default)]
pub(crate) struct Media {
    call: Option<Call>,
    talks_out: HashMap<ContactId, TalkOut>,
    talks_in: HashMap<ContactId, TalkIn>,
    group_call: Option<group::GroupCall>,
    group_talks_out: HashMap<GroupId, group::GroupTalkOut>,
    group_talks_in: HashMap<GroupId, group::GroupTalkIn>,
    /// The group call this device left last: it does not ring again.
    left_group_call: Option<StreamId>,
}

/// What the contact may do, as far as media is concerned.
pub(crate) struct Allowed {
    pub calls: bool,
    pub instant_voice: bool,
}

impl Media {
    /// Whether a call or talk with the contact is under way: bulk transfers then hold back so audio
    /// is not stuck behind them.
    pub fn active_with(&self, contact: ContactId) -> bool {
        self.call.as_ref().is_some_and(|c| c.contact == contact)
            || self.talks_out.contains_key(&contact)
            || self.talks_in.contains_key(&contact)
            || self.group_active_with(contact)
    }

    /// The contact of the 1:1 call under way whose link went away, and whether this device's camera
    /// is on in it (a path for video is looked for then).
    pub fn call_waiting_for_link(&self) -> Option<(ContactId, bool)> {
        self.call
            .as_ref()
            .filter(|c| c.answered && c.unlinked_since.is_some())
            .map(|c| (c.contact, c.camera != VideoState::Off))
    }

    /// The contact of 1:1 call `id`, while it lasts.
    pub fn call_contact(&self, id: StreamId) -> Option<ContactId> {
        self.call.as_ref().filter(|c| c.id == id).map(|c| c.contact)
    }

    /// In a call: a 1:1 one, or a group call this device is in.
    fn in_call(&self) -> bool {
        self.call.is_some() || self.in_group_call()
    }

    pub fn start_call(&mut self, contact: ContactId, id: StreamId, video: bool) -> Result<Effects, MediaError> {
        if self.call.is_some() || self.group_call.is_some() {
            return Err(MediaError::Busy);
        }
        self.call = Some(Call::new(id, contact, true));
        Ok(Effects::default().send(contact, ChatMessage::CallOffer { id, video }))
    }

    pub fn answer_call(&mut self, id: StreamId) -> Result<Effects, MediaError> {
        let call = self
            .call
            .as_mut()
            .filter(|c| c.id == id && !c.outgoing && !c.answered)
            .ok_or(MediaError::NoSuchStream)?;
        call.answered = true;
        let mut effects = Effects::default().send(call.contact, ChatMessage::CallAccept { id });
        if let Some(news) = call.camera_news() {
            effects = effects.send(call.contact, news);
        }
        Ok(effects)
    }

    /// This device's camera in a 1:1 call: on, off, or paused (on, but the link is too slow or the
    /// camera cannot be used now). The contact hears of it once the call is answered.
    pub fn set_camera(&mut self, id: StreamId, state: VideoState) -> Result<Effects, MediaError> {
        let Some(call) = self.call.as_mut().filter(|c| c.id == id) else {
            return self.set_group_camera(id, state);
        };
        if call.camera == state {
            return Ok(Effects::default());
        }
        call.camera = state;
        Ok(match call.answered {
            true => Effects::default().send(call.contact, ChatMessage::VideoState { id, state }),
            false => Effects::default(),
        })
    }

    /// An encoded frame of this device's camera for a 1:1 call under way, as records: nothing
    /// unless the call is answered and the camera on. Frames may be skipped only before a key frame
    /// (§8.6), so the receiver can tell a lost frame from a skipped one.
    pub fn video(
        &mut self,
        stream: StreamId,
        key: bool,
        rotation: u8,
        size: (u16, u16),
        frame: &[u8],
    ) -> Result<Vec<(ContactId, ChatMessage)>, MediaError> {
        if let Some(records) = self.group_video_out(stream, key, rotation, size, frame) {
            return records;
        }
        let call = self
            .call
            .as_mut()
            .filter(|c| c.id == stream && c.answered && c.camera == VideoState::On)
            .ok_or(MediaError::NoSuchStream)?;
        let parts = frame_parts(frame)?;
        let header = VideoHeader {
            frame: call.next_frame,
            key,
            rotation,
            width: size.0,
            height: size.1,
        };
        call.next_frame = call.next_frame.wrapping_add(1);
        Ok(frame
            .chunks(VIDEO_PART_LEN)
            .enumerate()
            .map(|(part, data)| {
                let message = ChatMessage::Video {
                    stream,
                    header,
                    part: part as u8,
                    parts,
                    data: Zeroizing::new(data.to_vec()),
                };
                (call.contact, message)
            })
            .collect())
    }

    /// The platform cannot decode the contact's video from here on (say, its decoder restarted):
    /// skip frames until a key frame, and ask the contact for one.
    pub fn request_key_frame(&mut self, stream: StreamId) -> Result<Effects, MediaError> {
        let call = self
            .call
            .as_mut()
            .filter(|c| c.id == stream && c.answered)
            .ok_or(MediaError::NoSuchStream)?;
        call.incoming.lose();
        call.incoming.asked_at = 0;
        Ok(Effects::default().send(call.contact, ChatMessage::KeyFrameRequest { id: stream }))
    }

    /// Hangs up or cancels the call, or declines it while it rings here; leaves a group call.
    pub fn hang_up(&mut self, id: StreamId) -> Effects {
        if self.group_call_row(id).is_some() {
            let reason = if self.in_group_call() {
                EndReason::HungUp
            } else {
                EndReason::Declined
            };
            return self.leave_group_call(id, reason).unwrap_or_default();
        }
        let ringing_here = self
            .call
            .as_ref()
            .is_some_and(|c| c.id == id && !c.outgoing && !c.answered);
        self.end_call(
            id,
            if ringing_here {
                EndReason::Declined
            } else {
                EndReason::HungUp
            },
        )
    }

    fn end_call(&mut self, id: StreamId, reason: EndReason) -> Effects {
        match self.call.take_if(|c| c.id == id) {
            Some(call) => Effects::default()
                .send(call.contact, ChatMessage::CallEnd { id, reason })
                .action(Action::CallEnded { id, reason }),
            None => Effects::default(),
        }
    }

    pub fn start_talk(&mut self, contact: ContactId, id: StreamId) -> Result<Effects, MediaError> {
        if self.in_call() {
            return Err(MediaError::Busy);
        }
        if self.talks_in.contains_key(&contact) {
            return Err(MediaError::FloorTaken);
        }
        let mut effects = Effects::default();
        if let Some(old) = self.talks_out.remove(&contact) {
            effects = effects.send(
                contact,
                ChatMessage::TalkEnd {
                    id: old.id,
                    reason: EndReason::HungUp,
                },
            );
        }
        self.talks_out.insert(
            contact,
            TalkOut {
                id,
                contact,
                next_seq: 0,
            },
        );
        Ok(effects.send(contact, ChatMessage::TalkStart { id }))
    }

    pub fn end_talk(&mut self, id: StreamId) -> Effects {
        let Some(contact) = self.talks_out.values().find(|t| t.id == id).map(|t| t.contact) else {
            return self.end_group_talk(id).unwrap_or_default();
        };
        self.talks_out.remove(&contact);
        Effects::default()
            .send(
                contact,
                ChatMessage::TalkEnd {
                    id,
                    reason: EndReason::HungUp,
                },
            )
            .action(Action::TalkEnded {
                id,
                reason: EndReason::HungUp,
            })
    }

    /// A packet of this device's audio for a call under way or a talk: where it goes, as records.
    pub fn audio(&mut self, stream: StreamId, packet: &[u8]) -> Vec<(ContactId, ChatMessage)> {
        let (contact, seq) = if let Some(call) = self.call.as_mut().filter(|c| c.id == stream && c.answered) {
            (call.contact, &mut call.next_seq)
        } else if let Some(talk) = self.talks_out.values_mut().find(|t| t.id == stream) {
            (talk.contact, &mut talk.next_seq)
        } else {
            return self.group_audio_out(stream, packet).unwrap_or_default();
        };
        let message = ChatMessage::Audio {
            stream,
            seq: *seq,
            packet: Zeroizing::new(packet.to_vec()),
        };
        *seq = seq.wrapping_add(1);
        vec![(contact, message)]
    }

    /// A media record from a contact.
    pub fn receive(&mut self, contact: ContactId, message: ChatMessage, allowed: Allowed) -> Effects {
        let effects = Effects::default();
        match message {
            ChatMessage::CallOffer { id, video } => {
                if !allowed.calls {
                    return effects.send(
                        contact,
                        ChatMessage::CallEnd {
                            id,
                            reason: EndReason::NotAllowed,
                        },
                    );
                }
                if self.call.as_ref().is_some_and(|c| c.id == id && c.contact == contact) {
                    // A resend of the offer ringing here already.
                    return effects;
                }
                if self.call.is_some() || self.group_call.is_some() {
                    return effects.send(
                        contact,
                        ChatMessage::CallEnd {
                            id,
                            reason: EndReason::Busy,
                        },
                    );
                }
                // An incoming call takes over from push-to-talk with anyone.
                let mut effects = self.end_talks(EndReason::Interrupted);
                self.call = Some(Call::new(id, contact, false));
                effects.send.push((contact, ChatMessage::Ringing { id }));
                effects.actions.push(Action::CallRinging { id, contact, video });
                effects
            }
            ChatMessage::Ringing { id } => match &self.call {
                Some(call) if call.id == id && call.contact == contact && call.outgoing && !call.answered => {
                    effects.action(Action::CallReached { id })
                }
                _ => effects,
            },
            ChatMessage::CallAccept { id } => match self.call.as_mut() {
                Some(call) if call.id == id && call.contact == contact && call.outgoing && !call.answered => {
                    call.answered = true;
                    let effects = effects.action(Action::CallAccepted { id });
                    match call.camera_news() {
                        Some(news) => effects.send(contact, news),
                        None => effects,
                    }
                }
                _ => effects,
            },
            ChatMessage::VideoState { id, state } => match self.answered_call(id, contact) {
                Some(call) => {
                    if state != VideoState::On {
                        call.incoming.frame = None;
                    }
                    effects.action(Action::VideoStateChanged {
                        id,
                        from: contact,
                        state,
                    })
                }
                None => effects,
            },
            ChatMessage::Video {
                stream,
                header,
                part,
                parts,
                data,
            } => {
                let Some(call) = self.answered_call(stream, contact) else {
                    return effects;
                };
                let (frame, ask) = call.incoming.part(header, part, parts, data);
                let mut effects = effects;
                if ask {
                    effects = effects.send(contact, ChatMessage::KeyFrameRequest { id: stream });
                }
                match frame {
                    Some((header, data)) => effects.action(Action::Video {
                        stream,
                        from: contact,
                        key: header.key,
                        rotation: header.rotation,
                        width: header.width,
                        height: header.height,
                        frame: data,
                    }),
                    None => effects,
                }
            }
            ChatMessage::KeyFrameRequest { id } => match self.answered_call(id, contact) {
                Some(call) if call.camera == VideoState::On => effects.action(Action::KeyFrameRequested { id }),
                _ => effects,
            },
            ChatMessage::CallEnd { id, reason } => match self.call.take_if(|c| c.id == id && c.contact == contact) {
                Some(_) => effects.action(Action::CallEnded { id, reason }),
                None => effects,
            },
            ChatMessage::TalkStart { id } => {
                if !allowed.instant_voice || self.in_call() {
                    let reason = if allowed.instant_voice {
                        EndReason::Busy
                    } else {
                        EndReason::NotAllowed
                    };
                    return effects.send(contact, ChatMessage::TalkEnd { id, reason });
                }
                let mut effects = effects;
                if let Some(ours) = self.talks_out.get(&contact) {
                    // Both pressed at once: the smaller id talks first. The larger one stops; its
                    // device learns of the other turn the same way and stops too.
                    if ours.id < id {
                        return effects;
                    }
                    let ours = ours.id;
                    self.talks_out.remove(&contact);
                    effects = effects
                        .send(
                            contact,
                            ChatMessage::TalkEnd {
                                id: ours,
                                reason: EndReason::Interrupted,
                            },
                        )
                        .action(Action::TalkEnded {
                            id: ours,
                            reason: EndReason::Interrupted,
                        });
                }
                if let Some(old) = self.talks_in.insert(contact, TalkIn { id, heard_at: 0 })
                    && old.id != id
                {
                    effects = effects.action(Action::TalkEnded {
                        id: old.id,
                        reason: EndReason::HungUp,
                    });
                }
                effects.action(Action::TalkStarted { id, contact })
            }
            ChatMessage::TalkEnd { id, reason } => {
                if self.talks_in.get(&contact).is_some_and(|t| t.id == id) {
                    self.talks_in.remove(&contact);
                    return effects.action(Action::TalkEnded { id, reason });
                }
                // The contact turned this device's talk down, or went first.
                if self.talks_out.get(&contact).is_some_and(|t| t.id == id) {
                    self.talks_out.remove(&contact);
                    return effects.action(Action::TalkEnded { id, reason });
                }
                self.group_talk_end(contact, id, reason).unwrap_or(effects)
            }
            ChatMessage::Audio { stream, seq, packet } => {
                let playing = self
                    .call
                    .as_ref()
                    .is_some_and(|c| c.id == stream && c.contact == contact && c.answered);
                let talking = self.talks_in.get_mut(&contact).filter(|t| t.id == stream);
                let heard = playing || talking.is_some();
                if let Some(talk) = talking {
                    talk.heard_at = 0;
                }
                if !heard && !self.group_audio_in(contact, stream) {
                    return effects;
                }
                effects.action(Action::Audio {
                    stream,
                    from: contact,
                    seq,
                    packet,
                })
            }
            _ => effects,
        }
    }

    /// The answered 1:1 call `id` with `contact`.
    fn answered_call(&mut self, id: StreamId, contact: ContactId) -> Option<&mut Call> {
        self.call
            .as_mut()
            .filter(|c| c.id == id && c.contact == contact && c.answered)
    }

    /// The link to the contact is up again; a call goes on over it.
    pub fn linked(&mut self, contact: ContactId) {
        if let Some(call) = self.call.as_mut().filter(|c| c.contact == contact) {
            call.unlinked_since = None;
        }
        self.group_linked(contact);
    }

    /// The link to the contact is gone: a call waits a while for the next one; talks end.
    pub fn unlinked(&mut self, contact: ContactId) -> Effects {
        if let Some(call) = self.call.as_mut().filter(|c| c.contact == contact) {
            call.unlinked_since.get_or_insert(0);
        }
        let mut effects = Effects::default();
        if let Some(talk) = self.talks_out.remove(&contact) {
            effects = effects.action(Action::TalkEnded {
                id: talk.id,
                reason: EndReason::Lost,
            });
        }
        if let Some(talk) = self.talks_in.remove(&contact) {
            effects = effects.action(Action::TalkEnded {
                id: talk.id,
                reason: EndReason::Lost,
            });
        }
        effects.extend(self.group_unlinked(contact));
        effects
    }

    /// Ends everything with a contact that was blocked or deleted.
    pub fn forget(&mut self, contact: ContactId) -> Effects {
        let mut effects = self.unlinked(contact);
        effects.extend(self.group_forget(contact));
        if let Some(call) = self.call.take_if(|c| c.contact == contact) {
            effects.actions.push(Action::CallEnded {
                id: call.id,
                reason: EndReason::HungUp,
            });
        }
        effects
    }

    fn end_talks(&mut self, reason: EndReason) -> Effects {
        let mut effects = Effects::default();
        for (contact, talk) in self.talks_out.drain() {
            effects
                .send
                .push((contact, ChatMessage::TalkEnd { id: talk.id, reason }));
            effects.actions.push(Action::TalkEnded { id: talk.id, reason });
        }
        for (_, talk) in self.talks_in.drain() {
            effects.actions.push(Action::TalkEnded { id: talk.id, reason });
        }
        effects.extend(self.end_group_talks(reason));
        effects
    }

    /// Gives up calls that ring or wait for a link too long, and talks gone silent.
    pub fn tick(&mut self, now_secs: u64) -> Effects {
        let mut effects = Effects::default();
        let stamp = |at: &mut u64| {
            if *at == 0 {
                *at = now_secs.max(1);
            }
            now_secs.saturating_sub(*at)
        };
        if let Some(call) = self.call.as_mut() {
            let ringing = if call.answered {
                0
            } else {
                stamp(&mut call.ringing_since)
            };
            let unlinked = call.unlinked_since.as_mut().map_or(0, stamp);
            let reason = if !call.answered && ringing >= RING_SECS {
                Some(EndReason::NoAnswer)
            } else if unlinked >= LINK_GRACE_SECS {
                Some(EndReason::Lost)
            } else {
                None
            };
            let incoming = &mut call.incoming;
            if incoming.awaiting_key && stamp(&mut incoming.asked_at) >= KEY_FRAME_RETRY_SECS {
                incoming.asked_at = 0;
                effects
                    .send
                    .push((call.contact, ChatMessage::KeyFrameRequest { id: call.id }));
            }
            if let Some(reason) = reason {
                let id = call.id;
                effects.extend(self.end_call(id, reason));
            }
        }
        let silent: Vec<ContactId> = self
            .talks_in
            .iter_mut()
            .filter_map(|(contact, talk)| (stamp(&mut talk.heard_at) >= TALK_SILENCE_SECS).then_some(*contact))
            .collect();
        for contact in silent {
            if let Some(talk) = self.talks_in.remove(&contact) {
                effects.actions.push(Action::TalkEnded {
                    id: talk.id,
                    reason: EndReason::Lost,
                });
            }
        }
        effects.extend(self.group_tick(&stamp));
        effects
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED: Allowed = Allowed {
        calls: true,
        instant_voice: true,
    };

    fn sent(effects: &Effects) -> Vec<&ChatMessage> {
        effects.send.iter().map(|(_, m)| m).collect()
    }

    #[test]
    fn a_call_rings_is_answered_carries_audio_and_ends() {
        let (mut alice, mut bob) = (Media::default(), Media::default());
        let id = [1; 16];
        let offer = alice.start_call(7, id, false).unwrap();
        assert_eq!(sent(&offer), [&ChatMessage::CallOffer { id, video: false }]);
        assert!(alice.audio(id, b"x").is_empty(), "no audio before the call is answered");

        let ringing = bob.receive(3, ChatMessage::CallOffer { id, video: false }, ALLOWED);
        assert!(matches!(ringing.actions[..], [Action::CallRinging { contact: 3, .. }]));
        let reached = alice.receive(7, ringing.send[0].1.clone(), ALLOWED);
        assert!(matches!(reached.actions[..], [Action::CallReached { .. }]));
        let accept = bob.answer_call(id).unwrap();
        let accepted = alice.receive(7, accept.send[0].1.clone(), ALLOWED);
        assert!(matches!(accepted.actions[..], [Action::CallAccepted { .. }]));

        let (to, packet) = alice.audio(id, b"opus").remove(0);
        assert_eq!(to, 7);
        let heard = bob.receive(3, packet, ALLOWED);
        assert!(matches!(&heard.actions[..], [Action::Audio { seq: 0, packet, .. }] if packet.as_slice() == b"opus"));
        let (_, second) = alice.audio(id, b"more").remove(0);
        assert!(matches!(second, ChatMessage::Audio { seq: 1, .. }));
        assert!(bob.active_with(3) && alice.active_with(7));

        let hang_up = bob.hang_up(id);
        let ended = alice.receive(7, hang_up.send[0].1.clone(), ALLOWED);
        assert!(matches!(
            ended.actions[..],
            [Action::CallEnded {
                reason: EndReason::HungUp,
                ..
            }]
        ));
        assert!(!alice.active_with(7) && !bob.active_with(3));
    }

    #[test]
    fn calls_are_refused_without_permission_and_busy_during_another() {
        let mut bob = Media::default();
        let no = bob.receive(
            3,
            ChatMessage::CallOffer {
                id: [1; 16],
                video: false,
            },
            Allowed {
                calls: false,
                instant_voice: true,
            },
        );
        assert_eq!(
            sent(&no),
            [&ChatMessage::CallEnd {
                id: [1; 16],
                reason: EndReason::NotAllowed
            }]
        );
        assert!(no.actions.is_empty(), "it does not ring");

        bob.receive(
            3,
            ChatMessage::CallOffer {
                id: [1; 16],
                video: false,
            },
            ALLOWED,
        );
        let second = bob.receive(
            4,
            ChatMessage::CallOffer {
                id: [2; 16],
                video: false,
            },
            ALLOWED,
        );
        assert_eq!(
            sent(&second),
            [&ChatMessage::CallEnd {
                id: [2; 16],
                reason: EndReason::Busy
            }]
        );
        assert_eq!(bob.start_call(5, [3; 16], false).err(), Some(MediaError::Busy));
        let declined = bob.hang_up([1; 16]);
        assert_eq!(
            sent(&declined),
            [&ChatMessage::CallEnd {
                id: [1; 16],
                reason: EndReason::Declined
            }]
        );
    }

    #[test]
    fn unanswered_calls_give_up_and_calls_wait_a_while_for_the_link() {
        let mut alice = Media::default();
        alice.start_call(7, [1; 16], false).unwrap();
        assert!(alice.tick(100).actions.is_empty());
        let gave_up = alice.tick(100 + RING_SECS);
        assert_eq!(
            sent(&gave_up),
            [&ChatMessage::CallEnd {
                id: [1; 16],
                reason: EndReason::NoAnswer
            }]
        );

        let mut bob = Media::default();
        bob.receive(
            3,
            ChatMessage::CallOffer {
                id: [2; 16],
                video: false,
            },
            ALLOWED,
        );
        bob.answer_call([2; 16]).unwrap();
        bob.unlinked(3);
        assert!(bob.tick(200).actions.is_empty());
        bob.linked(3);
        assert!(
            bob.tick(200 + LINK_GRACE_SECS).actions.is_empty(),
            "the link came back in time"
        );
        bob.unlinked(3);
        bob.tick(300);
        let lost = bob.tick(300 + LINK_GRACE_SECS);
        assert!(matches!(
            lost.actions[..],
            [Action::CallEnded {
                reason: EndReason::Lost,
                ..
            }]
        ));
    }

    #[test]
    fn talks_play_only_with_permission_and_the_smaller_id_goes_first() {
        let mut bob = Media::default();
        let no = bob.receive(
            3,
            ChatMessage::TalkStart { id: [5; 16] },
            Allowed {
                calls: true,
                instant_voice: false,
            },
        );
        assert_eq!(
            sent(&no),
            [&ChatMessage::TalkEnd {
                id: [5; 16],
                reason: EndReason::NotAllowed
            }]
        );

        // Both press at once: Bob's turn has the smaller id and goes on, Alice's stops.
        let (mut alice, mut bob) = (Media::default(), Media::default());
        alice.start_talk(7, [9; 16]).unwrap();
        bob.start_talk(3, [4; 16]).unwrap();
        let at_bob = bob.receive(3, ChatMessage::TalkStart { id: [9; 16] }, ALLOWED);
        assert!(at_bob.send.is_empty() && at_bob.actions.is_empty(), "Bob keeps talking");
        let at_alice = alice.receive(7, ChatMessage::TalkStart { id: [4; 16] }, ALLOWED);
        assert!(at_alice.actions.iter().any(|a| matches!(
            a,
            Action::TalkEnded {
                reason: EndReason::Interrupted,
                ..
            }
        )));
        assert!(
            at_alice
                .actions
                .iter()
                .any(|a| matches!(a, Action::TalkStarted { contact: 7, .. }))
        );
        assert!(alice.audio([9; 16], b"x").is_empty(), "Alice's turn is over");
        assert!(!bob.audio([4; 16], b"x").is_empty());
        assert_eq!(alice.start_talk(7, [10; 16]).err(), Some(MediaError::FloorTaken));
    }

    #[test]
    fn a_talk_gone_silent_ends() {
        let mut bob = Media::default();
        bob.receive(3, ChatMessage::TalkStart { id: [5; 16] }, ALLOWED);
        bob.tick(10);
        let audio = ChatMessage::Audio {
            stream: [5; 16],
            seq: 0,
            packet: Zeroizing::new(vec![1]),
        };
        bob.receive(3, audio, ALLOWED);
        assert!(
            bob.tick(10 + TALK_SILENCE_SECS).actions.is_empty(),
            "audio arrived meanwhile"
        );
        let over = bob.tick(10 + 2 * TALK_SILENCE_SECS + 1);
        assert!(matches!(
            over.actions[..],
            [Action::TalkEnded {
                reason: EndReason::Lost,
                ..
            }]
        ));
    }

    /// Alice calls Bob (contact 7 to her, she is 3 to him) as a video call; Bob answers.
    fn video_call() -> (Media, Media, StreamId) {
        let (mut alice, mut bob) = (Media::default(), Media::default());
        let id = [5; 16];
        let offer = alice.start_call(7, id, true).unwrap();
        alice.set_camera(id, VideoState::On).unwrap();
        assert!(sent(&offer) == [&ChatMessage::CallOffer { id, video: true }]);
        let ringing = bob.receive(3, offer.send[0].1.clone(), ALLOWED);
        assert!(matches!(ringing.actions[..], [Action::CallRinging { video: true, .. }]));
        let answer = bob.answer_call(id).unwrap();
        let accepted = alice.receive(7, answer.send[0].1.clone(), ALLOWED);
        assert_eq!(
            sent(&accepted),
            [&ChatMessage::VideoState {
                id,
                state: VideoState::On
            }],
            "the camera, on before the answer, is announced with it"
        );
        let heard = bob.receive(3, accepted.send[0].1.clone(), ALLOWED);
        assert!(matches!(
            heard.actions[..],
            [Action::VideoStateChanged {
                state: VideoState::On,
                ..
            }]
        ));
        (alice, bob, id)
    }

    fn frame(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Hands Alice's records to Bob; returns the frames he puts together and what he sends back.
    fn deliver(bob: &mut Media, records: Vec<(ContactId, ChatMessage)>) -> (Vec<Vec<u8>>, Vec<ChatMessage>) {
        let (mut frames, mut back) = (Vec::new(), Vec::new());
        for (to, record) in records {
            assert_eq!(to, 7);
            let effects = bob.receive(3, record, ALLOWED);
            back.extend(effects.send.into_iter().map(|(_, m)| m));
            for action in effects.actions {
                if let Action::Video { frame, .. } = action {
                    frames.push(frame.to_vec());
                }
            }
        }
        (frames, back)
    }

    #[test]
    fn video_frames_travel_in_parts_and_come_back_whole() {
        let (mut alice, mut bob, id) = video_call();
        let key = frame(VIDEO_PART_LEN * 2 + 100, 1);
        let records = alice.video(id, true, 1, (1280, 720), &key).unwrap();
        assert_eq!(records.len(), 3);
        let (frames, back) = deliver(&mut bob, records);
        assert_eq!((frames, back), (vec![key], vec![]));

        let small = frame(900, 2);
        let records = alice.video(id, false, 1, (1280, 720), &small).unwrap();
        let effects = bob.receive(3, records[0].1.clone(), ALLOWED);
        assert!(matches!(
            &effects.actions[..],
            [Action::Video { key: false, rotation: 1, width: 1280, height: 720, frame, .. }] if **frame == small
        ));

        assert_eq!(
            alice
                .video(id, false, 0, (1280, 720), &frame(VIDEO_PART_LEN * 64 + 1, 3))
                .err(),
            Some(MediaError::FrameTooLarge)
        );
        alice.set_camera(id, VideoState::Paused).unwrap();
        assert!(
            alice.video(id, false, 0, (1280, 720), &small).is_err(),
            "nothing while paused"
        );
    }

    #[test]
    fn no_video_before_the_answer_or_with_the_camera_off() {
        let (mut alice, mut bob) = (Media::default(), Media::default());
        let id = [6; 16];
        alice.start_call(7, id, false).unwrap();
        assert!(
            alice.set_camera(id, VideoState::On).unwrap().send.is_empty(),
            "not answered yet"
        );
        assert_eq!(
            alice.video(id, true, 0, (640, 480), b"x").err(),
            Some(MediaError::NoSuchStream)
        );
        bob.receive(3, ChatMessage::CallOffer { id, video: false }, ALLOWED);
        let answer = bob.answer_call(id).unwrap();
        alice.receive(7, answer.send[0].1.clone(), ALLOWED);
        assert_eq!(alice.video(id, true, 0, (640, 480), b"x").unwrap().len(), 1);
        let off = alice.set_camera(id, VideoState::Off).unwrap();
        assert_eq!(
            sent(&off),
            [&ChatMessage::VideoState {
                id,
                state: VideoState::Off
            }]
        );
        assert!(alice.video(id, true, 0, (640, 480), b"x").is_err());

        // Video for a call that is not under way, or from someone else, is dropped.
        let stray = ChatMessage::Video {
            stream: [9; 16],
            header: VideoHeader {
                frame: 0,
                key: true,
                rotation: 0,
                width: 640,
                height: 480,
            },
            part: 0,
            parts: 1,
            data: Zeroizing::new(vec![1]),
        };
        assert!(bob.receive(3, stray, ALLOWED).actions.is_empty());
    }

    #[test]
    fn a_lost_frame_skips_video_until_a_key_frame_that_is_asked_for() {
        let (mut alice, mut bob, id) = video_call();
        let send = |alice: &mut Media, key: bool, seed: u8| {
            alice
                .video(id, key, 0, (1280, 720), &frame(VIDEO_PART_LEN + 10, seed))
                .unwrap()
        };
        let (frames, _) = deliver(&mut bob, send(&mut alice, true, 1));
        assert_eq!(frames.len(), 1);

        // The second part of the next frame is lost (say, the link moved mid-frame).
        let mut lost = send(&mut alice, false, 2);
        lost.pop();
        let (frames, back) = deliver(&mut bob, lost);
        assert!(frames.is_empty());
        assert!(back.is_empty(), "the loss shows only when the next frame begins");
        let (frames, back) = deliver(&mut bob, send(&mut alice, false, 3));
        assert!(frames.is_empty(), "undecodable without the lost frame");
        assert_eq!(back, [ChatMessage::KeyFrameRequest { id }]);
        let request = alice.receive(7, back[0].clone(), ALLOWED);
        assert!(matches!(request.actions[..], [Action::KeyFrameRequested { .. }]));

        let (frames, back) = deliver(&mut bob, send(&mut alice, false, 4));
        assert!(frames.is_empty() && back.is_empty(), "asked once while waiting");
        let retry = bob.tick(100);
        assert!(retry.send.is_empty(), "the tick notes the time first");
        let retry = bob.tick(100 + KEY_FRAME_RETRY_SECS);
        assert_eq!(sent(&retry), [&ChatMessage::KeyFrameRequest { id }]);

        let (frames, back) = deliver(&mut bob, send(&mut alice, true, 5));
        assert_eq!((frames.len(), back.len()), (1, 0));
        let (frames, _) = deliver(&mut bob, send(&mut alice, false, 6));
        assert_eq!(frames.len(), 1, "back to normal after the key frame");
        assert!(bob.tick(200).send.is_empty() && bob.tick(300).send.is_empty());

        // Frames the sender skipped before a key frame are no loss.
        alice.video(id, false, 0, (1280, 720), b"skipped").unwrap();
        let (frames, back) = deliver(&mut bob, send(&mut alice, true, 7));
        assert_eq!((frames.len(), back.len()), (1, 0));

        // A new decoder on Bob's side asks for a key frame itself.
        let asked = bob.request_key_frame(id).unwrap();
        assert_eq!(sent(&asked), [&ChatMessage::KeyFrameRequest { id }]);
        let (frames, _) = deliver(&mut bob, send(&mut alice, false, 8));
        assert!(frames.is_empty());
    }
}
