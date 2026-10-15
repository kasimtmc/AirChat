//! Puts incoming audio packets back in order and paces them for playout (docs/architecture.md §6).
//!
//! The platform's playback clock asks for one packet per frame (20 ms). Playout starts once a few
//! packets are held, so late ones still make it; a lost packet comes out as [`Playout::Missing`], for
//! the decoder to conceal; when far behind, the oldest packets are dropped to catch up; and after a
//! longer gap (the other side stopped talking) the buffer fills up again before playing on.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

/// More than this many packets held means something is wrong: the oldest are dropped.
const MAX_HELD: usize = 250;
/// Concealed frames in a row before the buffer stops and fills up again.
const REBUFFER_AFTER: u32 = 5;

#[derive(Debug, PartialEq, Eq)]
pub enum Playout {
    /// The next packet: decode and play it.
    Packet(Zeroizing<Vec<u8>>),
    /// The next packet is lost or late: conceal the gap.
    Missing,
    /// Nothing to play (filling up, or the other side is silent): play silence.
    Silence,
}

pub struct JitterBuffer {
    packets: BTreeMap<u32, Zeroizing<Vec<u8>>>,
    /// The next sequence number to play; anything earlier arrived too late.
    next: Option<u32>,
    playing: bool,
    /// Packets held before playout starts.
    target: usize,
    /// Packets held beyond which the oldest are dropped.
    max: usize,
    missing_in_a_row: u32,
}

impl JitterBuffer {
    /// `target` packets are held before playing (3 = 60 ms of 20 ms frames); beyond `max`, the
    /// oldest are dropped.
    pub fn new(target: usize, max: usize) -> Self {
        Self {
            packets: BTreeMap::new(),
            next: None,
            playing: false,
            target: target.max(1),
            max: max.max(target.max(1)),
            missing_in_a_row: 0,
        }
    }

    pub fn push(&mut self, seq: u32, packet: Zeroizing<Vec<u8>>) {
        if self.next.is_some_and(|next| seq < next) {
            return;
        }
        self.packets.insert(seq, packet);
        while self.packets.len() > MAX_HELD {
            self.packets.pop_first();
        }
    }

    /// What to play for the next frame.
    pub fn pop(&mut self) -> Playout {
        if !self.playing {
            if self.packets.len() < self.target {
                return Playout::Silence;
            }
            self.playing = true;
            self.next = self.packets.keys().next().copied();
        }
        // Too far behind: drop the oldest, so the delay stays bounded.
        while self.packets.len() > self.max {
            self.packets.pop_first();
            self.next = self.packets.keys().next().copied();
        }
        let next = self.next.unwrap_or(0);
        if let Some(packet) = self.packets.remove(&next) {
            self.next = Some(next.wrapping_add(1));
            self.missing_in_a_row = 0;
            return Playout::Packet(packet);
        }
        self.missing_in_a_row += 1;
        if self.packets.is_empty() && self.missing_in_a_row > REBUFFER_AFTER {
            // A pause: fill up again before playing on. Anything older than `next` stays too late.
            self.playing = false;
            self.missing_in_a_row = 0;
            return Playout::Silence;
        }
        self.next = Some(next.wrapping_add(1));
        Playout::Missing
    }

    /// Packets waiting to be played.
    pub fn depth(&self) -> usize {
        self.packets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(seq: u32) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(seq.to_be_bytes().to_vec())
    }

    fn played(buffer: &mut JitterBuffer, frames: usize) -> Vec<Option<u32>> {
        (0..frames)
            .map(|_| match buffer.pop() {
                Playout::Packet(p) => Some(u32::from_be_bytes(p[..4].try_into().unwrap())),
                Playout::Missing => None,
                Playout::Silence => Some(u32::MAX),
            })
            .collect()
    }

    const SILENCE: Option<u32> = Some(u32::MAX);

    #[test]
    fn waits_for_the_target_then_plays_in_order_whatever_the_arrival_order() {
        let mut buffer = JitterBuffer::new(3, 10);
        buffer.push(1, packet(1));
        buffer.push(0, packet(0));
        assert_eq!(buffer.pop(), Playout::Silence, "still filling up");
        buffer.push(3, packet(3));
        buffer.push(2, packet(2));
        assert_eq!(played(&mut buffer, 4), [Some(0), Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn a_lost_packet_is_concealed_and_a_late_one_dropped() {
        let mut buffer = JitterBuffer::new(2, 10);
        for seq in [0, 1, 3, 4] {
            buffer.push(seq, packet(seq));
        }
        assert_eq!(played(&mut buffer, 2), [Some(0), Some(1)]);
        assert_eq!(buffer.pop(), Playout::Missing, "2 never came");
        buffer.push(2, packet(2));
        assert_eq!(played(&mut buffer, 2), [Some(3), Some(4)], "2 came too late");
        assert_eq!(buffer.depth(), 0);
    }

    #[test]
    fn far_behind_it_drops_the_oldest() {
        let mut buffer = JitterBuffer::new(2, 4);
        for seq in 0..10 {
            buffer.push(seq, packet(seq));
        }
        assert_eq!(played(&mut buffer, 4), [Some(6), Some(7), Some(8), Some(9)]);
    }

    #[test]
    fn after_a_pause_it_fills_up_again() {
        let mut buffer = JitterBuffer::new(2, 10);
        buffer.push(0, packet(0));
        buffer.push(1, packet(1));
        assert_eq!(played(&mut buffer, 2), [Some(0), Some(1)]);
        let gap = played(&mut buffer, REBUFFER_AFTER as usize + 1);
        assert_eq!(gap.last(), Some(&SILENCE), "stops concealing and waits");
        buffer.push(1, packet(1));
        buffer.push(40, packet(40));
        assert_eq!(
            buffer.pop(),
            Playout::Silence,
            "1 is too late; one packet is not enough"
        );
        buffer.push(41, packet(41));
        assert_eq!(played(&mut buffer, 2), [Some(40), Some(41)]);
    }
}
