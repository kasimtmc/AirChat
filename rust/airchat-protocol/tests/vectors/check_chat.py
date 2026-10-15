#!/usr/bin/env python3
"""Independent check of the chat message test vector (docs/protocol.md §8.1, §8.3 to §8.5, §9.5, §9.6).

Encodes every message kind from the specification alone and compares it with the vector. Needs only
the standard library.

    python3 check_chat.py
"""

import hashlib
import json
import pathlib
import sys

here = pathlib.Path(__file__).parent
failures = 0

# §8.4: chunk length, and the limits on what a file offer carries.
CHUNK_LEN = 15360


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")


def u8(n):
    return n.to_bytes(1, "big")


def u16(n):
    return n.to_bytes(2, "big")


def u64(n):
    return n.to_bytes(8, "big")


v = json.loads((here / "chat_messages.json").read_text())
print("chat_messages.json")
mid = bytes.fromhex(v["message_id"])
sent_at = int(v["sent_at_ms"])

# §8.1: kind || body.
check("text", (u8(0x01) + mid + u64(sent_at) + "Merhaba 👋".encode()).hex(), v["text"])
check("ack", (u8(0x02) + mid).hex(), v["ack"])
check("refused", (u8(0x05) + mid).hex(), v["refused"])
check("ping", "03", v["ping"])
check("pong", "04", v["pong"])

# §8.3: move request and declined carry the target (0x01 local-only hotspot).
check("move request", (u8(0x10) + u8(0x01)).hex(), v["move_request"])
ssid, passphrase = b"AndroidShare_4821", b"k7q2m9x4p1"
offer = u8(0x11) + u16(40123) + u8(len(ssid)) + ssid + u8(len(passphrase)) + passphrase
check("hotspot offer", offer.hex(), v["hotspot_offer"])
check("move declined", (u8(0x12) + u8(0x01)).hex(), v["move_declined"])

# §8.4: the file, its offer, and its chunks.
size = int(v["file_size"])
content = bytes((i * 7 + 3) % 256 for i in range(size))
digest = hashlib.sha256(content).digest()
check("file sha256", digest.hex(), v["file_sha256"])
name, mime, thumbnail = "tatil fotoğrafı.jpg".encode(), b"image/jpeg", bytes.fromhex("ffd8ffd9")
file_offer = (
    u8(0x20) + mid + u64(sent_at) + u64(size) + digest
    + u8(len(mime)) + mime + u8(len(name)) + name + u16(len(thumbnail)) + thumbnail
)
check("file offer", file_offer.hex(), v["file_offer"])
check("chunk request", (u8(0x21) + mid + u64(0) + u16(16)).hex(), v["chunk_request"])
chunks = [content[i:i + CHUNK_LEN] for i in range(0, size, CHUNK_LEN)]
check("chunk count", len(chunks), 2)
chunk = [u8(0x22) + mid + u64(i) + data for i, data in enumerate(chunks)]
check("chunk 0 (sha256)", hashlib.sha256(chunk[0]).hexdigest(), v["chunk_0_sha256"])
check("chunk 1", chunk[1].hex(), v["chunk_1"])
check("unavailable: not now", (u8(0x23) + mid + u8(0x01)).hex(), v["unavailable_not_now"])
check("unavailable: gone", (u8(0x23) + mid + u8(0x02)).hex(), v["unavailable_gone"])

# §8.5: calls and push-to-talk, named by a 16-byte stream id; reasons 0x02 declined, 0x07 interrupted.
check("call offer", (u8(0x30) + mid).hex(), v["call_offer"])
check("ringing", (u8(0x36) + mid).hex(), v["ringing"])
check("call accept", (u8(0x31) + mid).hex(), v["call_accept"])
check("call end", (u8(0x32) + mid + u8(0x02)).hex(), v["call_end"])
check("talk start", (u8(0x33) + mid).hex(), v["talk_start"])
check("talk end", (u8(0x34) + mid + u8(0x07)).hex(), v["talk_end"])
check("audio", (u8(0x35) + mid + (70000).to_bytes(4, "big") + bytes([0x4B] * 60)).hex(), v["audio"])
check("largest audio packet fits a record", 1 + 16 + 4 + 1275 <= 16384, True)

# §8.6: video. A video call's offer ends in the media byte 0x01; camera states 0x00 off, 0x01 on,
# 0x02 paused; frames in parts, each with the frame's header (here part 1 of 3 of key frame 300,
# rotation 3, 1280x720).
check("video call offer", (u8(0x30) + mid + u8(0x01)).hex(), v["video_call_offer"])
check("video state", (u8(0x3A) + mid + u8(0x02)).hex(), v["video_state"])
video = u8(0x3B) + mid + (300).to_bytes(4, "big") + u8(0x01) + u8(3) + u16(1280) + u16(720) + u8(1) + u8(3) + bytes([0x65] * 40)
check("video", video.hex(), v["video"])
check("key frame request", (u8(0x3C) + mid).hex(), v["key_frame_request"])
check("largest video part fits a record", 1 + 16 + 4 + 1 + 1 + 2 + 2 + 1 + 1 + 16320 <= 16384, True)

# §9.5: group records; the group message (§9.3) travels as sealed, here 4 stand-in bytes.
group_id = bytes([0x67] * 16)
check("update part", (u8(0x40) + mid + u16(1) + u16(2) + bytes([0xAB] * 5)).hex(), v["update_part"])
check("group message", (u8(0x41) + bytes([0xCD] * 4)).hex(), v["group_message"])
check("group ack", (u8(0x42) + group_id + mid).hex(), v["group_ack"])
check("group leave", (u8(0x43) + group_id).hex(), v["group_leave"])
# §9.6: group voice; talk end and audio are those of §8.5.
check("group talk start", (u8(0x37) + mid + group_id).hex(), v["group_talk_start"])
check("group call", (u8(0x38) + mid + group_id).hex(), v["group_call"])
check("group call leave", (u8(0x39) + mid).hex(), v["group_call_leave"])
# Call presence and audio: an origin, then the member's identity key and count, or a numbered packet.
origin = bytes([0x0C] * 8)
check("call presence", (u8(0x3E) + mid + origin + bytes([0x5E] * 32) + (7).to_bytes(4, "big")).hex(), v["call_presence"])
check("call audio", (u8(0x3F) + mid + origin + (9).to_bytes(4, "big") + b"opus").hex(), v["call_audio"])
# §9.9: group video. A presence with the camera on ends in its state; a camera off is left out.
check(
    "call presence, camera on",
    (u8(0x3E) + mid + origin + bytes([0x5E] * 32) + (8).to_bytes(4, "big") + u8(0x01)).hex(),
    v["call_presence_camera"],
)
call_video = u8(0x46) + mid + origin + (41).to_bytes(4, "big") + u8(0x00) + u8(1) + u16(640) + u16(360) + u8(0) + u8(2) + bytes([0x41] * 24)
check("call video", call_video.hex(), v["call_video"])
check("call key frame request", (u8(0x47) + mid + origin + bytes([0x7A] * 8)).hex(), v["call_key_frame_request"])
check("largest call video part fits a record", 1 + 16 + 8 + 4 + 1 + 1 + 2 + 2 + 1 + 1 + 16320 <= 16384, True)
check("largest update part fits a record", 1 + 16 + 2 + 2 + 15360 <= 16384, True)
check("largest group message fits a record", 1 + 16 + 8 + 16 + 32 + 24 + 8 + 8192 + 16 + 64 <= 16384, True)

# §6.9: a static key, signed by its owner's identity key, and its acknowledgement.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

record = bytes.fromhex(v["static_key"])
version, key, signature = record[1:5], record[5:5 + 1216], record[5 + 1216:]
check("static key layout", (record[0], len(record)), (0x5C, 1 + 4 + 1216 + 64))
check("static key version", int.from_bytes(version, "big"), 5)
owner = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["static_key_identity_seed"]))
check("static key signature", owner.sign(b"AirChat v1 static-key" + version + key), signature)
check("static key taken", (u8(0x5D) + (5).to_bytes(4, "big")).hex(), v["static_key_taken"])
# §5.4: a presence key and its acknowledgement.
check("presence key", (u8(0x5E) + (2).to_bytes(4, "big") + bytes([0x6B] * 32)).hex(), v["presence_key"])
check("presence key taken", (u8(0x5F) + (2).to_bytes(4, "big")).hex(), v["presence_key_taken"])
attestation_certs = [bytes([0x30, 0x03, 0x02, 0x01, 0x07]), bytes([0x30] * 300)]
attestation_proof = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
check(
    "build attestation",
    (u8(0x60) + u8(len(attestation_certs))
     + b"".join(len(c).to_bytes(2, "big") + c for c in attestation_certs)
     + u8(len(attestation_proof)) + attestation_proof).hex(),
    v["build_attestation"],
)

# §9.8: a proposal to add a person to a conversation of two, and its answer.
person = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["static_key_identity_seed"])).public_key().public_bytes_raw()
name = lambda text: u8(len(text.encode())) + text.encode()
proposal = u8(0x44) + mid + (1_800_000_000).to_bytes(8, "big") + person + name("Cem") + name("Üçümüz")
check("member proposal", proposal.hex(), v["member_proposal"])
check("member proposal answer", (u8(0x45) + mid + u8(1)).hex(), v["member_proposal_answer"])

# The largest offer and chunk fit in one record (§6.4: at most 16384 bytes of payload).
largest_offer = 1 + 16 + 8 + 8 + 32 + 1 + 127 + 1 + 255 + 2 + 12288
check("largest offer fits a record", largest_offer <= 16384, True)
check("largest chunk fits a record", 1 + 16 + 8 + CHUNK_LEN <= 16384, True)

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
