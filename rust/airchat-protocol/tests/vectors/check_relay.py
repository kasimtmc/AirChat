#!/usr/bin/env python3
"""Independent check of the relay test vector (docs/protocol.md §15).

Encodes again from the specification alone: a relay invite record and the join, ready and refused
frames.

    python3 check_relay.py
"""

import json
import pathlib
import sys

vector = json.loads(pathlib.Path(__file__).with_name("relay.json").read_text())
field = lambda name: bytes.fromhex(vector[name])
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {what}")


print("relay.json")
room, token, reference = field("room"), field("token"), field("reference")
# §15.1: 0x62 relay invite: room || token || size (2) || purpose (0x01 a file) || reference.
check("invite record", field("invite_record"), b"\x62" + room + token + bytes([2, 0x01]) + reference)
# §15.2: 0xa0 join: room || token || size || wait (u16, 180 minutes).
check("join", field("join"), b"\x00\xa0" + room + token + bytes([2]) + (180).to_bytes(2, "big"))
check("ready", field("ready"), b"\x00\xa1")
# Failure 9 (§13.7), no retry time.
check("refused", field("refused"), b"\x00\x7f\x09" + bytes(4))

sys.exit(1 if failures else 0)
