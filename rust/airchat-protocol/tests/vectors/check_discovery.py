#!/usr/bin/env python3
"""Independent check of the discovery test vector (docs/protocol.md §5, §7.3 and §7.4).

Recomputes the presence token, the pairing beacon label and the BLE and Wi-Fi Aware beacons from
the specification alone. Needs only the standard library.

    python3 check_discovery.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

SAS_EMOJI = (
    "🐶🐱🦁🐴🦄🐷🐘🐰🐼🐔🐧🐢🐟🐙🦋🌻🌳🌵🍄🌍🌙🌈🔥🍌🍎🍓🌽🍕🎂🍇😀🤖"
    "🎩👓🔧🐝👍🌂⌛⏰🎁💡📕🔦📎🧲🔒🔑🔨📞🚩🚂🚲🚁🚀🏆⚽🎸🎺🔔⚓🎧📁📌"
)
here = pathlib.Path(__file__).parent
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")


v = json.loads((here / "discovery.json").read_text())
print("discovery.json")

# §5.2: HMAC-SHA-256(presence_key, label || epoch as u64 big-endian), first 8 bytes.
key = bytes.fromhex(v["presence_key"])
epoch = int(v["epoch"])
token = hmac.new(key, b"AirChat v1 presence-token" + epoch.to_bytes(8, "big"), hashlib.sha256).digest()[:8]
check("presence token", token.hex(), v["presence_token"])

# §5.1: emoji from the low six bits of byte 0, then bytes 1..3 as u16 mod 10000.
pairing = bytes.fromhex(v["pairing_token"])
label = f"{SAS_EMOJI[pairing[0] & 63]} {int.from_bytes(pairing[1:3], 'big') % 10000:04d}"
check("pairing label", label, v["pairing_label"])

# §7.3: kind (0x01 presence, 0x02 pairing) || PSM (one byte, 0x80..0xFF) || token.
psm = int(v["ble_psm"])
assert 0x80 <= psm <= 0xFF
check("BLE presence beacon", (bytes([0x01, psm]) + token).hex(), v["ble_presence_beacon"])
check("BLE pairing beacon", (bytes([0x02, psm]) + pairing).hex(), v["ble_pairing_beacon"])
# §11.2: a channel beacon, kind 0x03, carries the channel token (any 8 bytes here).
channel = bytes([0xC1, 0xC2, 0xC3, 0xC4, 0x51, 0x52, 0x53, 0x54])
check("BLE channel beacon", (bytes([0x03, psm]) + channel).hex(), v["ble_channel_beacon"])
check("BLE service UUID", v["ble_service_uuid"], "5decc7aa-bcb2-413d-97bc-4e02358f29a6")

# §7.4: Wi-Fi Aware service-specific information is kind || token, without a PSM.
check("Wi-Fi Aware service name", v["aware_service_name"], "airchat-v0")
check("Wi-Fi Aware presence beacon", (bytes([0x01]) + token).hex(), v["aware_presence_beacon"])
check("Wi-Fi Aware pairing beacon", (bytes([0x02]) + pairing).hex(), v["aware_pairing_beacon"])
check("Wi-Fi Aware channel beacon", (bytes([0x03]) + channel).hex(), v["aware_channel_beacon"])

# §4.8: a request beacon for an AirChat ID; its 120 bits are the first 24 symbols of the text (§4.2).
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
symbols = v["request_id"].removeprefix("AIR-").replace("-", "")[:24]
request_id = sum(ALPHABET.index(c) << (5 * (23 - i)) for i, c in enumerate(symbols)).to_bytes(15, "big")


def hkdf(ikm, info):
    prk = hmac.new(b"", ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


request_key = hkdf(request_id, b"AirChat v1 id-request-key")
request = hmac.new(request_key, b"AirChat v1 id-request-token" + epoch.to_bytes(8, "big"), hashlib.sha256).digest()[:8]
check("request token", request.hex(), v["request_token"])
check("BLE request beacon", (bytes([0x04, psm]) + request).hex(), v["ble_request_beacon"])
check("Wi-Fi Aware request beacon", (bytes([0x04]) + request).hex(), v["aware_request_beacon"])

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
