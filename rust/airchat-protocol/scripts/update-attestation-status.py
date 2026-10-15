#!/usr/bin/env python3
"""Fetches Google's revocation list of Android key attestation certificates and writes the
revoked serial numbers into src/attest/revoked.txt, where they are
compiled in. Apps never go online for it: run this before each release, then commit the file.

    python3 scripts/update-attestation-status.py
"""

import datetime
import json
import pathlib
import re
import urllib.request

URL = "https://android.googleapis.com/attestation/status"
OUT = pathlib.Path(__file__).resolve().parent.parent / "src/attest/revoked.txt"

with urllib.request.urlopen(URL, timeout=60) as response:
    entries = json.load(response)["entries"]
serials = sorted(
    serial.lower()
    for serial, entry in entries.items()
    if entry.get("status") in ("REVOKED", "SUSPENDED")
)
assert serials and all(re.fullmatch(r"[a-f1-9][a-f0-9]*", s) for s in serials), "unexpected serial format"
today = datetime.date.today().isoformat()
OUT.write_text(f"# {URL}, {today}: {len(serials)} revoked or suspended.\n" + "\n".join(serials) + "\n")
print(f"{OUT}: {len(serials)} serials")
