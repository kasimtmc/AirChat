# Formal models

Symbolic (Dolev-Yao) models of the protocol's handshakes in the
[Tamarin prover](https://tamarin-prover.com). The adversary controls the network and may learn any
device's long-term keys at any time; a lemma states what it still cannot do.

| Model | Covers |
|---|---|
| [`link.spthy`](link.spthy) | Contact link sessions: recognition tags (§6.2), the handshake (§6.3), link keys (§6.8) |
| [`pairing.spthy`](pairing.spthy) | Pairing (§4.3) in all three modes: QR invites (§4.4), Nearby Pairing with emoji (§4.5), adding by AirChat ID (§4.8); contact cards (§4.6) |

## Running

Tamarin 1.12 with Maude 3.5 (Arch, CachyOS: `pacman -S tamarin-prover`; other systems: see
tamarin-prover.com). Some Maude packages do not find their own prelude; `MAUDE_LIB` points it there.

```sh
cd formal
MAUDE_LIB=/usr/share/maude tamarin-prover --prove link.spthy
MAUDE_LIB=/usr/share/maude tamarin-prover --prove pairing.spthy
```

`--prove=<lemma>` proves one lemma; `tamarin-prover interactive .` opens the models in a browser.

## What `link.spthy` shows

All twelve lemmas are verified, in about two minutes on a laptop (Tamarin 1.12, 2026-10-14). The
adversary owns the network and may reveal any device's static key and any link key at any time.

| Lemma | Says |
|---|---|
| `executable` | The handshake can complete, so the lemmas below are not true for want of runs. |
| `initiator_send_key_secret`, `initiator_receive_key_secret` | The initiator's transport keys stay secret unless, before the handshake ended, the adversary had both the link key used and the responder's static key. |
| `responder_send_key_secret`, `responder_receive_key_secret` | Likewise for the responder, with the initiator's static key. |
| `initiator_injective_agreement`, `responder_injective_agreement` | When a side finishes, the other ran the same handshake with it (identities, link key, keys), and no other run ends with those keys; under the same condition. |
| `healing_initiator`, `healing_responder` | A handshake the adversary stayed out of yields transport keys and a next link key it never learns, even if it knew every static key and link key all along. |
| `ephemeral_keys_secret`, `static_keys_secret`, `encapsulated_secrets` | Helpers, proved first and then used: who can know a private key or an encapsulated secret. |

Read together:

- **Forward secrecy:** whatever leaks after a handshake ended does not open it.
- **Key-compromise impersonation resistance:** a device's own static key and link keys, stolen,
  do not let anyone pass as its contacts to it; that needs the contact's static key too.
- **Mutual authentication** without signatures, and no replay of a whole handshake.
- **Healing:** the next link key comes out of a handshake the thief did not take part in, so the
  handshake after it needs nothing the thief holds.

The lemmas are not vacuous: with the initiator's static key left out of the key schedule
(`MixKey(ss3)` dropped), Tamarin finds an attack on both responder lemmas in 32 steps (anyone with
the link key alone passes as the initiator), while the initiator's lemmas still hold.

## What `pairing.spthy` shows

All twelve lemmas are verified, in about three and a half minutes (2026-10-15). The adversary
owns the network, may reveal any identity key and any invite secret (someone photographed the QR
code), may pair as itself under an identity key of its own, and may run devices of its own that
show whatever emoji it likes.

| Lemma | Says |
|---|---|
| `executable_invite`, `executable_nearby`, `executable_request` | Each mode can complete. |
| `link_secret_secret` | In invite and request mode, the new link secret (`psk` of every later link, §6.1) is shared with the peer whose card was taken, and the adversary learns it only if that peer is itself or a device whose identity key it had before the pairing ended. A photographed QR code does not help. |
| `peer_agreed` | Under the same condition, the peer ran the same pairing with the same secret. |
| `peer_keys_authentic` | The static and presence keys a card brings are the peer device's own, unless its identity key had leaked. |
| `invite_scanner_gets_the_shower` | The device that scanned a QR code pairs with the device that showed it, unless that one's identity key had leaked. |
| `nearby_link_secret_secret`, `nearby_peer_is_the_device_picked` | In Nearby Pairing, when both users compared the emoji with the device they picked, each gets that device's card, and the link secret is the adversary's only if the device picked is: no leaked key helps a man in the middle. |
| `presence_keys_secret` | A device's presence key reaches only those it sent its card to after authenticating them: the holder of an identity key it saw proven (a leaked one, or the adversary as itself, which the user approved), the device its user compared emoji with, or in invite mode whoever had the QR code. Someone who answers an ID request without the ID's key learns nothing (§4.8). |
| `ephemeral_keys_secret`, `encapsulated_secrets` | Helpers. |

Writing the model found nothing wrong in the protocol, but two things the lemmas first missed: the
adversary may pair as itself, which the specification allows (§4.4, §4.8); and a device must reject
a card or proof with its own identity key, or its own card reflected back pairs it with itself.
The implementation does reject it (`src/pairing/protocol.rs`), as §4.6 says; the model now does too.
Not vacuous: when the scanner skips checking the card's pairing proof, Tamarin finds the attack on
`invite_scanner_gets_the_shower` (27 steps); when the initiator's user confirms without comparing
the emoji, it finds a man in the middle who learns the link secret (32 steps) and hands over
another device's card (12 steps). Emoji made without the transcript `h` exhausted 4 GB of memory
in 20 minutes without a verdict.

## What they do not show

The models' headers list their abstractions. In short:

- X-Wing, HKDF, HMAC, SHA-256 and ChaCha20-Poly1305 are ideal. Their computational security is the
  primitives' (libcrux, the X-Wing paper), not this model's.
- `link.spthy` assumes pairing gave both sides a fresh secret and each other's static key, which
  `pairing.spthy` shows for itself; the two are not composed in one model. Group links, channel
  and mesh links, envelopes, static key versions (§6.9) and build attestation are not modelled.
- The emoji are compared as whole hashes. That five emoji (30 bits) suffice, thanks to the
  commitment in message 2, is a matter of probability, outside a symbolic model.
- Identity hiding and unlinkability (§6.5) are privacy properties, which need observational
  equivalence; only trace properties are proved here.
- Link keys are not chained in the model: each handshake uses a key both sides share, which the
  adversary may learn, rather than the one the previous handshake made (chaining them makes every
  proof unfold all earlier handshakes, and Tamarin does not terminate). The healing lemmas carry
  the step from one handshake to the next by hand: a next key the adversary never learns is as
  good as a fresh secret one. Deleting old keys, which is what makes a thief's copied link keys
  stop working (§6.8), is not modelled.
- The recognition tag's replay protection and hour epochs are reduced to "each nonce once".
