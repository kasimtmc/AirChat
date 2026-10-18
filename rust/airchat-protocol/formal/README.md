# Formal models

Symbolic (Dolev-Yao) models of the protocol's handshakes in the
[Tamarin prover](https://tamarin-prover.com). The adversary controls the network and may learn any
device's long-term keys at any time; a lemma states what it still cannot do.

| Model | Covers |
|---|---|
| [`link.spthy`](link.spthy) | Contact link sessions: recognition tags (§6.2), the handshake (§6.3), link keys (§6.8) |
| [`pairing.spthy`](pairing.spthy) | Pairing (§4.3) in all three modes: QR invites (§4.4), Nearby Pairing with emoji (§4.5), adding by AirChat ID (§4.8); contact cards (§4.6) |
| [`group.spthy`](group.spthy) | Group keys: updates (§9.2) and messages (§9.3) of a group of three whose admin removes one member |
| [`mesh.spthy`](mesh.spthy) | 1:1 mesh envelopes (§10.3) and one-time prekeys (§10.7) |

## Running

Tamarin 1.12 with Maude 3.5 (Arch, CachyOS: `pacman -S tamarin-prover`; other systems: see
tamarin-prover.com). Some Maude packages do not find their own prelude; `MAUDE_LIB` points it there.

```sh
cd formal
MAUDE_LIB=/usr/share/maude tamarin-prover --prove link.spthy
MAUDE_LIB=/usr/share/maude tamarin-prover --prove pairing.spthy
MAUDE_LIB=/usr/share/maude tamarin-prover --derivcheck-timeout=0 --prove group.spthy
MAUDE_LIB=/usr/share/maude tamarin-prover --prove mesh.spthy
```

On a system with a Turkish locale, set `LC_ALL=C.UTF-8` (Tamarin reads the models as UTF-8, and
shell character ranges then behave). `--derivcheck-timeout=0` turns off a sanity check of the
group model's rules that does not finish in the default five seconds; it proves nothing.

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

## What `group.spthy` shows

All twelve lemmas are verified, in about ten minutes (2026-10-18). The adversary owns the network
and may reveal any device's static key and identity key at any time, which makes that device its
own: a member it controls keeps every key it was given and writes with them, also after it was
removed.

| Lemma | Says |
|---|---|
| `epoch_0_key_secret`, `epoch_1_key_secret` | An epoch's key is the adversary's only if a member of that epoch is. |
| `removed_member_gets_nothing_new` | The member removed never learns the next epoch's key, whatever it holds. |
| `updates_authentic` | A member takes an epoch only as its admin issued it, unless the admin's identity key leaked. |
| `messages_authentic` | What a member reads as from X in an epoch, X wrote in that epoch, unless X's identity key leaked. |
| `messages_secret` | A message written under an epoch key the admin issued is read by nobody outside that epoch, unless one of its members is the adversary's. |
| `removed_member_cannot_write` | Once a member holds the next epoch, it reads earlier-epoch messages only from those still in the group (§9.3): nothing more from the member removed, though it keeps the old key. Unless the admin's identity key leaked. |
| `executable`, `executable_late` | Both epochs can be taken and read, and a late message of epoch 0 from someone still in the group is read after epoch 1. |
| `static_keys_secret`, `identity_keys_secret`, `encapsulated_secrets` | Helpers. |

Not vacuous: when the admin seals epoch 1's key to the member removed too, Tamarin finds the attack
on `epoch_1_key_secret` (13 steps); when a device reads late messages from anyone in the earlier
epoch, it finds the removed member writing in (`removed_member_cannot_write`, 58 steps).

## What `mesh.spthy` shows

All ten lemmas are verified, in about nine minutes (2026-10-18). Every relay is the adversary's,
and it may reveal any static key, any pairing secret, and any prekey while its owner still holds
it.

| Lemma | Says |
|---|---|
| `prekey_text_secret`, `static_text_secret` | Relays cannot read: a text is the adversary's only if it has both the pairing secret and the recipient's key it was sealed to (that prekey, or the static key). |
| `prekey_text_forward_secret` | Once the recipient opened a text sealed to a prekey, the prekey is gone: taking the device later, with its static key, every other prekey and the pairing secret, opens nothing (§10.6). |
| `envelopes_authentic` | What the recipient takes as from A, A sent, with the same id, tag, expiry and drop, unless their pairing secret leaked (all a forger needs, as §10.6 says). |
| `envelopes_taken_once` | No envelope is taken twice. |
| `executable_prekey`, `executable_static` | Both kinds of envelope go through. |
| `static_keys_secret`, `prekeys_secret`, `encapsulated_secrets` | Helpers. |

Not vacuous: with the pairing secret left out of the seal key, Tamarin finds the static key alone
opening a text (`static_text_secret`, 11 steps) and anyone forging an envelope
(`envelopes_authentic`, 11 steps).

## What they do not show

The models' headers list their abstractions. In short:

- X-Wing, HKDF, HMAC, SHA-256 and ChaCha20-Poly1305 are ideal. Their computational security is the
  primitives' (libcrux, the X-Wing paper), not this model's.
- `link.spthy`, `group.spthy` and `mesh.spthy` assume pairing gave contacts a fresh secret and
  each other's keys, which `pairing.spthy` shows for itself; the models are not composed into one.
  Group links (§9.4), channel and mesh links (§11.3, §10.2), paths (§12), static key versions
  (§6.9) and build attestation are not modelled.
- `group.spthy` models one shape of group (three members, one removal) and not two updates of one
  epoch (§9.2); the tests cover that rule. Its devices may write in any epoch whose key they hold,
  which gives the adversary more than honest devices do.
- `mesh.spthy` leaves out tags, drops, hops and passing on, which carry no secret, and group
  envelopes, which are group messages (`group.spthy`).
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
