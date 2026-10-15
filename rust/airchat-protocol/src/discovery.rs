//! Discovery beacons (docs/protocol.md §5).

use crate::{
    crypto::{CryptoError, SecretBytes, hash::hmac_sha256, kdf, random},
    identity::AirChatId,
    labels,
    pairing::SAS_EMOJI,
};

pub const PAIRING_TOKEN_LEN: usize = 4;
/// Short enough for a BLE advertisement. It only decides whether to connect; the link handshake
/// authenticates the device, so a chance match costs a failed connection attempt and nothing more.
pub const PRESENCE_TOKEN_LEN: usize = 8;

pub type PairingToken = [u8; PAIRING_TOKEN_LEN];
/// A walkie-talkie channel's beacon (§11.2).
pub type ChannelToken = crate::channel::Token;
pub type PresenceToken = [u8; PRESENCE_TOKEN_LEN];
pub const REQUEST_TOKEN_LEN: usize = 8;
pub type RequestToken = [u8; REQUEST_TOKEN_LEN];

/// What a device announces so its contacts recognise it: a MAC of the epoch under the device's
/// presence key, which only contacts know. It changes every epoch (§6.2), so bystanders can link
/// a device's announcements for an hour at most.
pub fn presence_token(presence_key: &SecretBytes<32>, epoch: u64) -> PresenceToken {
    let mac = hmac_sha256(presence_key.expose(), &[labels::PRESENCE_TOKEN, &epoch.to_be_bytes()]);
    mac.expose()[..PRESENCE_TOKEN_LEN]
        .try_into()
        .expect("MAC is longer than a token")
}

/// What a device that wants to add the owner of `id` announces (§4.8): a MAC of the epoch under a
/// key derived from the ID, so only those who know the ID can tell whom it looks for.
pub fn request_token(id: &AirChatId, epoch: u64) -> Result<RequestToken, CryptoError> {
    let key: SecretBytes<32> = kdf::derive(&[], id.as_bytes(), labels::ID_REQUEST_KEY)?;
    let mac = hmac_sha256(key.expose(), &[labels::ID_REQUEST_TOKEN, &epoch.to_be_bytes()]);
    Ok(mac.expose()[..REQUEST_TOKEN_LEN]
        .try_into()
        .expect("MAC is longer than a token"))
}

/// What a device in "Add nearby" mode announces: a random token, new every time the mode opens.
/// It identifies the device for this pairing only and says nothing about its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingBeacon {
    token: PairingToken,
}

impl PairingBeacon {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(Self {
            token: random::array()?,
        })
    }

    pub fn from_token(token: PairingToken) -> Self {
        Self { token }
    }

    pub fn token(&self) -> &PairingToken {
        &self.token
    }

    /// Shown on the device's own screen and in other devices' lists, so the user can pick the
    /// device in front of them: an emoji and four digits, e.g. `🦄 0427`.
    pub fn label(&self) -> String {
        let emoji = SAS_EMOJI[usize::from(self.token[0] & 0x3f)];
        let number = u16::from_be_bytes([self.token[1], self.token[2]]) % 10_000;
        format!("{emoji} {number:04}")
    }
}

/// The 128-bit UUID under which AirChat beacons travel as BLE service data (§7.3). A later
/// protocol version gets a new one.
pub const BLE_SERVICE_UUID: &str = "5decc7aa-bcb2-413d-97bc-4e02358f29a6";

const BLE_PRESENCE: u8 = 0x01;
const BLE_PAIRING: u8 = 0x02;
const BLE_CHANNEL: u8 = 0x03;
const BLE_REQUEST: u8 = 0x04;
/// Dynamically assigned LE L2CAP PSMs lie in this range, so one byte carries them.
const LE_DYNAMIC_PSM: std::ops::RangeInclusive<u16> = 0x0080..=0x00ff;

/// A beacon as carried in a BLE advertisement, with the L2CAP PSM on which the device accepts
/// connections (§7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleBeacon {
    Presence {
        psm: u16,
        token: PresenceToken,
    },
    Pairing {
        psm: u16,
        token: PairingToken,
    },
    /// A walkie-talkie channel this device is tuned to (§11.2).
    Channel {
        psm: u16,
        token: ChannelToken,
    },
    /// A request to add the owner of an AirChat ID (§4.8).
    Request {
        psm: u16,
        token: RequestToken,
    },
}

impl BleBeacon {
    /// The service data; `None` if the PSM is outside the LE dynamic range.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let (kind, psm, token) = match self {
            Self::Presence { psm, token } => (BLE_PRESENCE, *psm, &token[..]),
            Self::Pairing { psm, token } => (BLE_PAIRING, *psm, &token[..]),
            Self::Channel { psm, token } => (BLE_CHANNEL, *psm, &token[..]),
            Self::Request { psm, token } => (BLE_REQUEST, *psm, &token[..]),
        };
        if !LE_DYNAMIC_PSM.contains(&psm) {
            return None;
        }
        let psm = u8::try_from(psm).expect("the range fits in a byte");
        Some([&[kind, psm][..], token].concat())
    }

    /// Reads service data found under [`BLE_SERVICE_UUID`]; anything malformed or of an unknown kind
    /// is `None`.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let (&[kind, psm], token) = data.split_first_chunk::<2>()?;
        let psm = u16::from(psm);
        if !LE_DYNAMIC_PSM.contains(&psm) {
            return None;
        }
        match kind {
            BLE_PRESENCE => Some(Self::Presence {
                psm,
                token: token.try_into().ok()?,
            }),
            BLE_PAIRING => Some(Self::Pairing {
                psm,
                token: token.try_into().ok()?,
            }),
            BLE_CHANNEL => Some(Self::Channel {
                psm,
                token: token.try_into().ok()?,
            }),
            BLE_REQUEST => Some(Self::Request {
                psm,
                token: token.try_into().ok()?,
            }),
            _ => None,
        }
    }
}

/// The Wi-Fi Aware service AirChat devices publish and subscribe to (§7.4). The radio carries only a
/// hash of it, which reveals that an AirChat device is nearby, as the BLE UUID does.
pub const AWARE_SERVICE_NAME: &str = "airchat-v0";
/// The follow-up message a subscriber sends a publisher to ask for a data path (§7.4).
pub const AWARE_CONNECT_REQUEST: &[u8] = &[0x01];

/// A beacon as published over Wi-Fi Aware (§7.4): the kinds of BLE beacons, without a PSM, since the
/// data path setup carries the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwareBeacon {
    Presence(PresenceToken),
    Pairing(PairingToken),
    Channel(ChannelToken),
    Request(RequestToken),
}

impl AwareBeacon {
    /// The service-specific information to publish.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Presence(token) => [&[BLE_PRESENCE][..], token].concat(),
            Self::Pairing(token) => [&[BLE_PAIRING][..], token].concat(),
            Self::Channel(token) => [&[BLE_CHANNEL][..], token].concat(),
            Self::Request(token) => [&[BLE_REQUEST][..], token].concat(),
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let (&kind, token) = data.split_first()?;
        match kind {
            BLE_PRESENCE => Some(Self::Presence(token.try_into().ok()?)),
            BLE_PAIRING => Some(Self::Pairing(token.try_into().ok()?)),
            BLE_CHANNEL => Some(Self::Channel(token.try_into().ok()?)),
            BLE_REQUEST => Some(Self::Request(token.try_into().ok()?)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_format() {
        assert_eq!(PairingBeacon::from_token([4, 0x01, 0xab, 0]).label(), "🦄 0427");
        assert_eq!(PairingBeacon::from_token([0x7f, 0xff, 0xff, 0]).label(), "📌 5535");
    }

    #[test]
    fn presence_tokens_depend_on_key_and_epoch() {
        let key = |b: u8| SecretBytes::from_slice(&[b; 32]).unwrap();
        assert_eq!(presence_token(&key(1), 7), presence_token(&key(1), 7));
        assert_ne!(presence_token(&key(1), 7), presence_token(&key(1), 8));
        assert_ne!(presence_token(&key(1), 7), presence_token(&key(2), 7));
    }

    #[test]
    fn ble_beacons_round_trip_and_reject_malformed_data() {
        let presence = BleBeacon::Presence {
            psm: 0x0081,
            token: [7; PRESENCE_TOKEN_LEN],
        };
        let pairing = BleBeacon::Pairing {
            psm: 0x00ff,
            token: [9; PAIRING_TOKEN_LEN],
        };
        for beacon in [presence, pairing] {
            assert_eq!(BleBeacon::decode(&beacon.encode().unwrap()), Some(beacon));
        }
        assert_eq!(pairing.encode().unwrap(), [0x02, 0xff, 9, 9, 9, 9]);
        assert_eq!(
            BleBeacon::Pairing {
                psm: 0x7f,
                token: [0; 4]
            }
            .encode(),
            None
        );
        assert_eq!(
            BleBeacon::Pairing {
                psm: 0x100,
                token: [0; 4]
            }
            .encode(),
            None
        );

        let data = presence.encode().unwrap();
        assert_eq!(
            data.len(),
            10,
            "fits a legacy advertisement next to the flags and the UUID"
        );
        assert_eq!(BleBeacon::decode(&data[..9]), None);
        assert_eq!(BleBeacon::decode(&[data.as_slice(), &[0]].concat()), None);
        assert_eq!(BleBeacon::decode(&[0x03, 0x81, 1, 2, 3, 4]), None);
        assert_eq!(BleBeacon::decode(&[0x02, 0x40, 1, 2, 3, 4]), None);
        assert_eq!(BleBeacon::decode(&[0x02]), None);
    }

    #[test]
    fn aware_beacons_round_trip_and_reject_malformed_data() {
        for beacon in [AwareBeacon::Presence([7; 8]), AwareBeacon::Pairing([9; 4])] {
            assert_eq!(AwareBeacon::decode(&beacon.encode()), Some(beacon));
        }
        assert_eq!(AwareBeacon::Pairing([1, 2, 3, 4]).encode(), [2, 1, 2, 3, 4]);
        assert_eq!(AwareBeacon::decode(&[1; 8]), None, "presence token too short");
        assert_eq!(AwareBeacon::decode(&[2; 6]), None, "pairing token too long");
        assert_eq!(AwareBeacon::decode(&[3, 1, 2, 3, 4]), None, "unknown kind");
        assert_eq!(AwareBeacon::decode(&[]), None);
    }

    #[test]
    fn vector() {
        use crate::crypto::test_util::{check_vector, to_hex};
        let presence_key = SecretBytes::from_slice(&[0x5a; 32]).unwrap();
        let epoch = 490_000;
        let token = presence_token(&presence_key, epoch);
        let pairing = PairingBeacon::from_token([0x13, 0x37, 0xbe, 0xef]);
        let psm = 0x0085;
        let request_id = AirChatId::from_bytes([0x3c; 15]);
        let request = request_token(&request_id, epoch).unwrap();
        check_vector(
            "discovery",
            &[
                ("presence_key", to_hex(presence_key.expose())),
                ("epoch", epoch.to_string()),
                ("presence_token", to_hex(&token)),
                ("pairing_token", to_hex(pairing.token())),
                ("pairing_label", pairing.label()),
                ("ble_service_uuid", BLE_SERVICE_UUID.into()),
                ("ble_psm", psm.to_string()),
                (
                    "ble_presence_beacon",
                    to_hex(&BleBeacon::Presence { psm, token }.encode().unwrap()),
                ),
                (
                    "ble_pairing_beacon",
                    to_hex(
                        &BleBeacon::Pairing {
                            psm,
                            token: *pairing.token(),
                        }
                        .encode()
                        .unwrap(),
                    ),
                ),
                (
                    "ble_channel_beacon",
                    to_hex(
                        &BleBeacon::Channel {
                            psm,
                            token: [0xc1, 0xc2, 0xc3, 0xc4, 0x51, 0x52, 0x53, 0x54],
                        }
                        .encode()
                        .unwrap(),
                    ),
                ),
                ("aware_service_name", AWARE_SERVICE_NAME.into()),
                ("aware_presence_beacon", to_hex(&AwareBeacon::Presence(token).encode())),
                (
                    "aware_pairing_beacon",
                    to_hex(&AwareBeacon::Pairing(*pairing.token()).encode()),
                ),
                (
                    "aware_channel_beacon",
                    to_hex(&AwareBeacon::Channel([0xc1, 0xc2, 0xc3, 0xc4, 0x51, 0x52, 0x53, 0x54]).encode()),
                ),
                ("request_id", request_id.to_string()),
                ("request_token", to_hex(&request)),
                (
                    "ble_request_beacon",
                    to_hex(&BleBeacon::Request { psm, token: request }.encode().unwrap()),
                ),
                ("aware_request_beacon", to_hex(&AwareBeacon::Request(request).encode())),
            ],
        );
    }

    #[test]
    fn beacons_are_random() {
        assert_ne!(
            PairingBeacon::new().unwrap().token(),
            PairingBeacon::new().unwrap().token()
        );
    }
}
