//! A small reader of DER (ITU-T X.690), enough for certificates and Android's key description:
//! definite lengths only, tag numbers above 30 (Android's authorization list uses 701 to 724).

use super::AttestError;

pub const UNIVERSAL: u8 = 0;
pub const CONTEXT: u8 = 2;

pub const BOOLEAN: u32 = 1;
pub const INTEGER: u32 = 2;
pub const BIT_STRING: u32 = 3;
pub const OCTET_STRING: u32 = 4;
pub const OID: u32 = 6;
pub const ENUMERATED: u32 = 10;
pub const SEQUENCE: u32 = 16;
pub const SET: u32 = 17;

/// One element: its tag, its content and all of its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub content: &'a [u8],
    /// Header and content, as signed in a certificate.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Whether this is the universal type `tag`.
    pub fn is(&self, tag: u32) -> bool {
        self.class == UNIVERSAL && self.tag == tag
    }

    /// The content of the universal type `tag`.
    pub fn expect(&self, tag: u32) -> Result<&'a [u8], AttestError> {
        if self.is(tag) {
            Ok(self.content)
        } else {
            Err(AttestError::Malformed)
        }
    }

    /// The elements of a SEQUENCE or SET.
    pub fn children(&self, tag: u32) -> Result<Reader<'a>, AttestError> {
        if !self.constructed {
            return Err(AttestError::Malformed);
        }
        Ok(Reader::new(self.expect(tag)?))
    }

    /// A BOOLEAN's value.
    pub fn boolean(&self) -> Result<bool, AttestError> {
        match self.expect(BOOLEAN)? {
            [0] => Ok(false),
            [_] => Ok(true),
            _ => Err(AttestError::Malformed),
        }
    }

    /// A non-negative INTEGER or ENUMERATED of at most 8 bytes.
    pub fn small(&self, tag: u32) -> Result<u64, AttestError> {
        let bytes = self.expect(tag)?;
        let (&first, _) = bytes.split_first().ok_or(AttestError::Malformed)?;
        if first & 0x80 != 0 {
            return Err(AttestError::Malformed);
        }
        let bytes = if first == 0 { &bytes[1..] } else { bytes };
        if bytes.len() > 8 {
            return Err(AttestError::Malformed);
        }
        Ok(bytes.iter().fold(0, |value, &b| (value << 8) | u64::from(b)))
    }
}

/// The elements of a constructed value, in order.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// The next element, or None at the end.
    pub fn element(&mut self) -> Result<Option<Tlv<'a>>, AttestError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (tlv, rest) = read(self.rest)?;
        self.rest = rest;
        Ok(Some(tlv))
    }

    /// The next element, which must be there.
    pub fn take(&mut self) -> Result<Tlv<'a>, AttestError> {
        self.element()?.ok_or(AttestError::Malformed)
    }

    /// Nothing may follow.
    pub fn end(&self) -> Result<(), AttestError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(AttestError::Malformed)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

/// The element at the start of `input`, and what follows it.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), AttestError> {
    let (&first, mut at) = input.split_first().ok_or(AttestError::Malformed)?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        // High tag number: base 128, most significant first, at most 4 bytes, no padding.
        tag = 0;
        for index in 0.. {
            let (&b, rest) = at.split_first().ok_or(AttestError::Malformed)?;
            at = rest;
            if index == 0 && b == 0x80 || index >= 4 {
                return Err(AttestError::Malformed);
            }
            tag = (tag << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
        if tag < 0x1f {
            return Err(AttestError::Malformed);
        }
    }
    let (&length_byte, rest) = at.split_first().ok_or(AttestError::Malformed)?;
    at = rest;
    let length = if length_byte < 0x80 {
        usize::from(length_byte)
    } else {
        let count = usize::from(length_byte & 0x7f);
        // 0x80 is BER's indefinite length, not DER; four bytes are more than any input here.
        if count == 0 || count > 4 || at.len() < count {
            return Err(AttestError::Malformed);
        }
        let (bytes, rest) = at.split_at(count);
        at = rest;
        bytes.iter().fold(0usize, |value, &b| (value << 8) | usize::from(b))
    };
    if at.len() < length {
        return Err(AttestError::Malformed);
    }
    let header = input.len() - at.len();
    let (content, rest) = at.split_at(length);
    Ok((
        Tlv {
            class,
            constructed,
            tag,
            content,
            raw: &input[..header + length],
        },
        rest,
    ))
}

/// The single element `input` holds.
pub fn single(input: &[u8]) -> Result<Tlv<'_>, AttestError> {
    let (tlv, rest) = read(input)?;
    if rest.is_empty() {
        Ok(tlv)
    } else {
        Err(AttestError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_and_long_forms() {
        // [704] EXPLICIT { BOOLEAN TRUE }: tag bytes 0xbf 0x85 0x40.
        let bytes = [0xbf, 0x85, 0x40, 0x03, 0x01, 0x01, 0xff, 0x00];
        let (tlv, rest) = read(&bytes).unwrap();
        assert_eq!((tlv.class, tlv.constructed, tlv.tag), (CONTEXT, true, 704));
        assert_eq!(rest, [0x00]);
        assert!(single(tlv.content).unwrap().boolean().unwrap());
        // A long length.
        let mut long = vec![0x04, 0x82, 0x01, 0x00];
        long.extend([7; 256]);
        assert_eq!(single(&long).unwrap().content.len(), 256);
    }

    #[test]
    fn rejects_what_is_not_der() {
        for bad in [
            &[][..],
            &[0x30],
            &[0x30, 0x80, 0x00, 0x00], // indefinite length
            &[0x04, 0x05, 0x00],       // too short
            &[0xbf, 0x80, 0x01, 0x00], // padded tag number
            &[0xbf, 0x05, 0x00],       // high form for a low number
            &[0x04, 0x85, 1, 0, 0, 0, 0],
        ] {
            assert!(read(bad).is_err(), "{bad:02x?}");
        }
        let negative = [0x02, 0x01, 0x80];
        assert!(single(&negative).unwrap().small(INTEGER).is_err());
    }
}
