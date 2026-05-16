//! OPC UA NodeId binary decoding into our typed [`crate::bronze::OpcUaNodeId`].

use crate::bronze::OpcUaNodeId;
use crate::opc_ua::reader::{Reader, ReaderError};

/// NodeId encoding mask (low 6 bits). The high 2 bits indicate ExpandedNodeId
/// extensions (NamespaceUri / ServerIndex flags); we read past them but the
/// embedder only sees the inner NodeId.
const ENC_TWO_BYTE: u8 = 0x00;
const ENC_FOUR_BYTE: u8 = 0x01;
const ENC_NUMERIC: u8 = 0x02;
const ENC_STRING: u8 = 0x03;
const ENC_GUID: u8 = 0x04;
const ENC_OPAQUE: u8 = 0x05;

const FLAG_NAMESPACE_URI: u8 = 0x80;
const FLAG_SERVER_INDEX: u8 = 0x40;

/// Decoded NodeId with namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedNodeId {
    pub namespace_index: u16,
    pub identifier: OpcUaNodeId,
}

/// Read a NodeId from the cursor.
pub fn read_node_id(r: &mut Reader<'_>) -> Result<DecodedNodeId, ReaderError> {
    let enc = r.read_u8()?;
    decode_node_id(r, enc & 0x3F)
}

/// Read an ExpandedNodeId — same as NodeId, with optional NamespaceUri /
/// ServerIndex tails determined by the top two bits of the encoding mask.
/// We discard the tails (they're not part of our `OpcUaNodeId` model).
pub fn read_expanded_node_id(r: &mut Reader<'_>) -> Result<DecodedNodeId, ReaderError> {
    let enc = r.read_u8()?;
    let inner = decode_node_id(r, enc & 0x3F)?;
    if enc & FLAG_NAMESPACE_URI != 0 {
        // Skip a String.
        let _ = r.read_byte_string()?;
    }
    if enc & FLAG_SERVER_INDEX != 0 {
        let _ = r.read_u32()?;
    }
    Ok(inner)
}

fn decode_node_id(r: &mut Reader<'_>, enc: u8) -> Result<DecodedNodeId, ReaderError> {
    match enc {
        ENC_TWO_BYTE => {
            let id = r.read_u8()?;
            Ok(DecodedNodeId {
                namespace_index: 0,
                identifier: OpcUaNodeId::Numeric(id as u32),
            })
        }
        ENC_FOUR_BYTE => {
            let ns = r.read_u8()? as u16;
            let id = r.read_u16()?;
            Ok(DecodedNodeId {
                namespace_index: ns,
                identifier: OpcUaNodeId::Numeric(id as u32),
            })
        }
        ENC_NUMERIC => {
            let ns = r.read_u16()?;
            let id = r.read_u32()?;
            Ok(DecodedNodeId {
                namespace_index: ns,
                identifier: OpcUaNodeId::Numeric(id),
            })
        }
        ENC_STRING => {
            let ns = r.read_u16()?;
            // OPC UA String NodeIds may legitimately contain non-UTF-8 bytes;
            // try valid-UTF-8 first, fall back to StringRaw.
            let len = r.read_i32()?;
            if len < 0 {
                return Ok(DecodedNodeId {
                    namespace_index: ns,
                    identifier: OpcUaNodeId::String(String::new()),
                });
            }
            let bytes = r.read_bytes(len as usize)?;
            let identifier = match std::str::from_utf8(bytes) {
                Ok(s) => OpcUaNodeId::String(s.to_string()),
                Err(_) => OpcUaNodeId::StringRaw(bytes.to_vec()),
            };
            Ok(DecodedNodeId {
                namespace_index: ns,
                identifier,
            })
        }
        ENC_GUID => {
            let ns = r.read_u16()?;
            let bytes = r.read_array::<16>()?;
            Ok(DecodedNodeId {
                namespace_index: ns,
                identifier: OpcUaNodeId::Guid(bytes),
            })
        }
        ENC_OPAQUE => {
            let ns = r.read_u16()?;
            let bytes = r.read_byte_string()?.unwrap_or(&[]);
            Ok(DecodedNodeId {
                namespace_index: ns,
                identifier: OpcUaNodeId::Opaque(bytes.to_vec()),
            })
        }
        _ => Err(ReaderError::InvalidLength),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_byte_encoding() {
        let bytes = [0x00, 0x2A]; // enc=TwoByte, id=42
        let mut r = Reader::new(&bytes);
        let n = read_node_id(&mut r).unwrap();
        assert_eq!(n.namespace_index, 0);
        assert_eq!(n.identifier, OpcUaNodeId::Numeric(42));
    }

    #[test]
    fn four_byte_encoding() {
        // enc=FourByte, ns=2, id=1234 (LE)
        let bytes = [0x01, 0x02, 0xD2, 0x04];
        let mut r = Reader::new(&bytes);
        let n = read_node_id(&mut r).unwrap();
        assert_eq!(n.namespace_index, 2);
        assert_eq!(n.identifier, OpcUaNodeId::Numeric(1234));
    }

    #[test]
    fn numeric_full_encoding() {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        let mut r = Reader::new(&bytes);
        let n = read_node_id(&mut r).unwrap();
        assert_eq!(n.namespace_index, 5);
        assert_eq!(n.identifier, OpcUaNodeId::Numeric(0xCAFE_BABE));
    }

    #[test]
    fn string_encoding() {
        let mut bytes = vec![0x03];
        bytes.extend_from_slice(&3u16.to_le_bytes()); // ns
        bytes.extend_from_slice(&5i32.to_le_bytes()); // len
        bytes.extend_from_slice(b"Tank1");
        let mut r = Reader::new(&bytes);
        let n = read_node_id(&mut r).unwrap();
        assert_eq!(n.namespace_index, 3);
        assert_eq!(n.identifier, OpcUaNodeId::String("Tank1".into()));
    }

    #[test]
    fn string_encoding_falls_back_to_raw_for_non_utf8() {
        let mut bytes = vec![0x03];
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&3i32.to_le_bytes());
        bytes.extend_from_slice(&[0xFF, 0x00, 0xFE]); // not valid UTF-8
        let mut r = Reader::new(&bytes);
        let n = read_node_id(&mut r).unwrap();
        assert_eq!(n.identifier, OpcUaNodeId::StringRaw(vec![0xFF, 0x00, 0xFE]));
    }

    #[test]
    fn guid_encoding() {
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 16]);
        let mut r = Reader::new(&bytes);
        let n = read_node_id(&mut r).unwrap();
        assert_eq!(n.namespace_index, 7);
        assert_eq!(n.identifier, OpcUaNodeId::Guid([0xAB; 16]));
    }

    #[test]
    fn expanded_node_id_skips_uri_and_server_index() {
        // enc=Numeric (0x02) | URI flag (0x80) | server-idx flag (0x40) = 0xC2
        let mut bytes = vec![0xC2];
        bytes.extend_from_slice(&5u16.to_le_bytes()); // ns
        bytes.extend_from_slice(&42u32.to_le_bytes()); // id
        bytes.extend_from_slice(&3i32.to_le_bytes()); // namespaceUri len
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(&99u32.to_le_bytes()); // serverIndex
        let mut r = Reader::new(&bytes);
        let n = read_expanded_node_id(&mut r).unwrap();
        assert_eq!(n.namespace_index, 5);
        assert_eq!(n.identifier, OpcUaNodeId::Numeric(42));
        assert_eq!(r.remaining(), 0);
    }
}
