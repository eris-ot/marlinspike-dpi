//! OPC UA service body parsers — ReadRequest and ReadResponse.
//!
//! Service messages live inside the body of an OPC UA `MSG` chunk. After the
//! 24-byte MSG security/sequence/request header, the service is encoded as:
//!
//!   TypeId NodeId  (identifies the service, e.g. ReadResponse_Encoding_DefaultBinary)
//!   ServiceBody    (RequestHeader/ResponseHeader + service-specific fields)

use crate::opc_ua::data_value::{read_data_value, DecodedDataValue};
use crate::opc_ua::node_id::{read_node_id, DecodedNodeId};
use crate::opc_ua::reader::{Reader, ReaderError};

/// OPC UA service TypeId NodeIds (numeric IDs in namespace 0).
pub const READ_REQUEST_TYPE_ID: u32 = 631; // ReadRequest_Encoding_DefaultBinary
pub const READ_RESPONSE_TYPE_ID: u32 = 634; // ReadResponse_Encoding_DefaultBinary

/// Identify the service type from the leading TypeId NodeId. Returns
/// `(numeric_type_id, bytes_consumed_for_typeid)` — the caller can advance
/// past the TypeId knowing which service follows.
pub fn read_service_type_id(r: &mut Reader<'_>) -> Result<u32, ReaderError> {
    let node = read_node_id(r)?;
    match node.identifier {
        crate::bronze::OpcUaNodeId::Numeric(n) if node.namespace_index == 0 => Ok(n),
        _ => Err(ReaderError::InvalidLength),
    }
}

/// Skip the OPC UA RequestHeader. Returns the request handle from the header
/// (caller may use it for correlation, though chunk-level RequestId is
/// usually preferred).
pub fn skip_request_header(r: &mut Reader<'_>) -> Result<u32, ReaderError> {
    let _auth_token = read_node_id(r)?;
    let _timestamp = r.read_i64()?;
    let request_handle = r.read_u32()?;
    let _return_diagnostics = r.read_u32()?;
    let _audit_entry_id = r.read_string()?;
    let _timeout_hint = r.read_u32()?;
    skip_extension_object(r)?;
    Ok(request_handle)
}

/// Skip the OPC UA ResponseHeader. Returns `(request_handle, service_result)`.
pub fn skip_response_header(r: &mut Reader<'_>) -> Result<(u32, u32), ReaderError> {
    let _timestamp = r.read_i64()?;
    let request_handle = r.read_u32()?;
    let service_result = r.read_u32()?;
    skip_diagnostic_info(r)?;
    skip_string_array(r)?;
    skip_extension_object(r)?;
    Ok((request_handle, service_result))
}

/// Skip a DiagnosticInfo struct.
pub fn skip_diagnostic_info(r: &mut Reader<'_>) -> Result<(), ReaderError> {
    let mask = r.read_u8()?;
    if mask & 0x01 != 0 {
        let _ = r.read_i32()?;
    }
    if mask & 0x02 != 0 {
        let _ = r.read_i32()?;
    }
    if mask & 0x04 != 0 {
        let _ = r.read_i32()?;
    }
    if mask & 0x08 != 0 {
        let _ = r.read_i32()?;
    }
    if mask & 0x10 != 0 {
        let _ = r.read_byte_string()?;
    }
    if mask & 0x20 != 0 {
        let _ = r.read_u32()?;
    }
    if mask & 0x40 != 0 {
        // Inner DiagnosticInfo — recurse.
        skip_diagnostic_info(r)?;
    }
    Ok(())
}

/// Skip a String[] (for the ResponseHeader's StringTable).
pub fn skip_string_array(r: &mut Reader<'_>) -> Result<(), ReaderError> {
    let len = match r.read_array_length()? {
        None => return Ok(()),
        Some(n) => n,
    };
    for _ in 0..len {
        let _ = r.read_byte_string()?;
    }
    Ok(())
}

/// Skip a DiagnosticInfo[] (for the ReadResponse's diagnosticInfos field).
pub fn skip_diagnostic_info_array(r: &mut Reader<'_>) -> Result<(), ReaderError> {
    let len = match r.read_array_length()? {
        None => return Ok(()),
        Some(n) => n,
    };
    for _ in 0..len {
        skip_diagnostic_info(r)?;
    }
    Ok(())
}

/// Skip an ExtensionObject (TypeId NodeId + encoding mask + optional body).
pub fn skip_extension_object(r: &mut Reader<'_>) -> Result<(), ReaderError> {
    let _type_id = read_node_id(r)?;
    let encoding = r.read_u8()?;
    match encoding {
        0x00 => {} // NoBody
        0x01 | 0x02 => {
            // Binary or XML — body is a length-prefixed ByteString.
            let _ = r.read_byte_string()?;
        }
        _ => return Err(ReaderError::InvalidLength),
    }
    Ok(())
}

/// Parse a ReadRequest body (after the TypeId NodeId already consumed by the
/// caller). Returns the NodeIds the request reads.
pub fn parse_read_request_body(
    r: &mut Reader<'_>,
) -> Result<Vec<DecodedNodeId>, ReaderError> {
    let _request_handle = skip_request_header(r)?;
    let _max_age = r.read_f64()?;
    let _timestamps_to_return = r.read_u32()?;
    let len = match r.read_array_length()? {
        None => return Ok(Vec::new()),
        Some(n) => n,
    };
    let mut nodes = Vec::with_capacity(len);
    for _ in 0..len {
        let node_id = read_node_id(r)?;
        let _attribute_id = r.read_u32()?;
        let _index_range = r.read_string()?;
        // QualifiedName dataEncoding: namespaceIndex (u16) + name (string).
        let _qname_ns = r.read_u16()?;
        let _qname_name = r.read_string()?;
        nodes.push(node_id);
    }
    Ok(nodes)
}

/// Parse a ReadResponse body. Returns each DataValue plus the service-result
/// status and request handle from the response header.
#[derive(Debug, Clone)]
pub struct ReadResponseBody {
    pub request_handle: u32,
    pub service_result: u32,
    pub results: Vec<DecodedDataValue>,
}

pub fn parse_read_response_body(r: &mut Reader<'_>) -> Result<ReadResponseBody, ReaderError> {
    let (request_handle, service_result) = skip_response_header(r)?;
    let len = match r.read_array_length()? {
        None => {
            return Ok(ReadResponseBody {
                request_handle,
                service_result,
                results: Vec::new(),
            });
        }
        Some(n) => n,
    };
    let mut results = Vec::with_capacity(len);
    for _ in 0..len {
        results.push(read_data_value(r)?);
    }
    // We don't bother with the trailing diagnosticInfos[] — the values are in.
    Ok(ReadResponseBody {
        request_handle,
        service_result,
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bronze::{OpcUaNodeId, PointValue, RawQuality};

    fn null_node_id() -> Vec<u8> {
        vec![0x00, 0x00] // TwoByte enc, id = 0
    }

    fn build_request_header(request_handle: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&null_node_id()); // authenticationToken
        bytes.extend_from_slice(&0i64.to_le_bytes()); // timestamp
        bytes.extend_from_slice(&request_handle.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // returnDiagnostics
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // auditEntryId = null string
        bytes.extend_from_slice(&0u32.to_le_bytes()); // timeoutHint
        // ExtensionObject additionalHeader: TypeId + encoding=NoBody
        bytes.extend_from_slice(&null_node_id());
        bytes.push(0x00);
        bytes
    }

    fn build_response_header(request_handle: u32, service_result: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i64.to_le_bytes()); // timestamp
        bytes.extend_from_slice(&request_handle.to_le_bytes());
        bytes.extend_from_slice(&service_result.to_le_bytes());
        bytes.push(0x00); // DiagnosticInfo encodingMask = 0
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // stringTable = null array
        bytes.extend_from_slice(&null_node_id()); // ExtensionObject TypeId
        bytes.push(0x00); // ExtensionObject encoding = NoBody
        bytes
    }

    #[test]
    fn read_request_round_trip() {
        let mut bytes = build_request_header(7);
        bytes.extend_from_slice(&0.0f64.to_le_bytes()); // maxAge
        bytes.extend_from_slice(&0u32.to_le_bytes()); // timestampsToReturn = Source
        bytes.extend_from_slice(&2i32.to_le_bytes()); // 2 nodes to read
        // Node 1: ns=2, id=1234 (FourByte enc)
        bytes.extend_from_slice(&[0x01, 0x02]);
        bytes.extend_from_slice(&1234u16.to_le_bytes());
        bytes.extend_from_slice(&13u32.to_le_bytes()); // attributeId = Value
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // indexRange
        bytes.extend_from_slice(&0u16.to_le_bytes()); // qname ns
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // qname name
        // Node 2: ns=3, id="Tank1" (String enc)
        bytes.extend_from_slice(&[0x03]);
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&5i32.to_le_bytes());
        bytes.extend_from_slice(b"Tank1");
        bytes.extend_from_slice(&13u32.to_le_bytes());
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(-1i32).to_le_bytes());

        let mut r = Reader::new(&bytes);
        let nodes = parse_read_request_body(&mut r).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].namespace_index, 2);
        assert_eq!(nodes[0].identifier, OpcUaNodeId::Numeric(1234));
        assert_eq!(nodes[1].namespace_index, 3);
        assert_eq!(nodes[1].identifier, OpcUaNodeId::String("Tank1".into()));
    }

    #[test]
    fn read_response_round_trip() {
        let mut bytes = build_response_header(7, 0);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // 1 result
        // DataValue: HAS_VALUE only, T_DOUBLE = 11, value = 50.0
        bytes.push(0x01);
        bytes.push(11);
        bytes.extend_from_slice(&50.0f64.to_le_bytes());

        let mut r = Reader::new(&bytes);
        let body = parse_read_response_body(&mut r).unwrap();
        assert_eq!(body.request_handle, 7);
        assert_eq!(body.service_result, 0);
        assert_eq!(body.results.len(), 1);
        assert_eq!(body.results[0].value, PointValue::Double(50.0));
        assert!(matches!(
            body.results[0].quality,
            RawQuality::OpcUaStatusCode(0)
        ));
    }

    #[test]
    fn skip_diagnostic_info_with_inner() {
        // mask = 0x40 (has inner) | 0x01 (has symbolicId)
        let mask: u8 = 0x40 | 0x01;
        let mut bytes = vec![mask];
        bytes.extend_from_slice(&5i32.to_le_bytes()); // symbolicId
        bytes.push(0x00); // inner mask = 0
        let mut r = Reader::new(&bytes);
        skip_diagnostic_info(&mut r).unwrap();
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn skip_extension_object_no_body() {
        let mut bytes = null_node_id();
        bytes.push(0x00);
        let mut r = Reader::new(&bytes);
        skip_extension_object(&mut r).unwrap();
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn skip_extension_object_with_binary_body() {
        let mut bytes = null_node_id();
        bytes.push(0x01);
        bytes.extend_from_slice(&3i32.to_le_bytes());
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let mut r = Reader::new(&bytes);
        skip_extension_object(&mut r).unwrap();
        assert_eq!(r.remaining(), 0);
    }
}
