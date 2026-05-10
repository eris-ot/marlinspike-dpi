//! DNS dissector — parses DNS queries and responses (RFC 1035).

use crate::registry::{PacketContext, ProtocolData, ProtocolDissector};

#[derive(Debug, Clone)]
pub struct DnsFields {
    pub transaction_id: u16,
    pub is_response: bool,
    pub queries: Vec<String>,
    pub answers: Vec<String>,
    /// Structured DNS resource records from answer + additional sections.
    /// Populated for mDNS responses; gives access to TXT key=value, SRV
    /// targets, and A/AAAA bindings that the flat `answers` strings lose.
    pub records: Vec<DnsRecord>,
}

/// A parsed DNS resource record (answer, authority, or additional).
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Owner name (e.g. "Bathroom TV._airplay._tcp.local").
    pub name: String,
    /// Record type: A, AAAA, PTR, TXT, SRV, etc.
    pub rtype: DnsRecordType,
    /// Parsed data — varies by record type.
    pub data: DnsRecordData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    PTR,
    TXT,
    SRV,
    Other(u16),
}

#[derive(Debug, Clone)]
pub enum DnsRecordData {
    /// A record: IPv4 address.
    A(String),
    /// AAAA record: IPv6 address.
    Aaaa(String),
    /// PTR record: domain name.
    Ptr(String),
    /// TXT record: key=value pairs.
    Txt(Vec<String>),
    /// SRV record: target host and port.
    Srv {
        target: String,
        port: u16,
        priority: u16,
        weight: u16,
    },
    /// Unparsed record.
    Raw(Vec<u8>),
}

#[derive(Default)]
pub struct DnsDissector;

const DNS_PORT: u16 = 53;

impl ProtocolDissector for DnsDissector {
    fn name(&self) -> &str {
        "dns"
    }

    fn can_parse(&self, data: &[u8], src_port: u16, dst_port: u16) -> bool {
        let is_dns =
            src_port == DNS_PORT || dst_port == DNS_PORT || src_port == 5353 || dst_port == 5353;
        is_dns && data.len() >= 12
    }

    fn parse(&self, data: &[u8], _context: &PacketContext) -> Option<ProtocolData> {
        if data.len() < 12 {
            return None;
        }

        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags & 0x8000) != 0;
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
        let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

        let mut offset = 12;
        let mut queries = Vec::new();
        let mut answers = Vec::new();
        let mut records = Vec::new();

        // Parse question records.
        for _ in 0..qdcount {
            let (name, new_offset) = parse_dns_name(data, offset)?;
            offset = new_offset;
            if offset + 4 > data.len() {
                return None;
            }
            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            queries.push(format!(
                "{} {} {}",
                name,
                type_to_str(qtype),
                class_to_str(qclass)
            ));
        }

        // Parse answer + authority + additional records.
        let total_rr = ancount + nscount + arcount;
        for i in 0..total_rr {
            let (name, new_offset) = match parse_dns_name(data, offset) {
                Some(v) => v,
                None => break,
            };
            offset = new_offset;
            if offset + 10 > data.len() {
                break;
            }
            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            let rdata = &data[offset..offset + rdlength];
            let rdata_str = format_rdata(rtype, rdata, data);

            // Only include answer section in the flat string list (backward compat)
            if i < ancount {
                answers.push(format!(
                    "{} {} TTL={} {}",
                    name,
                    type_to_str(rtype),
                    ttl,
                    rdata_str
                ));
            }

            // Always add to structured records
            let (record_type, record_data) = parse_record(rtype, rdata, data);
            records.push(DnsRecord {
                name: name.clone(),
                rtype: record_type,
                data: record_data,
            });

            offset += rdlength;
        }

        Some(ProtocolData::Dns(DnsFields {
            transaction_id,
            is_response,
            queries,
            answers,
            records,
        }))
    }
}

/// Parse a DNS domain name with compression pointer support.
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut final_offset = offset;
    let mut hops = 0;

    loop {
        if offset >= data.len() || hops > 128 {
            return None;
        }

        let len_or_ptr = data[offset];

        if len_or_ptr == 0 {
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        }

        // Compression pointer (top two bits = 11).
        if len_or_ptr & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            if !jumped {
                final_offset = offset + 2;
            }
            let ptr = ((len_or_ptr as usize & 0x3F) << 8) | data[offset + 1] as usize;
            offset = ptr;
            jumped = true;
            hops += 1;
            continue;
        }

        let label_len = len_or_ptr as usize;
        offset += 1;
        if offset + label_len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[offset..offset + label_len]).ok()?;
        labels.push(label.to_string());
        offset += label_len;
        hops += 1;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Some((name, final_offset))
}

fn type_to_str(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        _ => "UNKNOWN",
    }
}

fn class_to_str(c: u16) -> &'static str {
    // mDNS uses bit 15 as "cache flush" flag — mask it off
    match c & 0x7FFF {
        1 => "IN",
        3 => "CH",
        _ => "??",
    }
}

fn format_rdata(rtype: u16, rdata: &[u8], full_msg: &[u8]) -> String {
    match rtype {
        1 if rdata.len() == 4 => {
            format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        28 if rdata.len() == 16 => {
            let segs: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]])))
                .collect();
            segs.join(":")
        }
        12 | 5 | 2 => {
            // PTR, CNAME, NS — compressed domain name
            if let Some(msg_offset) = find_rdata_offset(full_msg, rdata) {
                parse_dns_name(full_msg, msg_offset)
                    .map(|(name, _)| name)
                    .unwrap_or_else(|| format!("<{} bytes>", rdata.len()))
            } else {
                parse_dns_name_no_compression(rdata)
                    .unwrap_or_else(|| format!("<{} bytes>", rdata.len()))
            }
        }
        16 => {
            // TXT record — sequence of length-prefixed strings
            let entries = parse_txt_rdata(rdata);
            entries.join("; ")
        }
        33 if rdata.len() >= 6 => {
            // SRV record — priority(2) + weight(2) + port(2) + target(name)
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let target = if let Some(off) = find_rdata_offset(full_msg, &rdata[6..]) {
                parse_dns_name(full_msg, off)
                    .map(|(n, _)| n)
                    .unwrap_or_else(|| "?".into())
            } else {
                parse_dns_name_no_compression(&rdata[6..]).unwrap_or_else(|| "?".into())
            };
            format!("{}:{}", target, port)
        }
        _ => format!("<{} bytes>", rdata.len()),
    }
}

/// Parse structured DNS record data into typed enum.
fn parse_record(rtype: u16, rdata: &[u8], full_msg: &[u8]) -> (DnsRecordType, DnsRecordData) {
    match rtype {
        1 if rdata.len() == 4 => (
            DnsRecordType::A,
            DnsRecordData::A(format!(
                "{}.{}.{}.{}",
                rdata[0], rdata[1], rdata[2], rdata[3]
            )),
        ),
        28 if rdata.len() == 16 => {
            let segs: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]])))
                .collect();
            (DnsRecordType::AAAA, DnsRecordData::Aaaa(segs.join(":")))
        }
        12 => {
            let name = if let Some(off) = find_rdata_offset(full_msg, rdata) {
                parse_dns_name(full_msg, off).map(|(n, _)| n)
            } else {
                parse_dns_name_no_compression(rdata)
            };
            (
                DnsRecordType::PTR,
                DnsRecordData::Ptr(name.unwrap_or_default()),
            )
        }
        16 => (
            DnsRecordType::TXT,
            DnsRecordData::Txt(parse_txt_rdata(rdata)),
        ),
        33 if rdata.len() >= 6 => {
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let target = if let Some(off) = find_rdata_offset(full_msg, &rdata[6..]) {
                parse_dns_name(full_msg, off)
                    .map(|(n, _)| n)
                    .unwrap_or_default()
            } else {
                parse_dns_name_no_compression(&rdata[6..]).unwrap_or_default()
            };
            (
                DnsRecordType::SRV,
                DnsRecordData::Srv {
                    target,
                    port,
                    priority,
                    weight,
                },
            )
        }
        other => (
            DnsRecordType::Other(other),
            DnsRecordData::Raw(rdata.to_vec()),
        ),
    }
}

/// Parse TXT rdata into a list of strings.
/// TXT rdata is a sequence of length-prefixed byte strings.
fn parse_txt_rdata(data: &[u8]) -> Vec<String> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let len = data[offset] as usize;
        offset += 1;
        if offset + len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[offset..offset + len]) {
            entries.push(s.to_string());
        }
        offset += len;
    }
    entries
}

/// Find the offset of an rdata slice within the full DNS message.
fn find_rdata_offset(full_msg: &[u8], rdata: &[u8]) -> Option<usize> {
    if rdata.is_empty() || full_msg.is_empty() {
        return None;
    }
    let full_start = full_msg.as_ptr() as usize;
    let rdata_start = rdata.as_ptr() as usize;
    if rdata_start >= full_start && rdata_start < full_start + full_msg.len() {
        Some(rdata_start - full_start)
    } else {
        None
    }
}

/// Parse a DNS name without compression pointer support (for standalone rdata).
fn parse_dns_name_no_compression(data: &[u8]) -> Option<String> {
    let mut labels = Vec::new();
    let mut offset = 0;
    loop {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            return None; // compression pointer — can't resolve without full msg
        }
        offset += 1;
        if offset + len > data.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&data[offset..offset + len])
                .ok()?
                .to_string(),
        );
        offset += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx() -> PacketContext {
        PacketContext {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 12345,
            dst_port: 53,
            vlan_id: None,
            timestamp: 0,
        }
    }

    /// Build a minimal DNS query for "example.com" type A class IN.
    fn build_dns_query() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&[0xAB, 0xCD]); // transaction id
        pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query
        pkt.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
        pkt.extend_from_slice(&[0x00, 0x00]); // ancount = 0
        pkt.extend_from_slice(&[0x00, 0x00]); // nscount = 0
        pkt.extend_from_slice(&[0x00, 0x00]); // arcount = 0

        // Question: example.com
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0); // end of name

        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt
    }

    /// Build a DNS response for "example.com" -> 93.184.216.34
    fn build_dns_response() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&[0xAB, 0xCD]); // transaction id
        pkt.extend_from_slice(&[0x81, 0x80]); // flags: response
        pkt.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
        pkt.extend_from_slice(&[0x00, 0x01]); // ancount = 1
        pkt.extend_from_slice(&[0x00, 0x00]); // nscount
        pkt.extend_from_slice(&[0x00, 0x00]); // arcount

        // Question
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN

        // Answer — use compression pointer to offset 12 (the question name)
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
        pkt.extend_from_slice(&[0x00, 0x04]); // rdlength = 4
        pkt.extend_from_slice(&[93, 184, 216, 34]); // rdata
        pkt
    }

    #[test]
    fn test_parse_dns_query() {
        let pkt = build_dns_query();
        let d = DnsDissector;
        assert!(d.can_parse(&pkt, 12345, 53));

        let result = d.parse(&pkt, &ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                assert_eq!(dns.transaction_id, 0xABCD);
                assert!(!dns.is_response);
                assert_eq!(dns.queries.len(), 1);
                assert!(dns.queries[0].contains("example.com"));
                assert!(dns.queries[0].contains("A"));
            }
            _ => panic!("expected DNS"),
        }
    }

    #[test]
    fn test_parse_dns_response() {
        let pkt = build_dns_response();
        let d = DnsDissector;

        let result = d.parse(&pkt, &ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                assert!(dns.is_response);
                assert_eq!(dns.queries.len(), 1);
                assert_eq!(dns.answers.len(), 1);
                assert!(dns.answers[0].contains("93.184.216.34"));
                // Check structured records
                assert_eq!(dns.records.len(), 1);
                assert_eq!(dns.records[0].rtype, DnsRecordType::A);
                match &dns.records[0].data {
                    DnsRecordData::A(ip) => assert_eq!(ip, "93.184.216.34"),
                    other => panic!("expected A record, got {other:?}"),
                }
            }
            _ => panic!("expected DNS"),
        }
    }

    /// Build an mDNS unsolicited announcement with TXT and A records
    /// (simulates what a Roku/AirPlay device sends).
    fn build_mdns_announcement() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header: response, 0 questions, 2 answers, 0 ns, 1 additional
        pkt.extend_from_slice(&[0x00, 0x00]); // transaction id = 0 (mDNS)
        pkt.extend_from_slice(&[0x84, 0x00]); // flags: response, authoritative
        pkt.extend_from_slice(&[0x00, 0x00]); // qdcount = 0
        pkt.extend_from_slice(&[0x00, 0x02]); // ancount = 2 (TXT + PTR)
        pkt.extend_from_slice(&[0x00, 0x00]); // nscount = 0
        pkt.extend_from_slice(&[0x00, 0x01]); // arcount = 1 (A record)

        // Answer 1: TXT record for "MyTV._airplay._tcp.local"
        // Name
        pkt.push(4);
        pkt.extend_from_slice(b"MyTV");
        pkt.push(8);
        pkt.extend_from_slice(b"_airplay");
        pkt.push(4);
        pkt.extend_from_slice(b"_tcp");
        pkt.push(5);
        pkt.extend_from_slice(b"local");
        pkt.push(0);
        // Type TXT (16), class IN+cache-flush (0x8001)
        pkt.extend_from_slice(&[0x00, 0x10]);
        pkt.extend_from_slice(&[0x80, 0x01]);
        // TTL
        pkt.extend_from_slice(&[0x00, 0x00, 0x11, 0x94]);
        // TXT rdata: "manufacturer=onn" + "model=H508X"
        let txt1 = b"manufacturer=onn";
        let txt2 = b"model=H508X";
        let rdlen = 1 + txt1.len() + 1 + txt2.len();
        pkt.extend_from_slice(&(rdlen as u16).to_be_bytes());
        pkt.push(txt1.len() as u8);
        pkt.extend_from_slice(txt1);
        pkt.push(txt2.len() as u8);
        pkt.extend_from_slice(txt2);

        // Answer 2: PTR record for "_airplay._tcp.local" -> "MyTV._airplay._tcp.local"
        pkt.push(8);
        pkt.extend_from_slice(b"_airplay");
        pkt.push(4);
        pkt.extend_from_slice(b"_tcp");
        pkt.push(5);
        pkt.extend_from_slice(b"local");
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x0C]); // type PTR
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x11, 0x94]); // TTL
        // PTR rdata: "MyTV._airplay._tcp.local" (use pointer to offset 12)
        let ptr_rdlen = 2u16; // just a compression pointer
        pkt.extend_from_slice(&ptr_rdlen.to_be_bytes());
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12

        // Additional: A record for "mydevice.local" -> 192.168.2.162
        pkt.push(8);
        pkt.extend_from_slice(b"mydevice");
        pkt.push(5);
        pkt.extend_from_slice(b"local");
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x80, 0x01]); // class IN+cache-flush
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL = 120
        pkt.extend_from_slice(&[0x00, 0x04]); // rdlength = 4
        pkt.extend_from_slice(&[192, 168, 2, 162]); // rdata

        pkt
    }

    fn mdns_ctx() -> PacketContext {
        PacketContext {
            src_mac: [0x72, 0xF1, 0x70, 0xD7, 0x30, 0x16],
            dst_mac: [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB],
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 2, 162)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            src_port: 5353,
            dst_port: 5353,
            vlan_id: None,
            timestamp: 0,
        }
    }

    #[test]
    fn test_mdns_can_parse() {
        let pkt = build_mdns_announcement();
        let d = DnsDissector;
        assert!(d.can_parse(&pkt, 5353, 5353));
    }

    #[test]
    fn test_mdns_txt_and_a_records() {
        let pkt = build_mdns_announcement();
        let d = DnsDissector;
        let result = d.parse(&pkt, &mdns_ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                assert!(dns.is_response);
                assert_eq!(dns.queries.len(), 0, "mDNS unsolicited has 0 questions");

                // Should have 3 records: TXT + PTR (answers) + A (additional)
                assert_eq!(dns.records.len(), 3, "records: {:#?}", dns.records);

                // TXT record with manufacturer and model
                let txt = dns.records.iter().find(|r| r.rtype == DnsRecordType::TXT);
                assert!(txt.is_some(), "expected TXT record");
                match &txt.unwrap().data {
                    DnsRecordData::Txt(entries) => {
                        assert!(
                            entries.iter().any(|e| e == "manufacturer=onn"),
                            "expected manufacturer=onn in {entries:?}"
                        );
                        assert!(
                            entries.iter().any(|e| e == "model=H508X"),
                            "expected model=H508X in {entries:?}"
                        );
                    }
                    other => panic!("expected TXT data, got {other:?}"),
                }

                // A record in additional section
                let a_rec = dns.records.iter().find(|r| r.rtype == DnsRecordType::A);
                assert!(a_rec.is_some(), "expected A record in additional");
                assert_eq!(a_rec.unwrap().name, "mydevice.local");
                match &a_rec.unwrap().data {
                    DnsRecordData::A(ip) => assert_eq!(ip, "192.168.2.162"),
                    other => panic!("expected A data, got {other:?}"),
                }
            }
            _ => panic!("expected DNS"),
        }
    }

    /// Helper: build an mDNS response with 0 questions, N answer TXT records,
    /// and 1 additional A record.
    fn build_mdns_txt_packet(
        txt_name: &str,
        txt_entries: &[&str],
        a_name: &str,
        a_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header: response, 0 questions, 1 answer (TXT), 0 ns, 1 additional (A)
        pkt.extend_from_slice(&[0x00, 0x00]); // txid
        pkt.extend_from_slice(&[0x84, 0x00]); // flags: response, auth
        pkt.extend_from_slice(&[0x00, 0x00]); // qdcount
        pkt.extend_from_slice(&[0x00, 0x01]); // ancount = 1
        pkt.extend_from_slice(&[0x00, 0x00]); // nscount
        pkt.extend_from_slice(&[0x00, 0x01]); // arcount = 1

        // Answer: TXT record
        for label in txt_name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x10]); // type TXT
        pkt.extend_from_slice(&[0x80, 0x01]); // class IN+flush
        pkt.extend_from_slice(&[0x00, 0x00, 0x11, 0x94]); // TTL
        let mut txt_rdata = Vec::new();
        for entry in txt_entries {
            txt_rdata.push(entry.len() as u8);
            txt_rdata.extend_from_slice(entry.as_bytes());
        }
        pkt.extend_from_slice(&(txt_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&txt_rdata);

        // Additional: A record
        for label in a_name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x80, 0x01]); // class IN+flush
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL
        pkt.extend_from_slice(&[0x00, 0x04]); // rdlength
        pkt.extend_from_slice(&a_ip);
        pkt
    }

    #[test]
    fn test_googlecast_txt() {
        let pkt = build_mdns_txt_packet(
            "Living Room._googlecast._tcp.local",
            &[
                "fn=Living Room TV",
                "md=Chromecast Ultra",
                "ve=05",
                "ca=200709",
            ],
            "chromecast-ultra.local",
            [192, 168, 1, 50],
        );
        let d = DnsDissector;
        assert!(d.can_parse(&pkt, 5353, 5353));
        let result = d.parse(&pkt, &mdns_ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                let txt = dns
                    .records
                    .iter()
                    .find(|r| r.rtype == DnsRecordType::TXT)
                    .unwrap();
                match &txt.data {
                    DnsRecordData::Txt(entries) => {
                        assert!(entries.iter().any(|e| e == "fn=Living Room TV"));
                        assert!(entries.iter().any(|e| e == "md=Chromecast Ultra"));
                    }
                    other => panic!("expected TXT, got {other:?}"),
                }
                let a = dns
                    .records
                    .iter()
                    .find(|r| r.rtype == DnsRecordType::A)
                    .unwrap();
                assert_eq!(a.name, "chromecast-ultra.local");
            }
            _ => panic!("expected DNS"),
        }
    }

    #[test]
    fn test_printer_ipp_txt() {
        let pkt = build_mdns_txt_packet(
            "HP LaserJet._ipp._tcp.local",
            &[
                "ty=HP LaserJet Pro MFP M428fdw",
                "usb_MFG=HP",
                "usb_MDL=LaserJet Pro MFP M428fdw",
                "product=(HP LaserJet Pro MFP M428fdw)",
                "pdl=application/postscript,application/pdf",
                "Color=T",
                "Duplex=T",
            ],
            "hplaserjet.local",
            [192, 168, 1, 100],
        );
        let d = DnsDissector;
        let result = d.parse(&pkt, &mdns_ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                let txt = dns
                    .records
                    .iter()
                    .find(|r| r.rtype == DnsRecordType::TXT)
                    .unwrap();
                match &txt.data {
                    DnsRecordData::Txt(entries) => {
                        assert!(entries.iter().any(|e| e == "usb_MFG=HP"));
                        assert!(
                            entries
                                .iter()
                                .any(|e| e == "usb_MDL=LaserJet Pro MFP M428fdw")
                        );
                        assert!(
                            entries
                                .iter()
                                .any(|e| e == "ty=HP LaserJet Pro MFP M428fdw")
                        );
                        assert!(entries.iter().any(|e| e == "Color=T"));
                    }
                    other => panic!("expected TXT, got {other:?}"),
                }
            }
            _ => panic!("expected DNS"),
        }
    }

    #[test]
    fn test_homekit_hap_txt() {
        let pkt = build_mdns_txt_packet(
            "Eve Energy._hap._tcp.local",
            &[
                "md=Eve Energy",
                "ci=7",
                "sf=0",
                "id=AA:BB:CC:DD:EE:FF",
                "c#=2",
            ],
            "eve-energy.local",
            [192, 168, 1, 75],
        );
        let d = DnsDissector;
        let result = d.parse(&pkt, &mdns_ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                let txt = dns
                    .records
                    .iter()
                    .find(|r| r.rtype == DnsRecordType::TXT)
                    .unwrap();
                match &txt.data {
                    DnsRecordData::Txt(entries) => {
                        assert!(entries.iter().any(|e| e == "md=Eve Energy"));
                        assert!(entries.iter().any(|e| e == "ci=7"));
                    }
                    other => panic!("expected TXT, got {other:?}"),
                }
            }
            _ => panic!("expected DNS"),
        }
    }

    #[test]
    fn test_sonos_txt() {
        let pkt = build_mdns_txt_packet(
            "Kitchen._sonos._tcp.local",
            &["mdl=S13", "vers=63.2-90210", "protovers=1.25.3"],
            "sonos-kitchen.local",
            [192, 168, 1, 80],
        );
        let d = DnsDissector;
        let result = d.parse(&pkt, &mdns_ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                let txt = dns
                    .records
                    .iter()
                    .find(|r| r.rtype == DnsRecordType::TXT)
                    .unwrap();
                match &txt.data {
                    DnsRecordData::Txt(entries) => {
                        assert!(entries.iter().any(|e| e == "mdl=S13"));
                        assert!(entries.iter().any(|e| e == "vers=63.2-90210"));
                    }
                    other => panic!("expected TXT, got {other:?}"),
                }
            }
            _ => panic!("expected DNS"),
        }
    }

    #[test]
    fn test_esphome_txt() {
        let pkt = build_mdns_txt_packet(
            "kitchen-sensor._esphomelib._tcp.local",
            &[
                "friendly_name=Kitchen Sensor",
                "version=2023.12.0",
                "board=esp32dev",
                "platform=ESP32",
                "mac=AABBCCDDEEFF",
            ],
            "kitchen-sensor.local",
            [192, 168, 1, 200],
        );
        let d = DnsDissector;
        let result = d.parse(&pkt, &mdns_ctx()).unwrap();
        match result {
            ProtocolData::Dns(dns) => {
                let txt = dns
                    .records
                    .iter()
                    .find(|r| r.rtype == DnsRecordType::TXT)
                    .unwrap();
                match &txt.data {
                    DnsRecordData::Txt(entries) => {
                        assert!(entries.iter().any(|e| e == "friendly_name=Kitchen Sensor"));
                        assert!(entries.iter().any(|e| e == "platform=ESP32"));
                    }
                    other => panic!("expected TXT, got {other:?}"),
                }
            }
            _ => panic!("expected DNS"),
        }
    }
}
