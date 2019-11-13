use byteorder::{ByteOrder, NetworkEndian};
use std::net::{Ipv4Addr, Ipv6Addr};

const CHUNK_PAYLOAD_START: usize = 6;

pub enum HepVersion {
    HepV1,
    HepV2,
    HepV3,
    Unknown,
}

impl std::convert::From<&[u8]> for HepVersion {
    fn from(b: &[u8]) -> Self {
        match b {
            &[01] => HepVersion::HepV1,
            &[02] => HepVersion::HepV2,
            &[48, 45, 50, 33] => HepVersion::HepV3,
            _ => HepVersion::Unknown,
        }
    }
}
#[derive(Debug, PartialEq)]
pub enum CapProtoType {
    Reserved,
    Sip,
    Xmpp,
    Sdp,
    Rtp,
    Rtcp,
    Mgcp,
    Megaco,
    Mtp2,
    Mtp3,
    Iax,
    H3222,
    H321,
    M2PA,
    MosFull,
    MosShort,
    SipJson,
    DnsJson,
    M3UaJson,
    Rtsp,
    Diameter,
    GsmMap,
}

impl std::fmt::Display for CapProtoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CapProtoType::*;
        match &self {
            Reserved => write!(f, "Reserved"),
            Sip => write!(f, "SIP"),
            Xmpp => write!(f, "XMPP"),
            Sdp => write!(f, "SDP"),
            Rtp => write!(f, "RTP"),
            Rtcp => write!(f, "RTCP"),
            Mgcp => write!(f, "MGCP"),
            Megaco => write!(f, "Megaco"),
            Mtp2 => write!(f, "MTP2"),
            Mtp3 => write!(f, "MTP3"),
            Iax => write!(f, "IAX"),
            H3222 => write!(f, "H322"),
            H321 => write!(f, "H321"),
            M2PA => write!(f, "M2PA"),
            MosFull => write!(f, "MOS Full"),
            MosShort => write!(f, "MOS Short"),
            SipJson => write!(f, "SIP JSON"),
            DnsJson => write!(f, "DNS JSON"),
            M3UaJson => write!(f, "M3UA JSON"),
            Rtsp => write!(f, "RTSP"),
            Diameter => write!(f, "Diameter"),
            GsmMap => write!(f, "GSM map"),
        }
    }
}

impl std::convert::From<u8> for CapProtoType {
    fn from(b: u8) -> Self {
        match b {
            0x00 => CapProtoType::Reserved,
            0x01 => CapProtoType::Sip,
            0x02 => CapProtoType::Xmpp,
            0x03 => CapProtoType::Sdp,
            0x04 => CapProtoType::Rtp,
            0x05 => CapProtoType::Rtcp,
            0x06 => CapProtoType::Mgcp,
            0x07 => CapProtoType::Megaco,
            0x08 => CapProtoType::Mtp2,
            0x09 => CapProtoType::Mtp3,
            0x0a => CapProtoType::Iax,
            0x0b => CapProtoType::H3222,
            0x0c => CapProtoType::H321,
            0x0d => CapProtoType::M2PA,
            0x22 => CapProtoType::MosFull,
            0x23 => CapProtoType::MosShort,
            0x32 => CapProtoType::SipJson,
            0x33 => CapProtoType::Reserved,
            0x34 => CapProtoType::Reserved,
            0x35 => CapProtoType::DnsJson,
            0x36 => CapProtoType::M3UaJson,
            0x37 => CapProtoType::Rtsp,
            0x38 => CapProtoType::Diameter,
            0x39 => CapProtoType::GsmMap,

            _ => CapProtoType::Reserved,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Chunk {
    IpProtocolFamily(u8),             //0x0001
    IpProtocolId(u8),                 //0x0002
    Ipv4SrcAddress(Ipv4Addr),         //0x0003
    Ipv4DstAddress(Ipv4Addr),         //0x0004
    Ipv6SrcAddress(Ipv6Addr),         //0x0005
    Ipv6DstAddress(Ipv6Addr),         //0x0006
    ProtoSrcPort(u16),                //0x0007
    ProtoDstPort(u16),                //0x0008
    TimestampSeconds(u32),            //0x0009
    TimestampMicroSecondsOffset(u32), //0x000a
    ProtoType(CapProtoType),          //0x000b
    CaptureAgentId(u32),              //0x000c
    KeepAliveTimer(u16),              //0x000d
    AuthenticateKey(String),          //0x000e
    PacketPayload(String),            //0x000f
    CompressedPayload(String),        //0x0010
    InternalCorrelationId(String),    //0x0011
    VlanId(u16),                      //0x0012
    GroupId(String),                  //0x0013
    SrcMac(u64),                      //0x0014
    DstMac(u64),                      //0x0015
    EthernetType(u16),                //0x0016
    TcpFlag(u8),                      //0x0017
    IpTos(u8),                        //0x0018
    MosValue(u16),                    //0x0020
    RFactor(u16),                     //0x0021
    GeoLocation(String),              //0x0022
    Jitter(u32),                      //0x0023
    TranslationType(String),          //0x0024
    PayloadJsonKeys(String),          //0x0025
    TagsValues(String),               //0x0026
    TypeOfTag(String),                //0x0027
    Reserved,                         //0x001f
}

pub fn parse_packet(packet: &[u8]) -> Result<Vec<Chunk>, ()> {
    let version = HepVersion::from(&packet[..4]);

    match version {
        HepVersion::HepV1 => {
            println!("HEP Version 1");
            parse_hep_v1(packet)
        }
        HepVersion::HepV2 => {
            println!("HEP Version 2");
            parse_hep_v2(packet)
        }
        HepVersion::HepV3 => {
            println!("HEP version 3");
            parse_hep_v3(packet)
        }
        _ => unreachable!(),
    }
}

fn parse_hep_v1(_packet: &[u8]) -> Result<Vec<Chunk>, ()> {
    let chunks = Vec::new();

    Ok(chunks)
}

fn parse_hep_v2(_packet: &[u8]) -> Result<Vec<Chunk>, ()> {
    let chunks = Vec::new();

    Ok(chunks)
}

fn parse_hep_v3(packet: &[u8]) -> Result<Vec<Chunk>, ()> {
    let mut current_byte = CHUNK_PAYLOAD_START;
    let total_len = NetworkEndian::read_u16(&packet[4..6]) as usize;

    let mut chunks = Vec::new();

    while current_byte < total_len {
        let chunk = &packet[current_byte as usize..];

        let chunk_type = NetworkEndian::read_u16(&chunk[2..4]);
        let chunk_len = NetworkEndian::read_u16(&chunk[4..6]) as usize;
        let chunk_payload = &chunk[CHUNK_PAYLOAD_START..chunk_len];

        let chunk = match chunk_type {
            0x0001 => Chunk::IpProtocolFamily(chunk_payload[0]),
            0x0002 => Chunk::IpProtocolId(chunk_payload[0]),
            0x0003 => Chunk::Ipv4SrcAddress(Ipv4Addr::new(
                chunk_payload[0],
                chunk_payload[1],
                chunk_payload[2],
                chunk_payload[3],
            )),
            0x0004 => Chunk::Ipv4DstAddress(Ipv4Addr::new(
                chunk_payload[0],
                chunk_payload[1],
                chunk_payload[2],
                chunk_payload[3],
            )),
            0x0005 => Chunk::Ipv6SrcAddress(Ipv6Addr::from(
                NetworkEndian::read_u128(&chunk_payload),
            )),
            0x0006 => Chunk::Ipv6DstAddress(Ipv6Addr::from(
                NetworkEndian::read_u128(&chunk_payload),
            )),
            0x0007 => {
                Chunk::ProtoSrcPort(NetworkEndian::read_u16(&chunk_payload))
            }
            0x0008 => {
                Chunk::ProtoDstPort(NetworkEndian::read_u16(&chunk_payload))
            }
            0x0009 => {
                Chunk::TimestampSeconds(NetworkEndian::read_u32(&chunk_payload))
            }
            0x000a => Chunk::TimestampMicroSecondsOffset(
                NetworkEndian::read_u32(&chunk_payload),
            ),

            0x000b => Chunk::ProtoType(CapProtoType::from(chunk_payload[0])),
            0x000c => {
                Chunk::CaptureAgentId(NetworkEndian::read_u32(&chunk_payload))
            }
            0x000d => {
                Chunk::KeepAliveTimer(NetworkEndian::read_u16(&chunk_payload))
            }
            0x000e => Chunk::AuthenticateKey(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or("".to_owned()),
            ),
            0x000f => Chunk::PacketPayload(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or("".to_owned()),
            ),
            0x0010 => Chunk::CompressedPayload(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or("".to_owned()),
            ),
            0x0011 => Chunk::InternalCorrelationId(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or("".to_owned()),
            ),
            0x0012 => Chunk::VlanId(NetworkEndian::read_u16(&chunk_payload)),
            0x0013 => Chunk::GroupId(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or(String::new()),
            ),
            0x0014 => Chunk::SrcMac(NetworkEndian::read_u64(&chunk_payload)),
            0x0015 => Chunk::DstMac(NetworkEndian::read_u64(&chunk_payload)),
            0x0016 => {
                Chunk::EthernetType(NetworkEndian::read_u16(&chunk_payload))
            }
            0x0017 => Chunk::TcpFlag(chunk_payload[0]),
            0x0018 => Chunk::IpTos(chunk_payload[0]),
            0x001f => Chunk::Reserved,
            0x0020 => Chunk::MosValue(NetworkEndian::read_u16(&chunk_payload)),
            0x0021 => Chunk::RFactor(NetworkEndian::read_u16(&chunk_payload)),
            0x0022 => Chunk::GeoLocation(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or(String::new()),
            ),
            0x0023 => Chunk::Jitter(NetworkEndian::read_u32(&chunk_payload)),
            0x0024 => Chunk::TranslationType(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or(String::new()),
            ),
            0x0025 => Chunk::PayloadJsonKeys(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or(String::new()),
            ),
            0x0026 => Chunk::TagsValues(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or(String::new()),
            ),
            0x0027 => Chunk::TypeOfTag(
                String::from_utf8(chunk_payload.to_vec())
                    .unwrap_or(String::new()),
            ),
            _ => Chunk::Reserved,
        };

        chunks.push(chunk);

        current_byte += chunk_len;
    }

    Ok(chunks)
}

impl std::fmt::Display for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chunk::Reserved => write!(f, "Reserved"),
            Chunk::IpProtocolFamily(b) => {
                write!(f, "IP protocol family: {}", b)
            }
            Chunk::IpProtocolId(b) => write!(f, "IP protocol ID: {}", b),
            Chunk::Ipv4SrcAddress(a) => write!(f, "IPv4 source address: {}", a),
            Chunk::Ipv4DstAddress(a) => {
                write!(f, "IPv4 destination address: {}", a)
            }
            Chunk::Ipv6SrcAddress(a) => write!(f, "IPv6 source address: {}", a),
            Chunk::Ipv6DstAddress(a) => {
                write!(f, "IPv6 destination address: {}", a)
            }
            Chunk::ProtoSrcPort(sp) => {
                write!(f, "Protocol source port: {}", sp)
            }
            Chunk::ProtoDstPort(dp) => {
                write!(f, "Protocol destination port: {}", dp)
            }
            Chunk::TimestampSeconds(s) => {
                write!(f, "Timestamp in seconds: {}", s)
            }
            Chunk::TimestampMicroSecondsOffset(s) => {
                write!(f, "Timestamp offset in microseconds: {}", s)
            }
            Chunk::ProtoType(pt) => write!(f, "Protocol type: {}", pt),
            Chunk::CaptureAgentId(ca) => write!(f, "Capture agent ID: {}", ca),
            Chunk::KeepAliveTimer(kt) => write!(f, "Keep-alive: {}", kt),
            Chunk::AuthenticateKey(_) => write!(f, "Authenticate key"),
            Chunk::PacketPayload(p) => write!(f, "Payload: {}", p),
            Chunk::CompressedPayload(p) => {
                write!(f, "Compressed payload: {}", p)
            }
            Chunk::InternalCorrelationId(id) => {
                write!(f, "Correlation ID: {}", id)
            }
            Chunk::VlanId(v) => write!(f, "VLAN: {}", v),
            Chunk::GroupId(id) => write!(f, "Group ID: {}", id),
            Chunk::SrcMac(mac) => write!(f, "Source MAC: {}", mac),
            Chunk::DstMac(mac) => write!(f, "Destination MAC: {}", mac),
            Chunk::EthernetType(t) => write!(f, "Ehernet type: {}", t),
            Chunk::TcpFlag(flag) => write!(f, "TCP flag: {}", flag),
            Chunk::IpTos(tos) => write!(f, "IP TOS: {}", tos),
            Chunk::MosValue(mos) => write!(f, "MOS: {}", mos),
            Chunk::RFactor(rf) => write!(f, "R-Factor: {}", rf),
            Chunk::GeoLocation(gl) => write!(f, "Geo-Location: {}", gl),
            Chunk::Jitter(j) => write!(f, "Jitter: {}", j),
            Chunk::TranslationType(t) => write!(f, "Translation type: {}", t),
            Chunk::PayloadJsonKeys(p) => write!(f, "Payload JSON keys: {}", p),
            Chunk::TagsValues(t) => write!(f, "Tags: {}", t),
            Chunk::TypeOfTag(t) => write!(f, "Type of tag: {}", t),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_hep_version_1() {
        assert_eq!(true, true)
    }

    #[test]
    fn parse_hep_version_2() {
        assert_eq!(true, true)
    }

    #[test]
    fn parse_hep_version_3() {
        #[rustfmt::skip]
        let packet = &[
            0x48, 0x45, 0x50, 0x33, // HepID
            0x00, 0x71, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x02, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x07, 0x11, // protocol ID = 17 (UDP)
            0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0xc0, 0xa8, 0xff, 0x0f, // IPv4 src = 192.168.255.15
            0x00, 0x00, 0x00, 0x04, 0x00, 0x0a, 0xa9, 0xfe, 0xc8, 0x0a, // IPv4 dst = 169.254.200.10
            0x00, 0x00, 0x00, 0x05, 0x00, 0x16, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48, // 2001:db8:85a3:8d3:1319:8a2e:370:7348
            0x00, 0x00, 0x00, 0x06, 0x00, 0x16, 0xf4, 0x80, 0x00, 0x00, 0x01, 0x00, 0xd0, 0x00, 0x02, 0x02, 0xb3, 0xff, 0xfe, 0x1e, 0x83, 0x29, // F480:0000:0100:00d0:0202:B3FF:FE1E:8329
            0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x2e, 0xea, // source port = 12010
            0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x13, 0xc4, // destination port = 5060
            0x00, 0x00, 0x00, 0x09, 0x00, 0x0a, 0x4e, 0x49, 0x82, 0xcb, // seconds timestamp 1313440459 = Mon Aug 15 22:34:19 2011
            0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x01, 0xd4, 0xc0, // micro-seconds timestamp offset 120000 = 0.12 seconds
            0x00, 0x00, 0x00, 0x0b, 0x00, 0x07, 0x01, // 01 – SIP
            0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xE4, // capture ID (228)
            0x00, 0x00, 0x00, 0x0f, 0x00, 0x14, 0x49, 0x4e, 0x56, 0x49, 0x54,
            0x45, 0x20, 0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f, 0x62, // SIP payload “INVITE sip:bob”
        ];

        use super::Chunk::*;

        assert_eq!(
            parse_hep_v3(packet).unwrap(),
            vec![
                IpProtocolFamily(2),
                IpProtocolId(17),
                Ipv4SrcAddress("192.168.255.15".parse().unwrap()),
                Ipv4DstAddress("169.254.200.10".parse().unwrap()),
                Ipv6SrcAddress(
                    "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap()
                ),
                Ipv6DstAddress(
                    "F480:0000:0100:d000:0202:B3FF:FE1E:8329".parse().unwrap()
                ),
                ProtoSrcPort(12010),
                ProtoDstPort(5060),
                TimestampSeconds(1313440459),
                TimestampMicroSecondsOffset(120000)
            ]
        )
    }
}
