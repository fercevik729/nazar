use super::{BWList, Deserialize, IpRange, PortRange, Protocol, Result};

use anyhow::anyhow;
use etherparse::{self, Icmpv4Type};
use httparse::Status;
use pnet::packet::tcp::{self, TcpPacket};
use std::{collections::HashMap, fmt, net::IpAddr};

#[derive(Deserialize, Debug)]
pub struct RuleConfig {
    /// Option-al blacklist or whitelist of source
    /// and destination IP Addresses
    pub ip_list: Option<BWList<IpRange>>,
    /// Option-al blacklist or whitelist of source
    /// and destination ports
    pub port_list: Option<BWList<PortRange>>,
    /// Option-al blacklist or whitelist of protocols
    pub protocol_list: Option<BWList<Protocol>>,
    /// Option-al vector of user-defined rules
    pub rules: Option<Vec<Rule>>,
    // Option-al threshold to prevent SYN flood attacks
    pub syn_threshold: Option<u64>,
}

// Enum used to represent intrusion detection system
// actions
// TODO: implement Action-specific packet processing functions
#[derive(Deserialize, Debug)]
pub enum IdsAction {
    Alert,
    Log,
    Block,
    Terminate,
    Whitelist,
    Blacklist,
}

#[derive(Deserialize, Debug)]
pub struct Rule {
    src_ip: Option<IpAddr>,
    src_port: Option<i32>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<i32>,
    prot_rule: ProtocolRule,
    action: IdsAction,
}

// Enum representing custom transport layer
// and application layer protocols
#[derive(Deserialize, Debug)]
pub enum ProtocolRule {
    // Transport Protocols
    Icmp(IcmpRule),
    Icmpv6(Icmpv6Rule),
    Tcp(TcpRule),
    Udp,
    // Application Protocols
    Http(HttpRule),
    Dns(DnsRule),
}

// Struct that represents a vector of string patterns
#[derive(Deserialize, Debug)]
struct Patterns(Vec<String>);

impl Patterns {
    fn match_exists(&self, target: &[u8]) -> bool {
        // Function that returns true if at least of one the string patterns are
        // contained by `target`
        for p in &self.0 {
            if target.windows(p.len()).any(|window| window == p.as_bytes()) {
                return true;
            }
        }
        false
    }
}

// A trait indicating that the type which implements is capable of processing request packets
trait ProcessPacket {
    fn process(&self, body: &[u8]) -> Result<bool>;
}

// Enum representing TCP Options
#[derive(Deserialize, Debug)]
enum TcpOption {
    /// Maximum segment size
    MSS,
    /// Window scale
    WSCALE,
    /// Selective acknowledgment
    SACK,
    /// End of Options list
    EOL,
    /// Timestamps
    TIMESTAMPS,
    /// No operation
    NOP,
}

#[derive(Deserialize, Debug)]
pub struct TcpRule {
    options: Option<Vec<TcpOption>>,
    flags: Option<u16>,
    max_window_size: Option<u16>,
    max_payload_size: Option<u32>,
}

impl TcpRule {
    fn new(
        options: Option<Vec<TcpOption>>,
        flags: Option<u16>,
        max_window_size: Option<u16>,
        max_payload_size: Option<u32>,
    ) -> Self {
        Self {
            options,
            flags,
            max_window_size,
            max_payload_size,
        }
    }

    fn match_opts(&self, x: tcp::TcpOptionPacket) -> bool {
        // If tcp options are specified in the rule, this function will return true
        // if at least one of the options are contained in the packet, otherwise it will
        // return false
        // If no tcp options are specified in the rule, this function will also return true
        // since in this case any TCP option is valid
        if let Some(rule_options) = &self.options {
            return rule_options.iter().any(|ro| match ro {
                TcpOption::MSS => x.get_number() == tcp::TcpOptionNumbers::MSS,
                TcpOption::EOL => x.get_number() == tcp::TcpOptionNumbers::EOL,
                TcpOption::NOP => x.get_number() == tcp::TcpOptionNumbers::NOP,
                TcpOption::SACK => x.get_number() == tcp::TcpOptionNumbers::SACK,
                TcpOption::WSCALE => x.get_number() == tcp::TcpOptionNumbers::WSCALE,
                TcpOption::TIMESTAMPS => x.get_number() == tcp::TcpOptionNumbers::TIMESTAMPS,
            });
        }

        true
    }
}

impl ProcessPacket for TcpRule {
    fn process(&self, body: &[u8]) -> Result<bool> {
        // Assumes that the packet is some kind of TCP Packet though not necessarily a valid one
        // The function parses the byte slice into a TcpPacket struct using the
        // pnet library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        // Try to make a TCP Packet
        if let Some(tcp_packet) = TcpPacket::new(body) {
            // Check the options
            if !tcp_packet.get_options_iter().any(|x| self.match_opts(x)) {
                return Ok(false);
            }

            // Check the window size
            if let Some(max_window_size) = self.max_window_size {
                if max_window_size < tcp_packet.get_window() {
                    return Ok(false);
                }
            }

            // Check the flags
            if let Some(flags) = self.flags {
                return Ok((flags & tcp_packet.get_flags()) > 0);
            }

            // TODO:
            // Check the payload
            //
            // Check the checksum
            //

            Ok(true)
        } else {
            Err(anyhow!("Unable to parse TCP Packet"))
        }
    }
}

#[cfg(test)]
mod tcp_tests {
    use pnet::packet::{tcp::MutableTcpPacket, Packet};

    use super::*;

    const TCP_PACKET_LEN: usize = 30;
    const TCP_PACKET_OFS: u8 = 10;

    #[test]
    fn test_tcp_process_packet_1() -> Result<()> {
        // Tests for TCP options in particular
        // 1 option - matches
        let rule = TcpRule::new(Some(vec![TcpOption::NOP]), None, None, None);
        let buff: Vec<u8> = vec![0; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet.set_options(&[tcp::TcpOption::nop()]);

        assert!(rule.process(tcp_packet.packet())?);

        // 2 options - at least 1 matches
        let buff_2: Vec<u8> = vec![0; TCP_PACKET_LEN];
        let mut tcp_packet_2 = MutableTcpPacket::owned(buff_2).unwrap();
        tcp_packet_2.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet_2.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet_2.set_options(&[tcp::TcpOption::nop(), tcp::TcpOption::sack_perm()]);

        assert!(rule.process(tcp_packet_2.packet())?);

        // 2 options - don't match
        let buff_3: Vec<u8> = vec![0; TCP_PACKET_LEN];
        let mut tcp_packet_3 = MutableTcpPacket::owned(buff_3).unwrap();
        tcp_packet_3.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet_3.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet_3.set_options(&[tcp::TcpOption::mss(3), tcp::TcpOption::sack_perm()]);

        assert!(!rule.process(tcp_packet_3.packet())?);
        Ok(())
    }

    #[test]
    fn test_tcp_process_packet_2() -> Result<()> {
        // Tests for TCP Flags in particular
        // 1 flag - matches
        let rule = TcpRule::new(Some(vec![TcpOption::MSS]), Some(0x02), None, None);
        let buff: Vec<u8> = vec![0; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS);
        tcp_packet.set_flags(tcp::TcpFlags::SYN);
        tcp_packet.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(rule.process(tcp_packet.packet())?);

        // 1 flag - doesn't match
        let buff_2: Vec<u8> = vec![0; TCP_PACKET_LEN];
        let mut tcp_packet_2 = MutableTcpPacket::owned(buff_2).unwrap();
        tcp_packet_2.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_2.set_flags(tcp::TcpFlags::ACK);
        tcp_packet_2.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(!rule.process(tcp_packet_2.packet())?);

        // 3 flags - at least 1 match
        let buff_3: Vec<u8> = vec![0; TCP_PACKET_LEN];
        let mut tcp_packet_3 = MutableTcpPacket::owned(buff_3).unwrap();
        tcp_packet_3.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_3.set_flags(tcp::TcpFlags::ACK | tcp::TcpFlags::SYN | tcp::TcpFlags::URG);
        tcp_packet_3.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(rule.process(tcp_packet_3.packet())?);

        // 3 flags - none match
        let buff_4: Vec<u8> = vec![0; TCP_PACKET_LEN];
        let mut tcp_packet_4 = MutableTcpPacket::owned(buff_4).unwrap();
        tcp_packet_4.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_4.set_flags(tcp::TcpFlags::ACK | tcp::TcpFlags::ECE | tcp::TcpFlags::URG);
        tcp_packet_4.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(!rule.process(tcp_packet_4.packet())?);

        Ok(())
    }
}

// Enum representing the different kinds of ICMPv6 Requests
#[derive(Deserialize, Debug)]
enum Icmpv6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    Unknown,
}

// Struct representing a rule to match against ICMPv6 packets
#[derive(Deserialize, Debug)]
pub struct Icmpv6Rule {
    icmpv6_types: Option<Vec<Icmpv6Type>>,
    icmpv6_codes: Option<Vec<u8>>,
}

impl Icmpv6Rule {
    fn new(icmpv6_types: Option<Vec<Icmpv6Type>>, icmpv6_codes: Option<Vec<u8>>) -> Self {
        Self {
            icmpv6_types,
            icmpv6_codes,
        }
    }
}

fn match_icmpv6_types(curr: &Icmpv6Type, target: &etherparse::Icmpv6Type) -> bool {
    // Helper function to match the ICMPv6 type of the packet with that of the rules
    match curr {
        Icmpv6Type::ParameterProblem => {
            matches!(target, etherparse::Icmpv6Type::ParameterProblem(_))
        }
        Icmpv6Type::TimeExceeded => matches!(target, etherparse::Icmpv6Type::TimeExceeded(_)),
        Icmpv6Type::DestinationUnreachable => {
            matches!(target, etherparse::Icmpv6Type::DestinationUnreachable(_))
        }
        Icmpv6Type::EchoReply => matches!(target, etherparse::Icmpv6Type::EchoReply(_)),
        Icmpv6Type::EchoRequest => matches!(target, etherparse::Icmpv6Type::EchoRequest(_)),
        Icmpv6Type::PacketTooBig => matches!(target, etherparse::Icmpv6Type::PacketTooBig { .. }),
        Icmpv6Type::Unknown => matches!(target, etherparse::Icmpv6Type::Unknown { .. }),
    }
}

impl ProcessPacket for Icmpv6Rule {
    fn process(&self, body: &[u8]) -> Result<bool> {
        // Assumes that the packet is some kind of ICMPv6 Packet though not necessarily a valid one
        // The function parses the byte slice into a etherparse::Icmpv6Slice struct using the
        // etherparse library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        //
        // Parse request
        let icmp_packet: etherparse::Icmpv6Slice = etherparse::Icmpv6Slice::from_slice(body)?;

        // Check the ICMPv6 headers
        if let Some(headers) = &self.icmpv6_types {
            let target = icmp_packet.header();
            if !headers
                .iter()
                .any(|header| match_icmpv6_types(header, &target.icmp_type))
            {
                return Ok(false);
            }
        }

        // Check the ICMPv6 codes
        if let Some(codes) = &self.icmpv6_codes {
            let target = &icmp_packet.code_u8();
            if !codes.iter().any(|c| c == target) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

// Enum representing the different kinds of ICMPv4 Requests
#[derive(Deserialize, Debug)]
enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    Redirect,
    TimeExceeded,
    ParameterProblem,
    TimestampRequest,
    TimestampReply,
    Unknown,
}

// Struct representing a rule to match against ICMPv4 packets
#[derive(Deserialize, Debug)]
pub struct IcmpRule {
    // Option-al vector of ICMPv4 Types that correspond to the different possible
    // ICMPv4 headers this rule should match
    icmp_types: Option<Vec<IcmpType>>,
    // Option-al vector of ICMPv4 codes that correspond to the different possible
    // ICMPv4 codes in headers this rule should match
    icmp_codes: Option<Vec<u8>>,
}

impl IcmpRule {
    fn new(icmp_types: Option<Vec<IcmpType>>, icmp_codes: Option<Vec<u8>>) -> Self {
        Self {
            icmp_types,
            icmp_codes,
        }
    }
}

fn match_icmpv4_types(curr: &IcmpType, target: &Icmpv4Type) -> bool {
    // Helper function to match the ICMPv4 type of the packet with that of the rules
    match curr {
        IcmpType::EchoReply => matches!(target, Icmpv4Type::EchoReply(_)),
        IcmpType::EchoRequest => matches!(target, Icmpv4Type::EchoRequest(_)),
        IcmpType::DestinationUnreachable => matches!(target, Icmpv4Type::DestinationUnreachable(_)),
        IcmpType::Redirect => matches!(target, Icmpv4Type::Redirect(_)),
        IcmpType::TimeExceeded => matches!(target, Icmpv4Type::TimeExceeded(_)),
        IcmpType::TimestampReply => matches!(target, Icmpv4Type::TimestampReply(_)),
        IcmpType::TimestampRequest => matches!(target, Icmpv4Type::TimestampRequest(_)),
        IcmpType::ParameterProblem => matches!(target, Icmpv4Type::ParameterProblem(_)),
        IcmpType::Unknown => matches!(target, Icmpv4Type::Unknown { .. }),
    }
}

impl ProcessPacket for IcmpRule {
    fn process(&self, body: &[u8]) -> Result<bool> {
        // Assumes that the packet is some kind of ICMPv4 Packet though not necessarily a valid one
        // The function parses the byte slice into a etherparse::Icmpv4Slice struct using the
        // etherparse library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        //
        // Parse request
        let icmp_packet: etherparse::Icmpv4Slice = etherparse::Icmpv4Slice::from_slice(body)?;

        // Check the ICMPv4 headers
        if let Some(headers) = &self.icmp_types {
            let target = icmp_packet.header();
            if !headers
                .iter()
                .any(|header| match_icmpv4_types(header, &target.icmp_type))
            {
                return Ok(false);
            }
        }

        // Check the ICMPv4 codes
        if let Some(codes) = &self.icmp_codes {
            let target = &icmp_packet.code_u8();
            if !codes.iter().any(|c| c == target) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod icmp_tests {

    use super::IcmpType;
    use super::*;
    use pnet::{
        packet::Packet,
        packet::{
            icmp::{echo_request, time_exceeded, IcmpType as pnetIcmpType},
            icmpv6::{Icmpv6Types, MutableIcmpv6Packet},
        },
    };

    #[test]
    fn test_icmpv4_1() -> Result<()> {
        let mut buffer = [0u8; 64];
        let mut icmp_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();
        icmp_packet.set_icmp_type(pnetIcmpType(8));

        let binding = icmp_packet.to_immutable();
        let icmp_bytes = binding.packet();
        let icmpv4_rule =
            IcmpRule::new(Some(vec![IcmpType::EchoRequest, IcmpType::EchoReply]), None);
        assert!(icmpv4_rule.process(&icmp_bytes)?);
        Ok(())
    }

    #[test]
    fn test_icmpv4_2() -> Result<()> {
        let mut buffer = [0u8; 64];
        let mut icmp_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();
        icmp_packet.set_icmp_type(pnetIcmpType(8));

        let binding = icmp_packet.to_immutable();
        let icmp_bytes = binding.packet();
        let icmpv4_rule = IcmpRule::new(
            Some(vec![IcmpType::TimeExceeded, IcmpType::EchoReply]),
            None,
        );
        assert!(!icmpv4_rule.process(&icmp_bytes)?);
        Ok(())
    }

    #[test]
    fn test_icmpv4_3() -> Result<()> {
        let mut buffer = [0u8; 64];
        let mut icmp_packet = time_exceeded::MutableTimeExceededPacket::new(&mut buffer).unwrap();
        icmp_packet.set_icmp_type(pnetIcmpType(0));

        let binding = icmp_packet.to_immutable();
        let icmp_bytes = binding.packet();
        let icmpv4_rule = IcmpRule::new(
            Some(vec![IcmpType::TimeExceeded, IcmpType::EchoReply]),
            None,
        );
        assert!(icmpv4_rule.process(&icmp_bytes)?);
        Ok(())
    }

    #[test]
    fn test_icmpv6_1() -> Result<()> {
        let mut buffer = [0u8; 64];
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::PacketTooBig);

        let binding = icmpv6_packet.to_immutable();
        let icmpv6_bytes = binding.packet();
        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            None,
        );

        assert!(icmpv6_rule.process(icmpv6_bytes)?);
        Ok(())
    }

    #[test]
    fn test_icmpv6_2() -> Result<()> {
        let mut buffer = [0u8; 64];
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);

        let binding = icmpv6_packet.to_immutable();
        let icmpv6_bytes = binding.packet();
        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            None,
        );

        assert!(!icmpv6_rule.process(icmpv6_bytes)?);
        Ok(())
    }

    #[test]
    fn test_icmpv6_3() -> Result<()> {
        let mut buffer = [0u8; 64];
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::PacketTooBig);

        let binding = icmpv6_packet.to_immutable();
        let icmpv6_bytes = binding.packet();
        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            Some(vec![1, 2, 55]),
        );

        assert!(!icmpv6_rule.process(icmpv6_bytes)?);
        Ok(())
    }

    #[test]
    fn test_icmpv6_4() -> Result<()> {
        // First packet
        let mut buffer_1 = [0u8; 64];
        let mut icmpv6_packet_1 = MutableIcmpv6Packet::new(&mut buffer_1).unwrap();
        icmpv6_packet_1.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        let binding_1 = icmpv6_packet_1.to_immutable();
        let icmpv6_bytes_1 = binding_1.packet();

        // Second packet
        let mut buffer_2 = [0u8; 64];
        let mut icmpv6_packet_2 = MutableIcmpv6Packet::new(&mut buffer_2).unwrap();
        icmpv6_packet_2.set_icmpv6_type(Icmpv6Types::EchoRequest);
        let binding_2 = icmpv6_packet_2.to_immutable();
        let icmpv6_bytes_2 = binding_2.packet();

        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            Some(vec![0, 1, 2, 55]),
        );

        assert!(icmpv6_rule.process(icmpv6_bytes_1)?);
        assert!(!icmpv6_rule.process(icmpv6_bytes_2)?);

        Ok(())
    }
}

#[derive(Deserialize, Debug)]
enum DnsType {
    A,
    Ns,
    Mx,
    Cname,
    Soa,
    Wks,
    Ptr,
    Minfo,
    Aaaa,
    Srv,
    Axfr,
    All,
}

// Struct to represent a DNS Rule
#[derive(Deserialize, Debug)]
pub struct DnsRule {
    // Option-al Patterns struct of DNS query_names
    // If it is None, then any DNS query name is matched
    // Otherwise, if specified only requests that contain
    // at least one of the patterns will match the rule
    query_names: Option<Patterns>,
    // Option-al vector of DNS Types to represent Query types
    // If None, then any query type is matched
    // Otherwise, the request must match at least one
    // of the query types
    query_types: Option<Vec<DnsType>>,
    // Option-al vector of DNS Types to represent Record types
    // If None, then any resource type is matched
    // Otherwise, the request must match at least one of the query
    // types
    record_types: Option<Vec<DnsType>>,
}

impl DnsRule {
    fn new(
        query_names: Option<Vec<String>>,
        query_types: Option<Vec<DnsType>>,
        record_types: Option<Vec<DnsType>>,
    ) -> Self {
        // Constructor of a DNS Rule
        // Takes in all Option-al parameters and returns a new DnsRule struct
        Self {
            query_names: query_names.map(Patterns),
            query_types,
            record_types,
        }
    }

    fn qtype_matches(&self, target_query_type: dns_parser::QueryType) -> bool {
        // A helper method that iterates over all the query types in the rule
        // and sees if any match the target_query_type, if so it returns true
        // otherwise false. If query_types is None it returns true
        if let Some(query_types) = &self.query_types {
            return query_types.iter().any(|q| match q {
                DnsType::A => target_query_type == dns_parser::QueryType::A,
                DnsType::Ns => target_query_type == dns_parser::QueryType::NS,
                DnsType::Mx => target_query_type == dns_parser::QueryType::MX,
                DnsType::Cname => target_query_type == dns_parser::QueryType::CNAME,
                DnsType::Soa => target_query_type == dns_parser::QueryType::SOA,
                DnsType::Wks => target_query_type == dns_parser::QueryType::WKS,
                DnsType::Ptr => target_query_type == dns_parser::QueryType::PTR,
                DnsType::Minfo => target_query_type == dns_parser::QueryType::MINFO,
                DnsType::Aaaa => target_query_type == dns_parser::QueryType::AAAA,
                DnsType::Srv => target_query_type == dns_parser::QueryType::SRV,
                DnsType::Axfr => target_query_type == dns_parser::QueryType::AXFR,
                DnsType::All => target_query_type == dns_parser::QueryType::All,
            });
        }

        // Return true if no query types are specified
        true
    }

    fn rtype_matches(&self, target_resource_type: &dns_parser::RData) -> bool {
        // A helper method that iterates over all the record data types in the rule
        // and sees if any match the target_resource_type. If so it returns true
        // otherwise false.
        if let Some(r_types) = &self.record_types {
            return r_types.iter().any(|r| match r {
                DnsType::A => matches!(target_resource_type, dns_parser::RData::A(_)),
                DnsType::Ns => matches!(target_resource_type, dns_parser::RData::NS(_)),
                DnsType::Mx => matches!(target_resource_type, dns_parser::RData::MX(_)),
                DnsType::Cname => matches!(target_resource_type, dns_parser::RData::CNAME(_)),
                DnsType::Soa => matches!(target_resource_type, dns_parser::RData::SOA(_)),
                DnsType::Ptr => matches!(target_resource_type, dns_parser::RData::PTR(_)),
                DnsType::Aaaa => matches!(target_resource_type, dns_parser::RData::AAAA(_)),
                DnsType::Srv => matches!(target_resource_type, dns_parser::RData::SRV(_)),
                _ => false,
            });
        }

        // Return true if no record types are specified
        true
    }
}

impl ProcessPacket for DnsRule {
    fn process(&self, body: &[u8]) -> Result<bool> {
        // Assumes that the packet is some kind of DNS Packet over UDP/53 or TCP/53
        // though not necessarily a valid one
        //
        // The function parses the byte slice into a dns_parser::Packet struct using the
        // dns_parser library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        //
        // Parse request
        let dns_request = dns_parser::Packet::parse(body)?;
        // Iterate over all the questions in the DNS packet and see if any match
        // the patterns specified in the DNS rule
        let questions = dns_request.questions;
        if let Some(q_patterns) = &self.query_names {
            if !questions
                .iter()
                .any(|q| q_patterns.match_exists(q.qname.to_string().as_bytes()))
            {
                return Ok(false);
            }
        }
        // Iterate over all the questions in the DNS packet and see if any match
        // one of the query types specified in the DNS Rule
        if self.query_types.is_some() && !questions.iter().any(|q| self.qtype_matches(q.qtype)) {
            return Ok(false);
        }

        // Iterate over all the answer records in the DNS packet and see if any match
        // one of the record types specified in the DNS Rule
        if self.record_types.is_some()
            && !dns_request
                .answers
                .iter()
                .any(|a| self.rtype_matches(&a.data))
        {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn test_dns_process_packet_1() -> Result<()> {
        let rule = DnsRule::new(
            Some(vec![String::from("malicious.com")]),
            Some(vec![DnsType::A]),
            None,
        );
        let mut builder = dns_parser::Builder::new_query(1, false);
        builder.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet = builder.build().unwrap_or_else(|x| x);
        assert!(rule.process(&dns_packet)?);

        let mut builder2 = dns_parser::Builder::new_query(2, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::AAAA,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);
        assert!(!rule.process(&dns_packet2)?);

        Ok(())
    }

    #[test]
    fn test_dns_process_packet_2() -> Result<()> {
        let rule = DnsRule::new(
            Some(vec![
                String::from("suspicious.com"),
                String::from("evil.com"),
            ]),
            Some(vec![DnsType::Aaaa, DnsType::Soa]),
            None,
        );
        let mut builder = dns_parser::Builder::new_query(1, false);
        builder.add_question(
            "evil.com",
            false,
            dns_parser::QueryType::SOA,
            dns_parser::QueryClass::IN,
        );
        let dns_packet = builder.build().unwrap_or_else(|x| x);
        assert!(rule.process(&dns_packet)?);

        let mut builder2 = dns_parser::Builder::new_query(1, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);

        assert!(!rule.process(&dns_packet2)?);

        Ok(())
    }

    #[test]
    fn test_dns_process_packet_3() -> Result<()> {
        let rule = DnsRule::new(
            Some(vec![
                String::from("suspicious.com"),
                String::from("malicious.net"),
            ]),
            Some(vec![DnsType::A, DnsType::Aaaa]),
            Some(vec![DnsType::A]),
        );

        let mut builder = dns_parser::Builder::new_query(1, false);
        builder.add_question(
            "malicious.net",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet = builder.build().unwrap_or_else(|x| x);
        assert!(!rule.process(&dns_packet)?);

        let mut builder2 = dns_parser::Builder::new_query(1, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);

        assert!(!rule.process(&dns_packet2)?);
        Ok(())
    }
}

// Enum to represent HTTP Methods
#[derive(Deserialize, Debug)]
enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Connection,
    Options,
    Trace,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Head => write!(f, "HEAD"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
            Self::Connection => write!(f, "CONNECTION"),
            Self::Options => write!(f, "OPTIONS"),
            Self::Trace => write!(f, "TRACE"),
        }
    }
}

// Struct to represent an HTTP rule
#[derive(Deserialize, Debug)]
pub struct HttpRule {
    // Option-al HTTP method.
    // If it is None then any HTTP method is allowed
    // Otherwise, if it is specified only requests with
    // that particular method match the rule
    method: Option<HttpMethod>,
    // Option-al HashMap of HTTP Headers and suspicious
    // Header values. If it is None then any HTTP header
    // matches the rule
    headers_contain: Option<HashMap<String, String>>,
    // Option-al Patterns struct that contains suspicious
    // patterns that might exist in the URI path
    path_contains: Option<Patterns>,
    // Option-al Patterns struct that contains suspicious
    // patterns that might exist in the Request body
    body_contains: Option<Patterns>,
}

impl HttpRule {
    fn new(
        // Constructor for HTTP Rule
        // Takes in all Option-al parameters and returns a new
        // HttpRule struct
        method: Option<HttpMethod>,
        headers_contain: Option<HashMap<String, String>>,
        path_patterns: Option<Vec<String>>,
        body_patterns: Option<Vec<String>>,
    ) -> Self {
        Self {
            method,
            headers_contain,
            path_contains: path_patterns.map(Patterns),
            body_contains: body_patterns.map(Patterns),
        }
    }
}

impl ProcessPacket for HttpRule {
    fn process(&self, body: &[u8]) -> Result<bool> {
        // Assumes that packet is some kind of HTTP Packet on port 80 or 8080
        // though not necessarily a valid one.
        //
        // The function parses the byte slice into a Request struct using the httparse
        // library. It returns an error if something went wrong parsing the required
        // fields of the HTTP request
        //
        // All parameters in the Rule struct are optional, and if not provided explicitly
        // this function will not check the request for those parameters.
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of their subfields as well as needed.
        //
        // Parse request
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        let res = req.parse(body)?;

        // Check the request method and see if it matches if one was provided in the Rules struct
        match req.method {
            Some(m) => {
                if let Some(rm) = &self.method {
                    if m != rm.to_string() {
                        return Ok(false);
                    }
                }
            }
            None => {
                return Err(anyhow!(
                    "Malformed HTTP Request, no method field could be parsed"
                ))
            }
        };
        // Check the request path
        // Must match at least one of the patterns in the path_contains field
        match req.path {
            Some(p) => {
                if let Some(rp) = &self.path_contains {
                    if !rp.match_exists(p.as_bytes()) {
                        return Ok(false);
                    }
                }
            }
            None => {
                return Err(anyhow!(
                    "Malformed HTTP request, no path field could be parsed"
                ))
            }
        };

        // Check the headers and make sure at least one of the header values is
        // in the request. Quit early once this header is found
        if let Some(map) = &self.headers_contain {
            let mut found = false;
            for (header, target) in map.iter() {
                // Find a header with a matching name in the request
                let value = req.headers.iter().find(|&x| x.name == header);
                if let Some(fnd) = value {
                    found = fnd
                        .value
                        .windows(target.len())
                        .any(|window| window == target.as_bytes());
                    // Break after the first match
                    if found {
                        break;
                    }
                }
            }

            // If no headers with matching values could be found in the
            // request, return false
            if !found {
                return Ok(false);
            }
        }

        // Check the request body for the pattern
        // Must contain at least one match
        // If the body is empty/nonexistent but there
        // are patterns in the rule the function should
        // return false
        if let Status::Complete(ofs) = res {
            if let Some(bp) = &self.body_contains {
                return Ok(bp.match_exists(&body[ofs..]));
            }
        } else if self.body_contains.is_some() {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use crate::hashmap;

    #[test]
    fn test_http_process_packet_1() -> Result<()> {
        let req = b"POST nazar.com/api/user HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: 25\r\n\
                        \r\n\
                        {\"username\":\"john\",\"password\":\"secret\"}";

        let rule = HttpRule::new(Some(HttpMethod::Post), None, None, None);
        assert!(rule.process(req)?);

        let rule_2 = HttpRule::new(
            Some(HttpMethod::Post),
            None,
            None,
            Some(vec![String::from("secret"), String::from("missing")]),
        );
        assert!(rule_2.process(req)?);

        Ok(())
    }

    #[test]
    fn test_http_process_packet_2() -> Result<()> {
        let req = b"POST /api/user HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: 25\r\n\
                        \r\n\
                        {\"username\":\"john\",\"password\":\"secret\"}";
        let rule = HttpRule::new(
            Some(HttpMethod::Post),
            Some(hashmap! {
                String::from("Host") => String::from("example.com"),
                String::from("Content-Type") => String::from("text/html")
            }),
            Some(vec![String::from("/api"), String::from("/usr")]),
            Some(vec![String::from("secret"), String::from("jenn")]),
        );
        assert!(rule.process(req)?);

        let rule2 = HttpRule::new(
            Some(HttpMethod::Post),
            None,
            Some(vec![String::from("/secrete")]),
            None,
        );

        assert!(!rule2.process(req)?);

        Ok(())
    }

    #[test]
    fn test_http_process_packet_3() -> Result<()> {
        let req = b"GET /virus/download.php HTTP/1.1\r\n\
                    Host: sussy.com\r\n";

        let rule = HttpRule::new(
            Some(HttpMethod::Get),
            Some(hashmap! {
                String::from("Host") => String::from("sussy.com"),
                String::from("Non-existent-Header") => String::from("malicious-value")
            }),
            Some(vec![String::from("/virus"), String::from("php")]),
            None,
        );

        assert!(rule.process(req)?);

        let rule_2 = HttpRule::new(
            Some(HttpMethod::Get),
            Some(hashmap! {
                String::from("Host") => String::from("sussy.com")
            }),
            None,
            Some(vec![String::from("Non existent body Value")]),
        );

        assert!(!rule_2.process(req)?);

        Ok(())
    }
}
