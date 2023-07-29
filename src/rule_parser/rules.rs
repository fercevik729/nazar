use self::dns_rule::DnsRule;
use self::http_rule::HttpRule;
use self::icmp_rule::{IcmpRule, Icmpv6Rule};
use self::tcp_rule::TcpRule;
use self::udp_rule::UdpRule;

use super::{BWList, Deserialize, IpRange, PortRange, Protocol};

use pnet::packet::{Packet, PacketSize};
use std::{collections::HashMap, net::IpAddr};

mod dns_rule;
mod http_rule;
mod icmp_rule;
mod tcp_rule;
mod udp_rule;

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
    pub rules: Option<Vec<CustomRule>>,
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
pub struct CustomRule {
    src_ip: Option<IpAddr>,
    src_port: Option<i32>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<i32>,
    prot_rule: ProtocolRule,
    action: IdsAction,
}

impl ProcessPacket for CustomRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        // Check the IpAddrs
        //
        // Check the port numbers
        //
        // Get the result of processing the protocol rule
        //
        Some(true)
    }
}

// Enum representing custom transport layer
// and application layer protocols
#[derive(Deserialize, Debug)]
pub enum ProtocolRule {
    // Transport Protocols
    Icmp(IcmpRule),
    Icmpv6(Icmpv6Rule),
    Tcp(TcpRule),
    Udp(UdpRule),
    // Application Protocols
    Http(HttpRule),
    Dns(DnsRule),
}

impl ProcessPacket for ProtocolRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        match self {
            Self::Icmp(rule) => rule.process(body),
            Self::Icmpv6(rule) => rule.process(body),
            Self::Tcp(rule) => rule.process(body),
            Self::Udp(rule) => rule.process(body),
            Self::Http(rule) => rule.process(body),
            Self::Dns(rule) => rule.process(body),
        }
    }
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
    fn process(&self, body: &[u8]) -> Option<bool>;
}
