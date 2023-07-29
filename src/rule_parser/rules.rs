use self::dns_rule::DnsRule;
use self::http_rule::HttpRule;
use self::icmp_rule::{IcmpRule, Icmpv6Rule};
use self::tcp_rule::TcpRule;
use self::udp_rule::UdpRule;

use super::{BWList, Deserialize, IpRange, PortRange, Protocol};

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, PacketSize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

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
}

impl RuleConfig {
    fn convert_protocols(prot: IpNextHeaderProtocol) -> Option<Protocol> {
        match prot {
            IpNextHeaderProtocols::Udp => Some(Protocol::Udp),
            IpNextHeaderProtocols::Tcp => Some(Protocol::Tcp),
            IpNextHeaderProtocols::Icmp => Some(Protocol::Icmp),
            IpNextHeaderProtocols::Icmpv6 => Some(Protocol::Icmpv6),
            _ => None,
        }
    }

    fn get_ports(body: &[u8]) -> Option<(u16, u16)> {
        // Gets the src and dest ports if the buffer is a TcpPacket or a UdpPacket
        let tcp_packet = TcpPacket::new(body);
        match tcp_packet {
            Some(t) => return Some((t.get_source(), t.get_destination())),
            _ => {}
        };

        let udp_packet = UdpPacket::new(body);
        match udp_packet {
            Some(u) => Some((u.get_source(), u.get_destination())),
            None => None,
        }
    }

    fn sniff_v4(&self, ipv4_packet: Ipv4Packet) -> Option<bool> {
        // Check the Ips
        if let Some(ips) = &self.ip_list {
            // Check if the src_ip is in the Black/White List of ips
            let src_ip = ipv4_packet.get_source();
            if !ips.is_valid_item(IpAddr::V4(src_ip)) {
                return Some(false);
            }

            // Check if the dest_ip is in the Black/White List of ips
            let dest_ip = ipv4_packet.get_destination();
            if !ips.is_valid_item(IpAddr::V4(dest_ip)) {
                return Some(false);
            }
        }

        // Check the ports
        if let Some(ports) = &self.port_list {
            match RuleConfig::get_ports(ipv4_packet.packet()) {
                // No ports could be retrieved
                None => return Some(false),
                // Validate src and dest ports
                Some((src, dest)) => {
                    if !ports.is_valid_item(src) {
                        return Some(false);
                    }
                    if !ports.is_valid_item(dest) {
                        return Some(false);
                    }
                }
            }
        }

        // Check the protocol
        if let Some(prots) = &self.protocol_list {
            match RuleConfig::convert_protocols(ipv4_packet.get_next_level_protocol()) {
                // Unsupported Protocol
                None => return Some(false),
                // Check if the protocol is allowed, if not return false
                Some(prot) if !prots.is_valid_item(prot) => return Some(false),
                _ => {}
            }
        }

        Some(true)
    }
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
    dest_ip: Option<IpAddr>,
    prot_rule: ProtocolRule,
    action: IdsAction,
}

impl CustomRule {
    fn match_ipv6(exp_ip: Option<IpAddr>, actual: Ipv6Addr) -> bool {
        // Checks if an optional IpAddr matches an Ipv6Addr
        match exp_ip {
            Some(IpAddr::V4(ip)) if ip.to_ipv6_mapped() != actual => false,
            Some(IpAddr::V6(ip)) if ip != actual => false,
            _ => true,
        }
    }

    fn match_ipv4(exp_ip: Option<IpAddr>, actual: Ipv4Addr) -> bool {
        // Checks if an optional IpAddr matches an Ipv4Addr
        match exp_ip {
            Some(IpAddr::V4(ip)) if ip != actual => false,
            Some(IpAddr::V6(_)) => false,
            _ => true,
        }
    }

    fn process_protocol_rule(&self, body: &[u8]) -> Option<bool> {
        match &self.prot_rule {
            ProtocolRule::Icmp(rule) => return rule.process(body),
            ProtocolRule::Icmpv6(rule) => return rule.process(body),
            ProtocolRule::Tcp(rule) => return rule.process(body),
            ProtocolRule::Udp(rule) => return rule.process(body),
            ProtocolRule::Http(rule) => return rule.process(body),
            ProtocolRule::Dns(rule) => return rule.process(body),
        };
    }

    fn get_action(&self) -> &IdsAction {
        &self.action
    }
}

impl ProcessPacket for CustomRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        if let Some(ip_packet) = Ipv6Packet::new(body) {
            // Check the IpAddrs
            if !CustomRule::match_ipv6(self.src_ip, ip_packet.get_source()) {
                return Some(false);
            }
            if !CustomRule::match_ipv6(self.dest_ip, ip_packet.get_destination()) {
                return Some(false);
            }

            // Get the result of processing the protocol rule
            return self.process_protocol_rule(body);
        }

        if let Some(ip_packet) = Ipv4Packet::new(body) {
            // Check the IpAddrs
            if !CustomRule::match_ipv4(self.src_ip, ip_packet.get_source()) {
                return Some(false);
            }
            if !CustomRule::match_ipv4(self.dest_ip, ip_packet.get_destination()) {
                return Some(false);
            }

            // Get the result of processing the protocol rule
            return self.process_protocol_rule(body);
        }
        None
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
