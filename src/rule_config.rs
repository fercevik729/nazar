use anyhow::{anyhow, Result};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::Deserialize;
use std::net::{IpAddr, Ipv6Addr};

// Submodules
pub mod custom;
pub mod structs;

use custom::CustomRule;
use structs::{BWList, IpRange, PortRange, Protocol};

// Enum used to represent intrusion detection system
// actions
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub enum IdsAction {
    Alert,
    Terminate,
    Block,
    Log,
    Nop,
}

// Hierarchy of Rule Matching
// --------------------------
// Level 1: Custom Rule with IdsAction::Alert > CustomRule with IdsAction::Terminate > ... CustomRule with
// IdsAction::Log (Packet must match all specified parameters of CustomRule - Logical AND)
// --------------------------
// Level 2: Global rules: if Packets match at least one of the specified parameters, then return
// Alert or a CustomRule's IdsAction. Otherwise return a Log action (Logical OR).

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
        // Given a pnet::IpNextHeaderProtocol it returns an Option of the Protocol enum
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
        if let Some(tcp_packet) = TcpPacket::new(body) {
            return Some((tcp_packet.get_source(), tcp_packet.get_destination()));
        }

        if let Some(udp_packet) = UdpPacket::new(body) {
            return Some((udp_packet.get_source(), udp_packet.get_destination()));
        }

        None
    }

    fn sniff_v6(&self, ipv6_packet: &Ipv6Packet) -> IdsAction {
        // A function that returns an IdsAction based on whether or not the Ipv6Packet matches the
        // global RuleConfig

        // Checks the list of CustomRules
        if let Some(custom_rules) = &self.rules {
            // Collect all the IdsActions of the custom rules that match against the current Ipv6Packet
            let mut actions: Vec<IdsAction> = custom_rules
                .iter()
                .map(|rule| rule.process_ipv6_packet(ipv6_packet))
                .filter(|action| !matches!(action, IdsAction::Nop))
                .collect();

            // If the length is nonzero sort by priority of actions
            // and return the first element in the vector
            if !actions.is_empty() {
                actions.sort();
                return actions[0];
            }
        }

        // Checks the ip addresses of the Ipv6Packet
        if let Some(ips) = &self.ip_list {
            // Check if the src_ip is in the Black/White List of ips
            let src_ip = ipv6_packet.get_source();
            if !ips.is_valid_item(IpAddr::V6(src_ip)) {
                return IdsAction::Alert;
            }

            // Check if the dest_ip is in the Black/White List of ips
            let dest_ip = ipv6_packet.get_destination();
            if !ips.is_valid_item(IpAddr::V6(dest_ip)) {
                return IdsAction::Alert;
            }
        }

        // Check the ports
        if let Some(ports) = &self.port_list {
            match RuleConfig::get_ports(ipv6_packet.packet()) {
                // No ports could be retrieved
                None => (),
                // Validate src and dest ports
                Some((src, dest)) => {
                    if !ports.is_valid_item(src) || !ports.is_valid_item(dest) {
                        return IdsAction::Alert;
                    }
                }
            }
        }

        // Check the protocol
        if let Some(prots) = &self.protocol_list {
            match RuleConfig::convert_protocols(ipv6_packet.get_next_header()) {
                // Check if the protocol is allowed, if not return false
                Some(prot) if !prots.is_valid_item(prot) => return IdsAction::Alert,
                // If unsupported or non matching Protocol
                _ => return IdsAction::Log,
            }
        }

        IdsAction::Log
    }

    fn sniff_v4(&self, ipv4_packet: &Ipv4Packet) -> IdsAction {
        // A function that returns an IdsAction based on whether or not the Ipv4Packet matches
        // the global RuleConfig

        // Checks the list of CustomRules
        if let Some(custom_rules) = &self.rules {
            // Collect all the IdsActions of the custom rules that match against the current Ipv6Packet
            let mut actions: Vec<IdsAction> = custom_rules
                .iter()
                .map(|rule| rule.process_ipv4_packet(ipv4_packet))
                .filter(|action| !matches!(action, IdsAction::Nop))
                .collect();

            // If the length is nonzero sort by priority of actions
            // and return the first element in the vector
            if !actions.is_empty() {
                actions.sort();
                return actions[0];
            }
        }
        // Check the Ips
        if let Some(ips) = &self.ip_list {
            // Check if the src_ip is in the Black/White List of ips
            let src_ip = ipv4_packet.get_source();
            if !ips.is_valid_item(IpAddr::V4(src_ip)) {
                return IdsAction::Alert;
            }

            // Check if the dest_ip is in the Black/White List of ips
            let dest_ip = ipv4_packet.get_destination();
            if !ips.is_valid_item(IpAddr::V4(dest_ip)) {
                return IdsAction::Alert;
            }
        }

        // Check the ports
        if let Some(ports) = &self.port_list {
            match RuleConfig::get_ports(ipv4_packet.packet()) {
                // No ports could be retrieved
                None => (),
                // Validate src and dest ports
                Some((src, dest)) => {
                    if !ports.is_valid_item(src) || !ports.is_valid_item(dest) {
                        return IdsAction::Alert;
                    }
                }
            }
        }

        // Check the protocol
        if let Some(prots) = &self.protocol_list {
            match RuleConfig::convert_protocols(ipv4_packet.get_next_level_protocol()) {
                // Check if the protocol is not allowed
                Some(prot) if !prots.is_valid_item(prot) => return IdsAction::Alert,
                // Unsupported or non matching Protocol
                _ => return IdsAction::Log,
            }
        }

        IdsAction::Log
    }
}
