use std::fs::{create_dir, File};
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::{ffi::OsStr, net::IpAddr};

use log::{error, info, warn};

use log::LevelFilter;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::{self, Config};

use anyhow::{anyhow, Context, Result};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::{
    datalink::{self, interfaces, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        Packet,
    },
};

pub mod rule_parser;
pub mod utils;

use rule_parser::rules::RuleConfig;

// Gets the network interface with the corresponding name or returns a default
// value
pub fn get_iface(iface: Option<String>) -> Option<NetworkInterface> {
    // Gather the network interfaces into an iterator
    let mut ifaces = interfaces().into_iter();

    // If an interface name was provided
    if let Some(iface_name) = iface {
        ifaces.find(|x| x.name == iface_name)

    // Try to find a suitable default interface
    } else {
        ifaces.find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
    }
}

// Validates a file's extension against the provided `ext` parameter
pub fn validate_file_ext(filepath: &Path, ext: &str) -> bool {
    filepath.extension() == Some(OsStr::new(ext))
}

// Parses a rule file ending in .json
pub fn parse_rules(filepath: &Path) -> Result<Box<RuleConfig>> {
    // Validate rules file extension
    // Currently only supports toml
    if !validate_file_ext(filepath, "json") {
        return Err(anyhow!("rules file must be a .json file"));
    }
    // Try opening the file
    let mut rules_file = File::open(filepath)
        .with_context(|| format!("No rules file of the name `{}` exists", &filepath.display()))?;

    // Try reading the contents of the file
    let mut contents = String::new();
    rules_file
        .read_to_string(&mut contents)
        .with_context(|| format!("Couldn't read contents from {}", &filepath.display()))?;

    // Try deserializing json file
    let rules: RuleConfig = serde_json::from_str(&contents)
        .with_context(|| "Couldn't deserialize into Rule struct".to_string())?;

    // Return rules wrapped by a box
    Ok(Box::new(rules))
}

pub struct PCap<'a> {
    rx: &'a mut dyn datalink::DataLinkReceiver,
    rules: Option<String>,
}

// Sets up the packet capture datalink receiver via a provided Ethernet interface
pub fn setup_pcap_rec(iface: &NetworkInterface) -> Result<Box<dyn datalink::DataLinkReceiver>> {
    match datalink::channel(iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(_, rx)) => Ok(rx),
        Ok(_) => Err(anyhow!("unknown channel type")),
        Err(_) => Err(anyhow!("couldn't create the datalink channel")),
    }
}

// Sets up logging using log4rs and a rotating file appender
pub fn setup_logging(
    mut log_path: std::path::PathBuf,
    window_size: u32,
    size_limit: u64,
) -> Result<()> {
    // Create log directory
    let res = create_dir(log_path.clone());
    if let Err(e) = res {
        // Only return err if it doesn't already exist
        if e.kind() != ErrorKind::AlreadyExists {
            return Err(anyhow!("{}", e.to_string()));
        }
    }
    log_path.push("logfile.gz");

    File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(log_path.clone())?;

    let fixed_window_roller =
        FixedWindowRoller::builder().build("./backups/log{}.gz", window_size)?;
    let size_trigger = SizeTrigger::new(size_limit);
    let compound_policy =
        CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));

    // log4rs config
    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Debug)))
                .build(
                    log_path.to_str().unwrap(),
                    Box::new(
                        RollingFileAppender::builder()
                            .encoder(Box::new(PatternEncoder::new("{d} {l}:{m}{n}")))
                            .build(log_path.to_str().unwrap(), Box::new(compound_policy))
                            .expect("Couldn't create RollingFileAppender"),
                    ),
                ),
        )
        .build(
            Root::builder()
                .appender(log_path.to_str().unwrap())
                .build(LevelFilter::Debug),
        )
        .with_context(|| "Couldn't create root logger".to_string())?;
    log4rs::init_config(config).expect("Failed to initialize log4rs");
    Ok(())
}

// Packet capture logic
// TODO: work on logging
// work on error recovery
// add helper functions to separate logic
// add multithreading eventually
pub fn handle_pcap(rx: &mut dyn datalink::DataLinkReceiver) {
    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                // If it is an ipv4 packet
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    handle_ipv4_packet(ipv4_packet);
                } else if eth_packet.get_ethertype() == EtherTypes::Ipv6 {
                    let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();
                    handle_ipv6_packet(ipv6_packet);
                }
            }
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn handle_tcp_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let tcp_packet = TcpPacket::new(packet);
    if let Some(tcp_packet) = tcp_packet {
        info!(
            "TCP Packet from {}:{} > {}:{}",
            src,
            tcp_packet.get_source(),
            dest,
            tcp_packet.get_destination(),
        );
    } else {
        warn!("Malformed TCP packet from {} > {}", src, dest);
    }
}

fn handle_udp_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let udp_packet = UdpPacket::new(packet);
    if let Some(udp_packet) = udp_packet {
        info!(
            "UDP Packet from {}:{} > {}:{}",
            src,
            udp_packet.get_source(),
            dest,
            udp_packet.get_destination(),
        );
    } else {
        warn!("Malformed UDP packet from {} > {}", src, dest);
    }
}

fn handle_icmp_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        info!(
            "ICMP Packet from {} > {} of type {:?} and code {:?}",
            src,
            dest,
            icmp_packet.get_icmp_type(),
            icmp_packet.get_icmp_code(),
        );
    } else {
        warn!("Malformed ICMP packet from {} > {}", src, dest);
    }
}

fn handle_icmpv6_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let icmp_packet = Icmpv6Packet::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        info!(
            "ICMPv6 Packet from {} > {} of type {:?} and code {:?}",
            src,
            dest,
            icmp_packet.get_icmpv6_type(),
            icmp_packet.get_icmpv6_code(),
        );
    } else {
        warn!("Malformed ICMPv6 packet from {} > {}", src, dest);
    }
}

fn handle_transport_protocol(
    src: IpAddr,
    dest: IpAddr,
    protocol: IpNextHeaderProtocol,
    payload: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(src, dest, payload),
        IpNextHeaderProtocols::Udp => handle_udp_packet(src, dest, payload),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(src, dest, payload),
        IpNextHeaderProtocols::Icmpv6 => handle_icmpv6_packet(src, dest, payload),
        _ => warn!("Unsupported protocol {}", protocol),
    }
}

fn handle_ipv4_packet(ipv4_packet: Ipv4Packet) {
    info!("Processing an ipv4 packet...");
    handle_transport_protocol(
        IpAddr::V4(ipv4_packet.get_source()),
        IpAddr::V4(ipv4_packet.get_destination()),
        ipv4_packet.get_next_level_protocol(),
        ipv4_packet.payload(),
    )
}

fn handle_ipv6_packet(ipv6_packet: Ipv6Packet) {
    info!("Processing an ipv6 packet...");
    handle_transport_protocol(
        IpAddr::V6(ipv6_packet.get_source()),
        IpAddr::V6(ipv6_packet.get_destination()),
        ipv6_packet.get_next_header(),
        ipv6_packet.payload(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::validate_file_ext;

    #[test]
    fn test_validate_file_ext() {
        let fp = PathBuf::from(r"/etc/config.toml");

        assert_eq!(true, validate_file_ext(&fp, "toml"));
        assert_eq!(false, validate_file_ext(&fp, "csv"));
        assert_eq!(false, validate_file_ext(&fp, "exe"));
        assert_eq!(false, validate_file_ext(&fp, "tom"));

        let fp2 = PathBuf::from(r"/etc/config");
        assert_eq!(false, validate_file_ext(&fp2, "toml"));
        assert_eq!(false, validate_file_ext(&fp2, "csv"));
        assert_eq!(false, validate_file_ext(&fp2, "exe"));
        assert_eq!(false, validate_file_ext(&fp2, "tom"));
    }
}
