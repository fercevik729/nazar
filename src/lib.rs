extern crate anyhow;
extern crate pnet;

use std::path::Path;
use std::{ffi::OsStr, net::IpAddr};

use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
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

use anyhow::{anyhow, Result};

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

// Sets up the packet capture datalink receiver via a provided Ethernet interface
pub fn setup_pcap_rec(iface: &NetworkInterface) -> Result<Box<dyn datalink::DataLinkReceiver>> {
    match datalink::channel(iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(_, rx)) => Ok(rx),
        Ok(_) => Err(anyhow!("unknown channel type")),
        Err(_) => Err(anyhow!("couldn't create the datalink channel")),
    }
}

// Packet capture logic
// TODO: work on logging
// work on error recovery
// add helper functions to separate logic
// add multithreading eventually
pub fn handle_pcap(rx: &mut dyn datalink::DataLinkReceiver, _: std::path::PathBuf) {
    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                // If it is an ipv4 packet
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    process_ipv4_packet(ipv4_packet);
                } else if eth_packet.get_ethertype() == EtherTypes::Ipv6 {
                    let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();
                    process_ipv6_packet(ipv6_packet);
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn process_tcp_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let tcp_packet = TcpPacket::new(packet);
    if let Some(tcp_packet) = tcp_packet {
        println!(
            "TCP Packet from {}:{} > {}:{}",
            src,
            tcp_packet.get_source(),
            dest,
            tcp_packet.get_destination(),
        );
    } else {
        println!("[WARN] Malformed TCP packet from {} > {}", src, dest);
    }
}

fn process_udp_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let udp_packet = UdpPacket::new(packet);
    if let Some(udp_packet) = udp_packet {
        println!(
            "UDP Packet from {}:{} > {}:{}",
            src,
            udp_packet.get_source(),
            dest,
            udp_packet.get_destination(),
        );
    } else {
        println!("[WARN] Malformed UDP packet from {} > {}", src, dest);
    }
}

fn process_icmp_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        println!(
            "ICMP Packet from {} > {} of type {:?} and code {:?}",
            src,
            dest,
            icmp_packet.get_icmp_type(),
            icmp_packet.get_icmp_code(),
        );
    } else {
        println!("[WARN] Malformed ICMP packet from {} > {}", src, dest);
    }
}

fn process_icmpv6_packet(src: IpAddr, dest: IpAddr, packet: &[u8]) {
    let icmp_packet = Icmpv6Packet::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        println!(
            "ICMPv6 Packet from {} > {} of type {:?} and code {:?}",
            src,
            dest,
            icmp_packet.get_icmpv6_type(),
            icmp_packet.get_icmpv6_code(),
        );
    } else {
        println!("[WARN] Malformed ICMPv6 packet from {} > {}", src, dest);
    }
}

fn process_transport_protocol(
    src: IpAddr,
    dest: IpAddr,
    protocol: IpNextHeaderProtocol,
    payload: &[u8],
) -> Result<()> {
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            process_tcp_packet(src, dest, payload);
            Ok(())
        }
        IpNextHeaderProtocols::Udp => {
            process_udp_packet(src, dest, payload);
            Ok(())
        }
        IpNextHeaderProtocols::Icmp => {
            process_icmp_packet(src, dest, payload);
            Ok(())
        }
        IpNextHeaderProtocols::Icmpv6 => {
            process_icmpv6_packet(src, dest, payload);
            Ok(())
        }
        _ => Err(anyhow!("Unsupported protocol {}", protocol)),
    }
}

fn process_ipv4_packet(ipv4_packet: Ipv4Packet) -> Result<()> {
    println!("Processing an ipv4 packet...");
    process_transport_protocol(
        IpAddr::V4(ipv4_packet.get_source()),
        IpAddr::V4(ipv4_packet.get_destination()),
        ipv4_packet.get_next_level_protocol(),
        ipv4_packet.payload(),
    )
}

fn process_ipv6_packet(ipv6_packet: Ipv6Packet) -> Result<()> {
    println!("Processing an ipv6 packet...");
    process_transport_protocol(
        IpAddr::V6(ipv6_packet.get_source()),
        IpAddr::V6(ipv6_packet.get_destination()),
        ipv6_packet.get_next_header(),
        ipv6_packet.payload(),
    )
}

#[cfg(test)]
mod tests {
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
