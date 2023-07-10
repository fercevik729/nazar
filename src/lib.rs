extern crate anyhow;
extern crate pnet;

use std::ffi::OsStr;
use std::path::Path;

use pnet::{
    datalink::{self, interfaces, DataLinkReceiver, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, Ethernet, EthernetPacket},
        ipv4::Ipv4Packet,
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

// Sets up the packet capture datalink receiver via Ethernet interface
pub fn setup_pcap_rec(iface: &NetworkInterface) -> Result<Box<dyn datalink::DataLinkReceiver>> {
    match datalink::channel(iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(_, rx)) => Ok(rx),
        Ok(_) => Err(anyhow!("unknown channel type")),
        Err(_) => Err(anyhow!("couldn't create the datalink channel")),
    }
}

// Packet capture logic
pub fn pcap_handle(rx: Box<&mut dyn datalink::DataLinkReceiver>, _: std::path::PathBuf) {
    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    println!(
                        "Source IP: {}, Destination IP: {}",
                        ipv4_packet.get_source(),
                        ipv4_packet.get_destination(),
                    );
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
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
