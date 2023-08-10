use std::collections::HashMap;
use std::fs::{create_dir, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::{ffi::OsStr, net::IpAddr};

use log::{error, info};

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
use pnet::{
    datalink::{self, interfaces, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        Packet,
    },
};

pub mod rule_config;
pub mod utils;

use rule_config::{IdsAction, RuleConfig};

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
pub fn parse_rules(filepath: PathBuf) -> Result<Box<RuleConfig>> {
    // Validate rules file extension
    // Currently only supports json
    if !validate_file_ext(&filepath, "json") {
        return Err(anyhow!("rules file must be a .json file"));
    }
    // Try opening the file
    let mut rules_file = File::open(&filepath)
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

// Struct that represents a TCP connection
struct TcpConnection {
    src_ip: IpAddr,
    src_port: u16,
}

// Main struct that implements the Business Logic of `nazar`
pub struct PacketCapturer {
    tx: Box<dyn datalink::DataLinkSender>,
    rx: Box<dyn datalink::DataLinkReceiver>,
    rules: Box<RuleConfig>,
    tcp_seq_nums: HashMap<TcpConnection, u32>,
}

impl PacketCapturer {
    fn perform_ids_action(&self, action: IdsAction) {
        todo!();
    }

    pub fn new(iface: Option<String>, rule_path: PathBuf, log_path: PathBuf) -> Result<Self> {
        if let Some(interface) = get_iface(iface) {
            let rules = parse_rules(rule_path)?;
            setup_logging(log_path, 5, 5 * 1024)?;
            let (tx, rx) = setup_pcap_rec(&interface)?;

            let tcp_seq_nums: HashMap<TcpConnection, u32> = HashMap::new();

            Ok(Self {
                tx,
                rx,
                rules,
                tcp_seq_nums,
            })
        } else {
            Err(anyhow!("no available ethernet interface could be found"))
        }
    }
}

// Sets up the packet capture datalink sender & receiver via a provided Ethernet interface
pub fn setup_pcap_rec(
    iface: &NetworkInterface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    match datalink::channel(iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(anyhow!("unknown channel type")),
        Err(_) => Err(anyhow!("couldn't create the datalink channel")),
    }
}

// Sets up logging using log4rs and a rotating file appender
pub fn setup_logging(mut log_path: PathBuf, window_size: u32, size_limit: u64) -> Result<()> {
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
                    info!("{:?}", ipv4_packet.payload());
                } else if eth_packet.get_ethertype() == EtherTypes::Ipv6 {
                    let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();
                    info!("{:?}", ipv6_packet.payload());
                }
            }
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_file_ext() {
        let fp = PathBuf::from(r"/etc/config.toml");

        assert!(validate_file_ext(&fp, "toml"));
        assert!(!validate_file_ext(&fp, "csv"));
        assert!(!validate_file_ext(&fp, "exe"));
        assert!(!validate_file_ext(&fp, "tom"));

        let fp2 = PathBuf::from(r"/etc/config");
        assert!(!validate_file_ext(&fp2, "toml"));
        assert!(!validate_file_ext(&fp2, "csv"));
        assert!(!validate_file_ext(&fp2, "exe"));
        assert!(!validate_file_ext(&fp2, "tom"));
    }
}
