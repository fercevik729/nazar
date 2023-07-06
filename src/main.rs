extern crate clap;
extern crate pnet;

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};

use clap::Parser;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

#[derive(Parser, Debug)]
#[command(name = "nazar")]
#[command(author = "Furkan E. <f.ercevik21@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "A simple packet sniffing and intrusion detection program")]
struct Args {
    // Name of the interface to perform packet sniffing on
    // If not provided, the program will try to find the first non-loopback
    // interface
    #[arg(short, long)]
    iface: Option<String>,

    // Path to file containing the rules
    #[arg(short, long, value_name = "FILE")]
    rules: std::path::PathBuf,

    // Path to directory to output log files
    // If not provided, the program will write logs in a 'logs' directory in the
    // current working directory
    #[arg(short, long, value_name = "FILE")]
    outlog: Option<std::path::PathBuf>,
}

#[derive(Debug)]
struct CustomError(String);

impl Error for CustomError {}

impl Display for CustomError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// Gets the network interface with the corresponding name or returns a default
// value
fn get_iface(iface: Option<String>) -> Option<NetworkInterface> {
    // Gather the network interfaces into an iterator
    let mut interfaces = datalink::interfaces().into_iter();

    // If an interface name was provided
    if let Some(iface_name) = iface {
        interfaces.find(|x| x.name == iface_name)

    // Try to find a suitable default interface
    } else {
        interfaces.find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Interface
    let iface = match get_iface(args.iface) {
        Some(x) => x,
        None => {
            return Err(Box::new(CustomError(String::from(
                "Error: unable to find a suitable network interface to sniff packets on",
            ))))
        }
    };

    // Log file
    let mut opts = OpenOptions::new();
    let outlog = match args.outlog {
        Some(fp) => opts.write(true).append(true).create(true).open(&fp),
        None => opts.write(true).append(true).create(true).open("nazar.log"),
    };

    // Rules file
    let rules_file = File::open(&args.rules)?;
    let mut buf = BufReader::new(rules_file);

    println!("------------YOUR RULES:----------");
    for line in buf.lines() {
        println!("{}", line?);
    }
    println!("----------------------------------");

    let (_, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    println!(
                        "Source IP: {}, Destination IP: {}, Payload: {:?}",
                        ipv4_packet.get_source(),
                        ipv4_packet.get_destination(),
                        ipv4_packet.payload(),
                    );
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
