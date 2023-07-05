extern crate clap;
extern crate pnet;

use clap::Parser;

use pnet::datalink;
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
    #[arg(short, long, value_name = "DIR")]
    outlog: Option<std::path::PathBuf>,
}

fn main() {
    let args = Args::parse();

    // TODO: handle None case of optional arguments

    println!("{:?}", args);

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == "en0")
        .expect("No non-loopback interface found.");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
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
