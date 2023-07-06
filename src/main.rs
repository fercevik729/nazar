extern crate anyhow;
extern crate clap;
extern crate pnet;

use std::fs::{create_dir, create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use clap::Parser;

use anyhow::{anyhow, Context, Result};

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
    #[arg(short, long, value_name = "DIR")]
    outlog: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Interface
    let iface = match nazar::get_iface(args.iface) {
        Some(x) => x,
        None => {
            return Err(anyhow!(
                "unable to find a suitable network interface to sniff packets on"
            ))
        }
    };

    // Logs directory
    let logdir = match args.outlog {
        Some(fp) => create_dir_all(fp),
        None => create_dir("logs"),
    };

    // Rules file
    let rules_file = File::open(&args.rules).with_context(|| {
        format!(
            "No rules file of the name `{}` exists",
            &args.rules.display()
        )
    })?;
    let mut buf = BufReader::new(rules_file);

    println!("------------YOUR RULES:----------");
    for line in buf.lines() {
        println!("{}", line?);
    }
    println!("----------------------------------");

    let mut rx = match datalink::channel(&iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(_, rx)) => rx,
        Ok(_) => return Err(anyhow!("unknown channel type",)),
        Err(_) => {
            return Err(anyhow!("couldn't create the datalink channel, make sure to run `nazar` as root or with `sudo`."));
        }
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
