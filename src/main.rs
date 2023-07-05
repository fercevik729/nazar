extern crate pnet;

use pnet::datalink::{self, NetworkInterface};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

fn main() {
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
