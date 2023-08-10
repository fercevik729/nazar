use clap::Parser;
use std::path::PathBuf;

use anyhow::Result;

#[derive(Parser, Debug)]
#[command(name = "nazar")]
#[command(author = "Furkan E. <f.ercevik21@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "A simple packet sniffing and intrusion detection program")]
struct Args {
    /// Name of the interface to perform sniff packets on
    #[arg(short, long)]
    iface: Option<String>,

    /// Path to file containing the rule config
    #[arg(short, long, value_name = "FILE")]
    rules: PathBuf,

    /// Path to directory to output log files
    #[arg(short, long, value_name = "DIR")]
    outlog: Option<PathBuf>,

    /// Flag indicating if the IDS should dynamically update its rules
    #[arg(short, long)]
    dynamic: bool,
}

// TODO: add subcommands to do simple port scans

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Dynamic: {}", args.dynamic);

    let log_path = args.outlog.unwrap_or_else(|| PathBuf::from("logs"));

    let _pcap = nazar::PacketCapturer::new(args.iface, args.rules, log_path)?;

    Ok(())
}
