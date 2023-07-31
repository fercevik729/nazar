[![codecov](https://codecov.io/github/fercevik729/nazar/branch/main/graph/badge.svg?token=L72BUOVDW2)](https://codecov.io/github/fercevik729/nazar)
![Issues](https://img.shields.io/github/issues/fercevik729/nazar)
![License](https://img.shields.io/github/license/fercevik729/nazar)
[![](https://tokei.rs/b1/github/fercevik729/nazar?category=lines)](https://github.com/fercevik729/nazar)
![GitHub Commit Activity](https://img.shields.io/github/commit-activity/m/fercevik729/nazar)
# nazar
A Rust CLI application that performs packet sniffing and intrusion detection on local networks.

## features
Currently supports JSON rule configuration files and processing ICMP/v6, TCP, UDP, DNS, and HTTP packets on non loopback ethernet interfaces. Limited attention will be given to other more niche protocols.

## future
* Special focus will be given to improving TCP packet processing to detect and prevent SYN-flood attacks and other kinds of TCP related attacks.
* Planning on mulithreading packet processing so packets don't get stalled and/or dropped.
