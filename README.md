# pcap-lite-packet-summarizer

A single-file Python tool that summarizes a `.pcap` capture: protocols, top talkers, top conversations
and DNS/DHCP traffic. It's a quick first look before opening Wireshark. **Standard library only**, so there's nothing to install.

It parses the binary pcap format and the packet headers by hand with `struct`:

- **File format:** classic libpcap (what `tcpdump -w` writes), little/big-endian, micro/nanosecond timestamps
- **Link layer:** Ethernet (with an 802.1Q VLAN tag), Linux "any"-interface captures (SLL and SLL2), raw IP
- **Network and transport:** ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6

## Usage

```bash
sudo tcpdump -i any -c 500 -w capture.pcap    # capture some traffic (or use any .pcap file)
python3 pcapsum.py capture.pcap               # text report
python3 pcapsum.py capture.pcap --top 10      # more top talkers/conversations
python3 pcapsum.py capture.pcap --json        # machine-readable output
```

pcapng files (Wireshark's default) are rejected with a hint: `editcap -F pcap in.pcapng out.pcap`.

## Example

Loopback traffic: 5 pings, 3 HTTP requests, UDP to ports 53 and 67, and 2 IPv6 pings.

```text
Packets: 62   Bytes: 6934   Duration: 2.2 s

Protocols
  TCP               36   58.1%
  ICMP              16   25.8%
  UDP                6    9.7%
  ICMPv6             4    6.5%

Top sources
  127.0.0.1       58
  ::1              4

Top destinations
  127.0.0.1       58
  ::1              4

Top conversations
  ICMP   127.0.0.1:0    <-> 127.0.0.1:0          16
  TCP    127.0.0.1:8080 <-> 127.0.0.1:50770      12
  TCP    127.0.0.1:8080 <-> 127.0.0.1:50782      12

DNS packets (port 53): 4   DHCP packets (UDP 67/68): 2
```

The 16 ICMP packets are 10 from the pings plus 6 *port unreachable* replies, because nothing was listening on UDP 53/67.

## How it was checked

- **Against tcpdump.** I captured real traffic in both Ethernet (`-i lo`) and Linux SLL2 (`-i any`) formats.
  Every count (all, TCP, UDP, ICMP, ICMPv6, DNS, DHCP) matched `tcpdump -r file <filter> | wc -l`.
  CI repeats this on every push with a fresh capture.
- **Unit tests** (`python3 -m unittest -v`): 17 tests on packets built byte by byte, covering every link type, both byte
  orders, nanosecond files, VLAN, IPv6, empty/truncated/garbage files, pcapng and the CLI.
  The hand-built test packets also decode identically in tcpdump.

## Limits

- IPv6 extension headers aren't followed, so the packet is counted under its first "next header" value.
- "DNS" means port 53 and "DHCP" means UDP 67/68. Packet contents aren't decoded.
- The whole file is read into memory, which is fine for the captures you'd summarize by hand.

## License

[MIT](LICENSE)
