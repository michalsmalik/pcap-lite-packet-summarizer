#!/usr/bin/env python3
"""pcapsum — summarize a .pcap capture file using only the Python standard library.

Reads the classic libpcap format (what `tcpdump -w` writes) and decodes Ethernet (with
802.1Q VLAN tags), Linux "any"-interface captures (SLL / SLL2) and raw IP, then ARP,
IPv4, IPv6, TCP, UDP and ICMP headers. Prints protocol counts, top talkers, top
conversations and DNS/DHCP traffic: a quick first look before opening Wireshark.

Usage: python3 pcapsum.py capture.pcap [--top N] [--json]
"""
import argparse
import ipaddress
import json
import struct
import sys
from collections import Counter

# Link-layer header types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101          # packet starts directly with an IP header
LINKTYPE_LINUX_SLL = 113    # tcpdump -i any (older)
LINKTYPE_LINUX_SLL2 = 276   # tcpdump -i any (newer)

ETH_IPV4, ETH_IPV6, ETH_ARP, ETH_VLAN = 0x0800, 0x86DD, 0x0806, 0x8100
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


class PcapError(Exception):
    """The file is not a classic pcap file we can read."""


def read_packets(data):
    """Yield (timestamp_seconds, link_type, packet_bytes) for each record in a pcap file."""
    if len(data) < 24:
        raise PcapError("file is too short to be a pcap file")
    magic = data[:4]
    # The magic number tells us the byte order and whether timestamps are in micro- or nanoseconds.
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9),
    }
    if magic == b"\x0a\x0d\x0d\x0a":
        raise PcapError("this is pcapng; convert it first: editcap -F pcap in.pcapng out.pcap")
    if magic not in formats:
        raise PcapError("not a pcap file (unknown magic number)")
    endian, ticks = formats[magic]
    link_type = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    offset = 24
    while offset + 16 <= len(data):
        sec, frac, caplen, _origlen = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if offset + caplen > len(data):
            raise PcapError(f"truncated packet record at byte {offset - 16}")
        yield sec + frac / ticks, link_type, data[offset:offset + caplen]
        offset += caplen


def network_layer(link_type, pkt):
    """Strip the link-layer header. Returns (ethertype, payload) or (None, None) if unsupported."""
    if link_type == LINKTYPE_ETHERNET:
        if len(pkt) < 14:
            return None, None
        ethertype, payload = struct.unpack("!H", pkt[12:14])[0], pkt[14:]
        if ethertype == ETH_VLAN and len(payload) >= 4:      # skip one 802.1Q VLAN tag
            ethertype, payload = struct.unpack("!H", payload[2:4])[0], payload[4:]
        return ethertype, payload
    if link_type == LINKTYPE_LINUX_SLL and len(pkt) >= 16:
        return struct.unpack("!H", pkt[14:16])[0], pkt[16:]
    if link_type == LINKTYPE_LINUX_SLL2 and len(pkt) >= 20:
        return struct.unpack("!H", pkt[0:2])[0], pkt[20:]
    if link_type == LINKTYPE_RAW and pkt:
        return (ETH_IPV4 if pkt[0] >> 4 == 4 else ETH_IPV6), pkt
    return None, None


def decode(link_type, pkt):
    """Decode one packet into a small dict: proto, src, dst, sport, dport (missing parts are None)."""
    info = {"proto": "other", "src": None, "dst": None, "sport": None, "dport": None}
    ethertype, ip = network_layer(link_type, pkt)
    if ethertype == ETH_ARP:
        info["proto"] = "ARP"
        return info
    if ethertype == ETH_IPV4 and len(ip) >= 20:
        header_len = (ip[0] & 0x0F) * 4
        proto = ip[9]
        info["src"], info["dst"] = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        transport = ip[header_len:]
    elif ethertype == ETH_IPV6 and len(ip) >= 40:
        proto = ip[6]   # "next header"; extension headers are not followed (kept simple)
        info["src"], info["dst"] = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
        transport = ip[40:]
    else:
        return info
    info["proto"] = IP_PROTOCOLS.get(proto, f"IP proto {proto}")
    if proto in (6, 17) and len(transport) >= 4:            # TCP and UDP both start with the two ports
        info["sport"], info["dport"] = struct.unpack("!HH", transport[:4])
    return info


def summarize(data, top=5):
    """Return a summary dict for the pcap file contents in `data` (bytes)."""
    protocols, sources, destinations, conversations = Counter(), Counter(), Counter(), Counter()
    dns = dhcp = total_bytes = count = 0
    first = last = None
    link_types = set()
    for ts, link_type, pkt in read_packets(data):
        count += 1
        total_bytes += len(pkt)
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
        link_types.add(link_type)
        p = decode(link_type, pkt)
        protocols[p["proto"]] += 1
        if p["src"]:
            sources[p["src"]] += 1
            destinations[p["dst"]] += 1
            # A conversation is the same pair of endpoints in either direction.
            a, b = sorted([(p["src"], p["sport"] or 0), (p["dst"], p["dport"] or 0)])
            conversations[(p["proto"], a, b)] += 1
        ports = {p["sport"], p["dport"]}
        if 53 in ports:
            dns += 1
        if p["proto"] == "UDP" and ports & {67, 68}:
            dhcp += 1
    return {
        "packets": count,
        "bytes": total_bytes,
        "duration_s": round(last - first, 3) if count else 0.0,
        "link_types": sorted(link_types),
        "protocols": dict(protocols.most_common()),
        "top_sources": sources.most_common(top),
        "top_destinations": destinations.most_common(top),
        "top_conversations": [
            {"proto": proto, "a": f"{a[0]}:{a[1]}", "b": f"{b[0]}:{b[1]}", "packets": n}
            for (proto, a, b), n in conversations.most_common(top)
        ],
        "dns_packets": dns,
        "dhcp_packets": dhcp,
    }


def print_report(s):
    print(f"Packets: {s['packets']}   Bytes: {s['bytes']}   Duration: {s['duration_s']} s")
    print("\nProtocols")
    for name, n in s["protocols"].items():
        print(f"  {name:<12} {n:>7}  {n * 100 / s['packets']:5.1f}%")
    for title, key in (("Top sources", "top_sources"), ("Top destinations", "top_destinations")):
        print(f"\n{title}")
        width = max((len(ip) for ip, _ in s[key]), default=0)
        for ip, n in s[key]:
            print(f"  {ip:<{width}}  {n:>7}")
    print("\nTop conversations")
    convs = s["top_conversations"]
    wa, wb = (max((len(c[k]) for c in convs), default=0) for k in ("a", "b"))
    for c in convs:
        print(f"  {c['proto']:<6} {c['a']:<{wa}} <-> {c['b']:<{wb}}  {c['packets']:>6}")
    print(f"\nDNS packets (port 53): {s['dns_packets']}   DHCP packets (UDP 67/68): {s['dhcp_packets']}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarize a .pcap capture file.")
    ap.add_argument("file", help="classic .pcap file (e.g. from tcpdump -w)")
    ap.add_argument("--top", type=int, default=5, help="how many top talkers/conversations to show (default 5)")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = ap.parse_args(argv)
    try:
        with open(args.file, "rb") as f:
            summary = summarize(f.read(), args.top)
    except (OSError, PcapError) as e:
        print(f"pcapsum: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_report(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
