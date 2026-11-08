"""Tests for pcapsum. Packets are built byte by byte, so no capture files are needed."""
import io
import json
import struct
import unittest
from contextlib import redirect_stdout

import pcapsum


def pcap(packets, link_type=1, endian="<", nano=False):
    """Build a pcap file: global header + one record per packet (each packet = bytes)."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, link_type)
    for i, pkt in enumerate(packets):
        out += struct.pack(endian + "IIII", 1_700_000_000 + i, 500, len(pkt), len(pkt)) + pkt
    return out


def ipv4(src, dst, proto, payload=b""):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return header + payload


def ports(sport, dport):
    """Enough of a TCP/UDP header for the decoder: the two ports + padding."""
    return struct.pack("!HH", sport, dport) + bytes(4)


def eth(ethertype, payload, vlan=False):
    head = bytes(12)
    if vlan:
        head += struct.pack("!HH", 0x8100, 42)
    return head + struct.pack("!H", ethertype) + payload


def udp_v4(src, dst, sport, dport):
    return eth(0x0800, ipv4(src, dst, 17, ports(sport, dport)))


class SummaryTests(unittest.TestCase):
    def test_counts_protocols_dns_dhcp(self):
        data = pcap([
            eth(0x0800, ipv4("10.0.0.2", "10.0.0.1", 6, ports(51000, 443))),
            eth(0x0800, ipv4("10.0.0.1", "10.0.0.2", 6, ports(443, 51000))),
            udp_v4("10.0.0.2", "10.0.0.53", 40000, 53),            # DNS query
            udp_v4("0.0.0.0", "255.255.255.255", 68, 67),          # DHCP discover
            eth(0x0800, ipv4("10.0.0.2", "10.0.0.1", 1)),          # ICMP
            eth(0x0806, bytes(28)),                                 # ARP
        ])
        s = pcapsum.summarize(data)
        self.assertEqual(s["packets"], 6)
        self.assertEqual(s["protocols"], {"TCP": 2, "UDP": 2, "ICMP": 1, "ARP": 1})
        self.assertEqual(s["dns_packets"], 1)
        self.assertEqual(s["dhcp_packets"], 1)
        self.assertEqual(s["duration_s"], 5.0)

    def test_conversation_counts_both_directions_together(self):
        data = pcap([
            eth(0x0800, ipv4("10.0.0.2", "10.0.0.1", 6, ports(51000, 443))),
            eth(0x0800, ipv4("10.0.0.1", "10.0.0.2", 6, ports(443, 51000))),
        ])
        convs = pcapsum.summarize(data)["top_conversations"]
        self.assertEqual(len(convs), 1)
        self.assertEqual(convs[0]["packets"], 2)

    def test_top_talkers_are_sorted_and_limited(self):
        data = pcap([udp_v4("10.0.0.9", "10.0.0.1", 1000, 2000)] * 3 +
                    [udp_v4(f"10.0.0.{i}", "10.0.0.1", 1000, 2000) for i in range(2, 8)])
        top = pcapsum.summarize(data, top=2)["top_sources"]
        self.assertEqual(top[0], ("10.0.0.9", 3))
        self.assertEqual(len(top), 2)

    def test_vlan_tagged_frame(self):
        data = pcap([eth(0x0800, ipv4("10.0.0.2", "10.0.0.1", 17, ports(1, 53)), vlan=True)])
        self.assertEqual(pcapsum.summarize(data)["protocols"], {"UDP": 1})

    def test_ipv6(self):
        ip6 = struct.pack("!IHBB", 0x60000000, 8, 17, 64) + bytes(15) + b"\x01" + bytes(15) + b"\x02" + ports(5353, 53)
        s = pcapsum.summarize(pcap([eth(0x86DD, ip6)]))
        self.assertEqual(s["protocols"], {"UDP": 1})
        self.assertEqual(s["top_sources"][0][0], "::1")
        self.assertEqual(s["dns_packets"], 1)


class LinkTypeTests(unittest.TestCase):
    PACKET = ipv4("192.168.1.5", "192.168.1.1", 6, ports(40000, 80))

    def test_linux_sll(self):          # tcpdump -i any, older format
        sll = bytes(14) + struct.pack("!H", 0x0800) + self.PACKET
        self.assertEqual(pcapsum.summarize(pcap([sll], link_type=113))["protocols"], {"TCP": 1})

    def test_linux_sll2(self):         # tcpdump -i any, newer format
        sll2 = struct.pack("!H", 0x0800) + bytes(18) + self.PACKET
        self.assertEqual(pcapsum.summarize(pcap([sll2], link_type=276))["protocols"], {"TCP": 1})

    def test_raw_ip(self):
        self.assertEqual(pcapsum.summarize(pcap([self.PACKET], link_type=101))["protocols"], {"TCP": 1})

    def test_unknown_link_type_is_counted_as_other(self):
        self.assertEqual(pcapsum.summarize(pcap([self.PACKET], link_type=999))["protocols"], {"other": 1})


class FileFormatTests(unittest.TestCase):
    def test_big_endian_and_nanoseconds(self):
        for endian in "<>":
            for nano in (False, True):
                data = pcap([udp_v4("1.1.1.1", "2.2.2.2", 1, 2)] * 2, endian=endian, nano=nano)
                s = pcapsum.summarize(data)
                self.assertEqual(s["packets"], 2, (endian, nano))
                self.assertEqual(s["duration_s"], 1.0, (endian, nano))

    def test_empty_capture(self):
        s = pcapsum.summarize(pcap([]))
        self.assertEqual((s["packets"], s["bytes"], s["duration_s"]), (0, 0, 0.0))

    def test_pcapng_is_rejected_with_hint(self):
        with self.assertRaisesRegex(pcapsum.PcapError, "editcap"):
            pcapsum.summarize(b"\x0a\x0d\x0d\x0a" + bytes(40))

    def test_garbage_is_rejected(self):
        with self.assertRaises(pcapsum.PcapError):
            pcapsum.summarize(b"hello, this is not a capture file")

    def test_truncated_record_is_rejected(self):
        data = pcap([udp_v4("1.1.1.1", "2.2.2.2", 1, 2)])
        with self.assertRaisesRegex(pcapsum.PcapError, "truncated"):
            pcapsum.summarize(data[:-5])

    def test_short_packets_do_not_crash(self):
        s = pcapsum.summarize(pcap([b"", b"\x00" * 5, eth(0x0800, b"\x45\x00")]))
        self.assertEqual(s["protocols"], {"other": 3})


class CliTests(unittest.TestCase):
    def test_json_output_and_exit_code(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap([udp_v4("1.1.1.1", "2.2.2.2", 1, 53)]))
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = pcapsum.main([f.name, "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(buf.getvalue())["dns_packets"], 1)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(pcapsum.main([f.name]), 0)      # text report runs too
        finally:
            os.unlink(f.name)

    def test_missing_file_returns_1(self):
        import contextlib
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pcapsum.main(["/nonexistent.pcap"]), 1)


if __name__ == "__main__":
    unittest.main()
