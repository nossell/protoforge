# -*- coding: utf-8 -*-
import struct

import pytest

from protoforge.core.pcapio import PcapError, extract_frames, read_pcap


def ip4(a):
    return bytes(int(x) for x in a.split("."))


def ip_checksum(hdr: bytes) -> int:
    if len(hdr) % 2:
        hdr += b"\x00"
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def wrap_udp(payload, sport=40000, dport=5566):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    src, dst = ip4("10.0.0.1"), ip4("10.0.0.2")
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0) + src + dst
    ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    return eth + ip + udp


def write_pcap(path, frames):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            pkt = wrap_udp(f, dport=5566 + i)
            fh.write(struct.pack("<IIII", 1000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)


def test_read_roundtrip(tmp_path):
    frames = [b"\x5a\x5a\x11\x01", b"\x00" * 8, b"\xff" * 3]
    p = tmp_path / "t.pcap"
    write_pcap(p, frames)
    pkts = read_pcap(p)
    assert len(pkts) == 3
    assert pkts[0].src == "10.0.0.1" and pkts[0].dst == "10.0.0.2"
    assert pkts[0].proto == "UDP"
    assert [x.payload for x in pkts] == frames
    assert pkts[1].ts == 1001.0


def test_extract_by_port(tmp_path):
    p = tmp_path / "t.pcap"
    write_pcap(p, [b"A" * 4, b"B" * 4, b"C" * 4])
    pkts = read_pcap(p)
    assert extract_frames(pkts, {5566}) == [b"A" * 4]
    assert extract_frames(pkts, {5566, 5567, 5568}) == [b"A" * 4, b"B" * 4, b"C" * 4]
    assert extract_frames(pkts, {1}) == []


def test_not_pcap(tmp_path):
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"hello world" * 10)
    with pytest.raises(PcapError):
        read_pcap(p)


def test_examples_demo_pcap():
    import os
    ex = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")
    pcap = os.path.join(ex, "demo.pcap")
    if not os.path.exists(pcap):  # make_demo.py 未运行时跳过
        pytest.skip("examples/demo.pcap 不存在（先运行 make_demo.py）")
    pkts = read_pcap(pcap)
    assert len(pkts) == 4
    assert all(x.dport in (5566, 5567) for x in pkts)
    frames = extract_frames(pkts, {5566, 5567})
    assert frames[0][:4] == b"\x5a\x5a\x11\x01"
    assert len(frames[3]) == len(frames[0])
