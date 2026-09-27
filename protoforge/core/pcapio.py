# -*- coding: utf-8 -*-
"""最小 pcap 读取（classic pcap、linktype 1 以太网、IPv4 + UDP/TCP）。

仅供测试台从抓包中提取应用层帧；pcapng 不支持（v1 范围，见 DESIGN D7）。
"""
from __future__ import annotations

import ipaddress
import os
import struct
from dataclasses import dataclass

PCAP_MAGICS = {
    0xA1B2C3D4: (">", 1e6), 0xD4C3B2A1: ("<", 1e6),
    0xA1B23C4D: (">", 1e9), 0x4D3CB2A1: ("<", 1e9),
}


class PcapError(ValueError):
    pass


@dataclass
class Packet:
    index: int
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    payload: bytes


def read_pcap(path: os.PathLike) -> list[Packet]:
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise PcapError("文件过短，不是 pcap")
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be not in PCAP_MAGICS:
        raise PcapError("不是 classic pcap 文件（pcapng 不受支持）")
    endian, divisor = PCAP_MAGICS[magic_be]
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0xFFFF
    if linktype != 1:
        raise PcapError(f"linktype {linktype} 不受支持（仅 Ethernet=1）")

    packets = []
    off = 24
    idx = 0
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > len(data):
            raise PcapError(f"文件截断：第 {idx + 1} 帧声明 {incl} 字节，实际不足")
        pkt = data[off:off + incl]
        off += incl
        idx += 1
        parsed = _parse_eth(pkt)
        packets.append(Packet(
            index=idx, ts=ts_sec + ts_frac / divisor,
            src=parsed[0], dst=parsed[1], sport=parsed[2], dport=parsed[3],
            proto=parsed[4], payload=parsed[5],
        ))
    return packets


def _parse_eth(pkt: bytes):
    if len(pkt) < 14:
        return "?", "?", 0, 0, "?", b""
    etype = struct.unpack(">H", pkt[12:14])[0]
    off = 14
    while etype == 0x8100 and len(pkt) >= off + 4:  # VLAN（可叠层）
        etype = struct.unpack(">H", pkt[off + 2:off + 4])[0]
        off += 4
    if etype != 0x0800 or len(pkt) < off + 20:
        return "?", "?", 0, 0, "?", b""
    ip = pkt[off:]
    ihl = (ip[0] & 0x0F) * 4
    total_len = struct.unpack(">H", ip[2:4])[0]
    proto_num = ip[9]
    src = str(ipaddress.IPv4Address(ip[12:16]))
    dst = str(ipaddress.IPv4Address(ip[16:20]))
    l4 = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]
    if proto_num == 17 and len(l4) >= 8:
        sport, dport, ulen = struct.unpack(">HHH", l4[:6])
        return src, dst, sport, dport, "UDP", l4[8:ulen] if 8 <= ulen <= len(l4) else l4[8:]
    if proto_num == 6 and len(l4) >= 20:
        sport, dport = struct.unpack(">HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        return src, dst, sport, dport, "TCP", l4[doff:]
    return src, dst, 0, 0, f"ip:{proto_num}", b""


def extract_frames(packets: list[Packet], ports: set[int]) -> list[bytes]:
    return [p.payload for p in packets if p.sport in ports or p.dport in ports]
