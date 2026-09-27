# -*- coding: utf-8 -*-
"""pcap / pcapng 读取（以太网、IPv4 + UDP/TCP）。

支持：classic pcap（linktype 1）与 pcapng（EPB，接口 linktype 须为 1）。
仅供测试台从抓包中提取应用层载荷；写入方向不支持。
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
PCAPNG_SHB_MAGIC = 0x0A0D0D0A
PCAPNG_BOM_LE = 0x1A2B3C4D      # 文件按小端读出的字节序魔数


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
    if len(data) >= 4:
        head = struct.unpack("<I", data[:4])[0]
        if head == PCAPNG_SHB_MAGIC or head == 0x0D0D0A0A:
            return read_pcapng_data(data)
    if len(data) < 24:
        raise PcapError("文件过短，不是 pcap")
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be not in PCAP_MAGICS:
        raise PcapError("不是 classic pcap 或 pcapng 文件")
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


def read_pcapng_data(data: bytes) -> list[Packet]:
    """解析 pcapng：SHB 的 BOM 定字节序（SHB type 魔数是回文，不能用于判端序），
    IDB 取 linktype，EPB 取包。"""
    packets: list[Packet] = []
    off = 0
    endian = "<"
    linktype = None
    idx = 0
    saw_shb = False
    while off + 12 <= len(data):
        t_le = struct.unpack("<I", data[off:off + 4])[0]
        if t_le == PCAPNG_SHB_MAGIC:
            bom = struct.unpack("<I", data[off + 8:off + 12])[0]
            if bom == PCAPNG_BOM_LE:
                endian = "<"
            elif bom == 0x4D3C2B1A:
                endian = ">"
            else:
                raise PcapError("pcapng 字节序魔数非法")
            saw_shb = True
            linktype = None      # 新 Section 重置接口
            blen = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
            if blen < 12 or blen % 4 or off + blen > len(data):
                raise PcapError(f"pcapng 块长度非法（offset {off}, len {blen}）")
            off += blen
            continue
        if not saw_shb:
            raise PcapError("不是 pcapng 文件（缺少 Section Header Block）")
        btype = struct.unpack(endian + "I", data[off:off + 4])[0]
        blen = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if blen < 12 or blen % 4 or off + blen > len(data):
            raise PcapError(f"pcapng 块长度非法（offset {off}, len {blen}）")
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:                      # Interface Description Block
            if linktype is None:
                linktype = struct.unpack(endian + "H", body[0:2])[0] & 0xFFFF
                if linktype != 1:
                    raise PcapError(f"linktype {linktype} 不受支持（仅 Ethernet=1）")
        elif btype == 0x00000006:                      # Enhanced Packet Block
            if len(body) < 20:
                raise PcapError("pcapng EPB 过短")
            iface, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
            if caplen > len(body) - 20:
                raise PcapError(f"pcapng EPB 包数据截断（第 {idx + 1} 帧）")
            pkt = body[20:20 + caplen]
            idx += 1
            parsed = _parse_eth(pkt)
            packets.append(Packet(
                index=idx, ts=((ts_hi << 32) | ts_lo) / 1e6,
                src=parsed[0], dst=parsed[1], sport=parsed[2], dport=parsed[3],
                proto=parsed[4], payload=parsed[5],
            ))
        # 其余块（ISB/NRB/自定义选项块）跳过
        off += blen
    if not saw_shb:
        raise PcapError("不是 pcapng 文件")
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
