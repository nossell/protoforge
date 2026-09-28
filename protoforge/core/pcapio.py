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
    seq: int = 0                # TCP 序号（UDP 恒 0）；流重组排序用
    stream: tuple = ()          # 无方向流标识：sorted((src,sport),(dst,dport))


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
            proto=parsed[4], payload=parsed[5], seq=parsed[6], stream=parsed[7],
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
            if blen < 16 or blen % 4 or off + blen > len(data):   # 至少容得下字节序魔数
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
            if len(body) < 8:
                raise PcapError(f"pcapng IDB 过短（{len(body)} 字节）")
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
                proto=parsed[4], payload=parsed[5], seq=parsed[6], stream=parsed[7],
            ))
        # 其余块（ISB/NRB/自定义选项块）跳过
        off += blen
    if not saw_shb:
        raise PcapError("不是 pcapng 文件")
    return packets


def _parse_eth(pkt: bytes):
    if len(pkt) < 14:
        return "?", "?", 0, 0, "?", b"", 0, ()
    etype = struct.unpack(">H", pkt[12:14])[0]
    off = 14
    while etype == 0x8100 and len(pkt) >= off + 4:  # VLAN（可叠层）
        etype = struct.unpack(">H", pkt[off + 2:off + 4])[0]
        off += 4
    if etype != 0x0800 or len(pkt) < off + 20:
        return "?", "?", 0, 0, "?", b"", 0, ()
    ip = pkt[off:]
    ihl = (ip[0] & 0x0F) * 4
    total_len = struct.unpack(">H", ip[2:4])[0]
    proto_num = ip[9]
    src = str(ipaddress.IPv4Address(ip[12:16]))
    dst = str(ipaddress.IPv4Address(ip[16:20]))
    l4 = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]
    stream = tuple(sorted([(src, 0), (dst, 0)]))
    if proto_num == 17 and len(l4) >= 8:
        sport, dport, ulen = struct.unpack(">HHH", l4[:6])
        stream = tuple(sorted([(src, sport), (dst, dport)]))
        return src, dst, sport, dport, "UDP", l4[8:ulen] if 8 <= ulen <= len(l4) else l4[8:], 0, stream
    if proto_num == 6 and len(l4) >= 20:
        sport, dport = struct.unpack(">HH", l4[:4])
        seq = struct.unpack(">I", l4[4:8])[0]
        doff = (l4[12] >> 4) * 4
        stream = tuple(sorted([(src, sport), (dst, dport)]))
        return src, dst, sport, dport, "TCP", l4[doff:], seq, stream
    return src, dst, 0, 0, f"ip:{proto_num}", b"", 0, stream


def extract_frames(packets: list[Packet], ports: set[int],
                   tcp_stream: bool = False) -> list[bytes]:
    """提取应用层载荷。tcp_stream=True 时按（流, 方向）聚合、按 TCP 序号拼接——
    供跑在 TCP 上的协议使用（多个分段拼成一整个应用层数据）。"""
    if not tcp_stream:
        return [p.payload for p in packets if p.sport in ports or p.dport in ports]
    groups: dict = {}
    for p in packets:
        if p.sport in ports or p.dport in ports:
            direction = (p.src, p.sport)
            groups.setdefault((p.stream, direction), []).append(p)
    out = []
    for key in sorted(groups, key=lambda k: (k[0], k[1])):
        pkts = sorted(groups[key], key=lambda x: x.seq)
        merged = b"".join(x.payload for x in pkts)
        if merged:
            out.append(merged)
    return out


# ---------------- 封包写出（v1.1：测试台复现帧 → pcap/pcapng，便于分享/附 issue） ----------------
def ip_checksum(hdr: bytes) -> int:
    if len(hdr) % 2:
        hdr += b"\x00"
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_udp_packet(payload: bytes, sport: int, dport: int,
                     src: str = "192.168.10.50", dst: str = "192.168.10.200") -> bytes:
    """应用层载荷 → 完整 Ethernet+IPv4+UDP 帧（演示/复现用，校验和填合规值）。"""
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_src = bytes(int(x) for x in src.split("."))
    ip_dst = bytes(int(x) for x in dst.split("."))
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 0x1234, 0x4000, 64, 17, 0) \
        + ip_src + ip_dst
    ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
    eth = bytes.fromhex("aabbccddeeff112233445566") + b"\x08\x00"
    return eth + ip + udp


def _ng_block(btype: int, body: bytes) -> bytes:
    pad = (4 - len(body) % 4) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total)


def write_capture(path: os.PathLike, payloads: list[bytes], dport: int = 5566,
                  fmt: str = "pcap", src: str = "192.168.10.50",
                  dst: str = "192.168.10.200") -> int:
    """载荷列表 → 抓包文件。fmt: pcap（classic，LE 微秒）| pcapng（LE）。
    统一封装为 Ethernet+IPv4+UDP，源端口 40000 起递增。返回写入帧数。"""
    pkts = [build_udp_packet(pl, 40000 + i, dport, src, dst)
            for i, pl in enumerate(payloads)]
    fmt = fmt.lower()
    if fmt == "pcapng":
        shb_body = (struct.pack("<I", 0x1A2B3C4D) + struct.pack("<HH", 1, 0)
                    + struct.pack("<q", -1))
        out = _ng_block(0x0A0D0D0A, shb_body)
        out += _ng_block(0x00000001, struct.pack("<HHI", 1, 0, 0))  # IDB: linktype 1
        for i, pkt in enumerate(pkts):
            epb_body = struct.pack("<IIIII", 0, 0, i, len(pkt), len(pkt)) + pkt
            out += _ng_block(0x00000006, epb_body)
    elif fmt == "pcap":
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for i, pkt in enumerate(pkts):
            out += struct.pack("<IIII", 1770000000 + i, 0, len(pkt), len(pkt)) + pkt
    else:
        raise PcapError(f"不支持的导出格式 '{fmt}'（仅 pcap/pcapng）")
    with open(path, "wb") as fh:
        fh.write(out)
    return len(pkts)
