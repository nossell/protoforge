# -*- coding: utf-8 -*-
"""R4 v0.13.0 回归：pcapng 读取、GUI 多绑定编辑、CLI 多端口提取。"""
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
    src, dst = ip4("10.1.1.1"), ip4("10.1.1.2")
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0) + src + dst
    ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    return eth + ip + udp


def build_pcapng(frames, endian="<", dports=None):
    """构造最小 pcapng：SHB + IDB(linktype 1) + 每帧一个 EPB。"""
    le = endian == "<"
    I = (struct.Struct("<I") if le else struct.Struct(">I")).pack
    H = (struct.Struct("<H") if le else struct.Struct(">H")).pack
    IIII = (struct.Struct("<IIIII") if le else struct.Struct(">IIIII")).pack

    def block(btype, body):
        total = 12 + len(body) + ((4 - len(body) % 4) % 4)
        pad = b"\x00" * ((4 - len(body) % 4) % 4)
        return I(btype) + I(total) + body + pad + I(total)

    bom = I(0x1A2B3C4D)
    shb_body = bom + H(1) + H(0) + I(0xFFFFFFFF)
    idb_body = H(1) + H(0) + I(0)  # linktype 1, reserved, snaplen
    out = block(0x0A0D0D0A, shb_body) + block(0x00000001, idb_body)
    for i, f in enumerate(frames):
        pkt = wrap_udp(f, dport=(dports[i] if dports else 5566))
        body = IIII(0, 0, 0, len(pkt), len(pkt)) + pkt
        out += block(0x00000006, body)
    return out


def test_pcapng_roundtrip(tmp_path):
    frames = [b"\x01\x02\x03", b"\xff" * 6, b"\x80" * 1]
    p = tmp_path / "t.pcapng"
    p.write_bytes(build_pcapng(frames))
    pkts = read_pcap(p)
    assert len(pkts) == 3
    assert [x.payload for x in pkts] == frames
    assert pkts[0].dport == 5566
    assert extract_frames(pkts, {5566}) == frames


def test_pcapng_big_endian(tmp_path):
    p = tmp_path / "be.pcapng"
    p.write_bytes(build_pcapng([b"\xAA" * 4], endian=">"))
    pkts = read_pcap(p)
    assert len(pkts) == 1 and pkts[0].payload == b"\xAA" * 4


def test_pcapng_still_accepts_classic(tmp_path):
    classic = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    p = tmp_path / "c.pcap"
    p.write_bytes(classic)
    assert read_pcap(p) == []


def test_pcapng_truncated_block(tmp_path):
    p = tmp_path / "t.pcapng"
    data = build_pcapng([b"\x01\x02"])
    p.write_bytes(data[:-6])          # 砍掉尾部
    with pytest.raises(PcapError):
        read_pcap(p)


def test_gui_multi_binding_edit(qtbot=None):
    os_env = __import__("os").environ
    os_env.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from protoforge.app.main_window import MainWindow
    w = MainWindow()
    w._populate_bindings()
    assert w.bind_table.rowCount() == 1
    # 模拟用户在表格加一行 tcp 7000
    w._loading_bindings = True
    w.bind_table.setRowCount(2)
    w.bind_table.setItem(1, 0, __import__("PySide6.QtWidgets", fromlist=["QTableWidgetItem"]).QTableWidgetItem("tcp.port"))
    w.bind_table.setItem(1, 1, __import__("PySide6.QtWidgets", fromlist=["QTableWidgetItem"]).QTableWidgetItem("7000"))
    w._loading_bindings = False
    w._bindings_from_table()
    tables = [b.table for b in w.protocol.bindings]
    assert "tcp.port" in tables
    lua = w.current_lua()
    assert 'DissectorTable.get("tcp.port")' in lua
    w.close()


def test_cli_multi_port(tmp_path):
    import os
    import subprocess
    import sys
    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = tmp_path / "x.lua"
    r = subprocess.run([sys.executable, "-m", "protoforge", "generate",
                        os.path.join(REPO, "examples", "smsp.json"), "-o", str(out)],
                       capture_output=True, text=True, cwd=REPO,
                       env={**os.environ, "PYTHONUTF8": "1"})
    assert r.returncode == 0
    from protoforge.core.pcapio import Packet
    pcap = tmp_path / "m.pcap"
    frames = [b"\x01", b"\x02"]
    with open(pcap, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            pkt = wrap_udp(f, dport=5566 + i)
            fh.write(struct.pack("<IIII", i, 0, len(pkt), len(pkt)))
            fh.write(pkt)
    r = subprocess.run([sys.executable, "-m", "protoforge", "verify", str(out),
                        "--pcap", str(pcap), "--port", "5566,5567"],
                       capture_output=True, text=True, cwd=REPO,
                       env={**os.environ, "PYTHONUTF8": "1"})
    assert r.returncode == 0, r.stderr
    assert "帧 1" in r.stdout and "帧 2" in r.stdout
