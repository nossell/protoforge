# -*- coding: utf-8 -*-
"""E2E（真机 tshark）：五轮迭代新增特性——小端/大端覆盖、MODBUS 校验和、
终止符字符串、嵌套 switch + default 分支、length_from 变长、启发式注册。

为何单独一个文件：mock 引擎（lupa）只能自证一致性，不能证明与真实 Wireshark
行为一致（历史教训：mock 通过而真机报 ByteArray:get() 不存在）。此处用真 tshark
逐特性验证。协议名/端口均唯一，避免与本机个人插件冲突造成"假通过"。
"""
import os
import struct
import subprocess
import sys

import pytest

TSHARK_CANDIDATES = [
    os.environ.get("TSHARK", ""),
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]
TSHARK = next((t for t in TSHARK_CANDIDATES if t and os.path.isfile(t)), None)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

pytestmark = pytest.mark.skipif(TSHARK is None, reason="本机无 tshark")

PORT = 5597          # 绑定端口
PORT_HEUR = 5596     # 启发式协议绑定端口（帧实际走未绑定端口）
PORT_OPEN = 40002    # 未绑定端口（考验启发式）

ADV = {
    "meta": {"name": "pfadv7", "long_name": "ProtoForge Advanced E2E Probe",
             "byte_order": "little"},
    "bindings": [{"table": "udp.port", "ports": [PORT]}],
    "fields": [
        {"name": "magic", "label": "Magic", "type": "uint16", "display": "hex",
         "const": "0x4B32"},
        {"name": "ver", "label": "Version", "type": "uint", "width": 4},
        {"name": "kind", "label": "Kind", "type": "uint", "width": 4,
         "enum": {"1": "Alpha", "2": "Beta", "3": "Gamma"}},
        {"name": "temp", "label": "Temp", "type": "int16"},
        {"name": "bigv", "label": "BigVal", "type": "uint16", "display": "hex",
         "byte_order": "big"},
        {"name": "nlen", "label": "NameLen", "type": "uint8"},
        {"name": "name", "label": "Name", "type": "string", "length_from": "nlen"},
        {"name": "ilen", "label": "ItemsLen", "type": "uint16"},
        {"name": "items", "label": "Item", "type": "array", "length_from": "ilen",
         "element": [
             {"name": "iid", "label": "ItemID", "type": "uint16", "display": "hex"},
             {"name": "ival", "label": "ItemVal", "type": "uint8"}]},
        {"name": "body", "label": "Body", "type": "switch", "on": "kind", "cases": {
            "1": [
                {"name": "count", "label": "Count", "type": "uint8"},
                {"name": "detail", "label": "Detail", "type": "switch", "on": "count",
                 "cases": {
                     "0": [{"name": "pad", "label": "Pad", "type": "bytes", "size": 2}],
                     "2": [{"name": "vals", "label": "Val", "type": "array",
                            "count_from": "count",
                            "element": [{"name": "v", "label": "V", "type": "uint16"}]}],
                     "default": [{"name": "note", "label": "Note", "type": "string",
                                  "terminated_by": 0}]}}],
            "2": [{"name": "text", "label": "Text", "type": "string",
                   "terminated_by": 0}],
            "default": [{"name": "errcode", "label": "Error Code", "type": "uint8",
                         "enum": {"17": "GeneralReject"}}]}},
        {"name": "crc", "label": "CRC-16/MODBUS", "type": "uint16", "display": "hex",
         "crc16": "modbus"},
    ],
}

# 无 CRC 的小协议：专门验证 "(unterminated)"（有 CRC 时 CRC 字节可能含 0x00 干扰扫描）
NOCRC = {
    "meta": {"name": "pfadv8", "long_name": "ProtoForge Unterminated Probe"},
    "bindings": [{"table": "udp.port", "ports": [PORT + 100]}],
    "fields": [
        {"name": "tag", "label": "Tag", "type": "uint8"},
        {"name": "label", "label": "Label", "type": "string", "terminated_by": 0},
    ],
}

HEUR = {
    "meta": {"name": "pfheur8", "long_name": "ProtoForge Heuristic Probe",
             "heuristic": "udp"},
    "bindings": [{"table": "udp.port", "ports": [PORT_HEUR]}],
    "fields": [
        {"name": "magic", "label": "Magic", "type": "uint16", "display": "hex",
         "const": "0xABCD"},
        {"name": "val", "label": "Val", "type": "uint8"},
    ],
}


def modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else crc >> 1
    return crc


def adv_body(kind, temp=-300, name=b"ABC", items=((0x0011, 0x22), (0x0033, 0x44)),
             tail=b""):
    b = struct.pack("<H", 0x4B32)                    # magic（小端线上字节 32 4B）
    b += bytes([(1 << 4) | kind])                    # ver=1, kind
    b += struct.pack("<h", temp)                     # int16 LE
    b += struct.pack(">H", 0x1234)                   # 字段级覆盖：大端
    b += bytes([len(name)]) + name                   # length_from 字符串
    it = b"".join(struct.pack("<HB", iid, iv) for iid, iv in items)
    b += struct.pack("<H", len(it)) + it             # length_from 数组（3 字节/元素）
    return b + tail


def advance_frame(kind, tail=b"", **kw) -> bytes:
    body = adv_body(kind, tail=tail, **kw)
    return body + struct.pack("<H", modbus(body))


def _write_pcap(path, frames):
    from examples.make_demo import wrap_udp
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, (payload, sport, dport) in enumerate(frames):
            pkt = wrap_udp(payload, sport, dport)
            fh.write(struct.pack("<IIII", 1770000000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)


def _write_pcap_raw(path, packets):
    """已封装完整的以太网帧直接写入 pcap（TCP 测试用，不再包 UDP）。"""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            fh.write(struct.pack("<IIII", 1770000000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)


def _gen(tmp_path, spec, fname):
    from protoforge.core.generator import generate_lua
    from protoforge.core.jsonio import load_protocol_dict
    p = load_protocol_dict(spec)
    path = tmp_path / fname
    path.write_text(generate_lua(p), encoding="utf-8")
    return path


def _run(lua_path, pcap_path, verbose=True):
    args = [TSHARK, "-r", str(pcap_path), "-X", f"lua_script:{lua_path}"]
    if verbose:
        args.append("-V")
    return subprocess.run(args, capture_output=True, text=True, timeout=90)


@pytest.fixture(scope="module")
def adv(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pf_adv")
    lua = _gen(tmp, ADV, "adv.lua")
    frames = [
        # 帧1：kind=1 → 嵌套 switch count=2 → 变长数组
        (advance_frame(1, tail=b"\x02" + struct.pack("<HH", 0x0102, 0x0304)),
         40000, PORT),
        # 帧2：kind=1 → 嵌套 switch count=0 → pad 2 字节
        (advance_frame(1, tail=b"\x00\x00\xAA"), 40001, PORT),
        # 帧3：kind=1 → 嵌套 switch count=5 → default → 终止符字符串
        (advance_frame(1, tail=b"\x05zz\x00"), 40002, PORT),
        # 帧4：kind=2 → 终止符字符串
        (advance_frame(2, name=b"XY", items=(), tail=b"hi\x00"), 40003, PORT),
        # 帧5：kind=3 → 顶层 default 分支
        (advance_frame(3, tail=b"\x11"), 40004, PORT),
        # 帧6：CRC 损坏
        (advance_frame(3, tail=b"\x11")[:-1] + b"\x00" + advance_frame(3, tail=b"\x11")[-1:],
         40005, PORT),
        # 帧7：过短帧（< min_len）→ too short expert
        (b"\x32\x4B\x11", 40006, PORT),
    ]
    # 修帧6：把最后一字节异或，制造 CRC 错误
    f6 = bytearray(advance_frame(3, tail=b"\x11"))
    f6[-1] ^= 0xFF
    frames[5] = (bytes(f6), 40005, PORT)
    pcap = tmp / "adv.pcap"
    _write_pcap(pcap, frames)
    return _run(lua, pcap), _run(lua, pcap, verbose=False)


@pytest.fixture(scope="module")
def nocrc(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pf_nocrc")
    lua = _gen(tmp, NOCRC, "nocrc.lua")
    pcap = tmp / "nocrc.pcap"
    _write_pcap(pcap, [(b"\x07abcd", 40010, PORT + 100)])
    return _run(lua, pcap)


@pytest.fixture(scope="module")
def heur(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pf_heur")
    lua = _gen(tmp, HEUR, "heur.lua")
    pcap = tmp / "heur.pcap"
    # 两帧走【未绑定】端口：一帧命中魔数（应被启发式接管），一帧不命中（应保持 Data）
    _write_pcap(pcap, [
        (struct.pack(">HB", 0xABCD, 7), 40020, PORT_OPEN),
        (struct.pack(">HB", 0x1234, 7), 40021, PORT_OPEN),
    ])
    return _run(lua, pcap)


def test_no_lua_errors(adv):
    verbose, summary = adv
    for out in (verbose.stdout, summary.stdout, verbose.stderr, summary.stderr):
        assert "Lua Error" not in out
        assert "Dissector bug" not in out


def test_le_signed_and_field_override(adv):
    """小端 int16 读出 -300（若按大端读则为 -11010）；字段级 big 覆盖读出 0x1234。"""
    out = adv[0].stdout.lower()
    assert "temp: -300" in out
    assert "0x1234" in out
    assert "0x4b32" in out            # 协议级小端读出的魔数


def test_enum_and_bitfield_rendering(adv):
    out = adv[0].stdout
    assert "Alpha (1)" in out         # 位域枚举
    assert "Gamma (3)" in out


def test_length_from_string_and_array(adv):
    out = adv[0].stdout
    assert "ABC" in out               # length_from 字符串
    assert "ItemID: 0x0011" in out    # length_from 数组按 3 字节/元素切分
    assert "ItemID: 0x0033" in out
    assert "ItemVal: 34" in out       # 0x22


def test_nested_switch_branches(adv):
    out = adv[0].stdout
    assert "Count: 2" in out
    assert "V: 258" in out            # 0x0102，嵌套 case 内 count_from 数组（元素标签 V）
    assert "Pad" in out               # 嵌套 default 之前的分支（count=0）
    assert "Note: zz" in out          # 嵌套 switch 的 default 分支（count=5）
    assert "Error Code: GeneralReject (17)" in out   # 顶层 default 分支


def test_modbus_crc_correct_incorrect_and_expert(adv):
    out = adv[0].stdout
    assert "[correct]" in out
    assert "[incorrect, expected 0x" in out
    assert "Expert Info (Error/Checksum)" in out


def test_too_short_expert(adv):
    out = adv[0].stdout
    assert "Expert Info" in out
    assert "too short" in out


def test_unterminated_string(nocrc):
    out = nocrc.stdout
    assert "Lua Error" not in out
    assert "abcd" in out
    assert "(unterminated)" in out


def test_heuristic_takes_over_unbound_port(heur):
    out = heur.stdout
    assert "Lua Error" not in out
    # 命中魔数的包：协议名出现且解析出 Val
    assert "ProtoForge Heuristic Probe" in out
    assert "Val: 7" in out
    # 不命中的包不应被接管（tshark 保持 Data），Val: 7 只应出现一次
    assert out.count("Val: 7") == 1


# ---------------- v0.16：TLV 变长元素数组（真机） ----------------
TLV = {
    "meta": {"name": "pftlv9", "long_name": "ProtoForge TLV E2E Probe"},
    "bindings": [{"table": "udp.port", "ports": [5595]}],
    "fields": [
        {"name": "magic", "label": "Magic", "type": "uint16", "display": "hex",
         "const": "0x5453"},
        {"name": "ncnt", "label": "TLV Count", "type": "uint8"},
        {"name": "tlvs", "label": "TLV", "type": "array", "count_from": "ncnt",
         "element": [
             {"name": "ttype", "label": "Type", "type": "uint8",
              "enum": {"1": "Val", "2": "Note"}},
             {"name": "tlen", "label": "Length", "type": "uint8"},
             {"name": "tval", "label": "Value", "type": "switch", "on": "ttype",
              "cases": {
                  "1": [{"name": "num", "label": "Num", "type": "uint32"}],
                  "2": [{"name": "txt", "label": "Txt", "type": "string",
                         "length_from": "tlen"}],
                  "default": [{"name": "raw", "label": "Raw", "type": "bytes",
                               "length_from": "tlen"}]}}]},
    ],
}


@pytest.fixture(scope="module")
def tlv(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pf_tlv")
    lua = _gen(tmp, TLV, "tlv.lua")
    frames = [
        # 2 个 TLV：Val(u32=0x0000FACE=64206) + Note("hi!")
        (struct.pack(">HB", 0x5453, 2) + b"\x01\x04\x00\x00\xfa\xce"
         + b"\x02\x03hi!", 41000, 5595),
        # default 分支：type=7 raw 2 字节
        (struct.pack(">HB", 0x5453, 1) + b"\x07\x02\xaa\xbb", 41001, 5595),
    ]
    pcap = tmp / "tlv.pcap"
    _write_pcap(pcap, [(f, sp, dp) for f, sp, dp in frames])
    return _run(lua, pcap)


def test_tlv_elements_dissect_in_real_tshark(tlv):
    out = tlv.stdout
    assert "Lua Error" not in out
    assert "ProtoForge TLV E2E Probe" in out
    assert "TLV [0]" in out and "TLV [1]" in out
    assert "Val (1)" in out and "Note (2)" in out   # 元素内枚举
    assert "Num: 64206" in out                      # 0x0000FACE
    assert "hi!" in out                             # length_from 字符串
    assert "Raw" in out and "aabb" in out.lower()   # 元素内 default 分支（真机 bytes 无冒号）


# ---------------- v0.16：TCP 解段（真机分片段重组） ----------------
def _tcp_checksum(seg: bytes, src: str, dst: str) -> int:
    pseudo = bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split(".")) \
        + struct.pack(">BBH", 0, 6, len(seg))
    blob = pseudo + seg
    if len(blob) % 2:
        blob += b"\x00"
    s = 0
    for i in range(0, len(blob), 2):
        s += (blob[i] << 8) | blob[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _tcp_packet(payload: bytes, seq: int, sport: int, dport: int,
                src="10.9.9.1", dst="10.9.9.2") -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18, 8192, 0, 0) + payload
    ck = _tcp_checksum(tcp, src, dst)
    tcp = tcp[:16] + struct.pack(">H", ck) + tcp[18:]
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0) \
        + bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    from protoforge.core.pcapio import ip_checksum
    ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp


TCP = {
    "meta": {"name": "pftcp9", "long_name": "ProtoForge TCP E2E Probe",
             "desegment": True,
             "length_check": {"field": "plen", "region": "payload"}},
    "bindings": [{"table": "tcp.port", "ports": [5594]}],
    "fields": [
        {"name": "magic", "label": "Magic", "type": "uint16", "display": "hex",
         "const": "0xCAFE"},
        {"name": "plen", "label": "Payload Len", "type": "uint16"},
        {"name": "payload", "label": "Payload", "type": "bytes", "length_from": "plen"},
    ],
}


@pytest.fixture(scope="module")
def tcp_deseg(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pf_tcp")
    lua = _gen(tmp, TCP, "tcp.lua")
    pdu1 = struct.pack(">HH", 0xCAFE, 6) + b"\x11\x22\x33\x44\x55\x66"   # 10 字节
    pdu2 = struct.pack(">HH", 0xCAFE, 2) + b"\xaa\xbb"                   # 6 字节
    pkts = [
        _tcp_packet(pdu1[:6], seq=1, sport=40030, dport=5594),           # 分段 1（前 6 字节）
        _tcp_packet(pdu1[6:], seq=7, sport=40030, dport=5594),           # 分段 2（后 4 字节）
        _tcp_packet(pdu2, seq=11, sport=40030, dport=5594),              # 完整第二 PDU
    ]
    pcap = tmp / "tcp.pcap"
    _write_pcap_raw(pcap, pkts)
    return _run(lua, pcap)


def test_desegment_reassembles_split_pdu(tcp_deseg):
    out = tcp_deseg.stdout
    assert "Lua Error" not in out
    assert "Reassembled TCP" in out                      # Wireshark 确实重组了
    assert "ProtoForge TCP E2E Probe" in out
    # 重组后的两个 PDU 都被解析（真机 bytes 渲染为连续 hex，无分隔符）
    assert "112233445566" in out.lower()
    assert "aabb" in out.lower()


def test_desegment_not_triggered_on_full_pdu(tcp_deseg):
    out = tcp_deseg.stdout
    # 完整 PDU 正常解析；截断样本由解段路径接管，不应产生 "too short" 误报
    assert "too short" not in out
