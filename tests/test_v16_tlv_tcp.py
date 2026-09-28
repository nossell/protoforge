# -*- coding: utf-8 -*-
"""v0.16.0 回归：TLV 变长元素数组（schema v1.1）+ TCP 解段 + 抓包写出。"""
import struct

import pytest

from protoforge.core.generator import generate_lua
from protoforge.core.jsonio import load_protocol_dict, protocol_to_dict
from protoforge.core.luaengine import LuaEngine
from protoforge.core.model import (
    Binding, Field, Protocol, ValidationError, validate,
)
from protoforge.core.pcapio import PcapError, extract_frames, read_pcap, write_capture


def make_proto(fields, name="tlvdemo", long_name="TLVDEMO", **meta):
    return Protocol(name=name, long_name=long_name,
                    bindings=[Binding("udp.port", [5566])], fields=fields, **meta)


def tree_text(r):
    out = []

    def rec(n):
        out.append((n.label or "") + (": " + str(n.value) if n.value is not None else ""))
        for c in n.children:
            rec(c)
    if r.tree:
        rec(r.tree)
    return "\n".join(out)


# ---------- TLV：元素内 length_from 引用元素局部字段 ----------
def test_tlv_element_local_length_from():
    """元素 = [type, len, value(bytes length_from=len)]——最常见 TLV。"""
    p = make_proto([
        Field("n", type="uint8"),
        Field("tlvs", type="array", count_from="n", label="TLV", element=[
            Field("t", type="uint8", display="hex"),
            Field("l", type="uint8"),
            Field("v", type="bytes", length_from="l"),
        ]),
    ])
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    frame = b"\x02" + b"\x01\x03ABC" + b"\x02\x01Z"
    r = eng.dissect(frame)
    text = tree_text(r)
    assert "TLV [0]" in text and "TLV [1]" in text
    assert 'v: 414243' in text and 'v: 5a' in text   # bytes 以小写 hex 显示
    assert r.error is None
    # 容器长度经 set_len 回设：proto 节点下 [n, TLV[0], TLV[1]]（TreeNode 字段名为 length）
    proto_node = r.tree.children[0]
    assert proto_node.children[1].label == "TLV [0]"
    assert proto_node.children[1].length == 5            # 1+1+3
    assert proto_node.children[2].length == 3            # 1+1+1


def test_tlv_element_with_switch():
    """元素 = [type(enum), len, value-switch-on-type]：按类型分支的 TLV。"""
    p = make_proto([
        Field("n", type="uint8"),
        Field("tlvs", type="array", count_from="n", label="TLV", element=[
            Field("t", type="uint8", enum={1: "Num", 2: "Text"}),
            Field("l", type="uint8"),
            Field("val", type="switch", on="t", cases={
                1: [Field("num", type="uint32")],
                2: [Field("text", type="string", length_from="l")],
            }),
        ]),
    ])
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    frame = (b"\x02"
             + b"\x01\x04" + struct.pack(">I", 0xDEADBEEF)
             + b"\x02\x03hi!")
    r = eng.dissect(frame)
    text = tree_text(r)
    assert "Num (1)" in text and "Text (2)" in text
    assert "num: 3735928559" in text            # 0xDEADBEEF
    assert 'text: "hi!"' in text
    assert r.error is None


def test_tlv_switch_on_type_nested_array_in_element():
    """元素内再嵌 count_from 数组（二级 TLV）。"""
    p = make_proto([
        Field("n", type="uint8"),
        Field("groups", type="array", count_from="n", label="Group", element=[
            Field("gid", type="uint8"),
            Field("cnt", type="uint8"),
            Field("items", type="array", count_from="cnt", label="Item", element=[
                Field("v", type="uint16"),
            ]),
        ]),
    ])
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    # 组0：gid=0xA0, cnt=1, 1×u16=0x0007；组1：gid=0xA1, cnt=2, 2×u16=0x0100,0x0203
    frame = b"\x02" + b"\xA0\x01\x00\x07" + b"\xA1\x02\x01\x00\x02\x03"
    r = eng.dissect(frame)
    text = tree_text(r)
    assert "Group [0]" in text and "Group [1]" in text
    assert "v: 7" in text and "v: 256" in text and "v: 515" in text   # 0x0007/0x0100/0x0203
    assert r.error is None


def test_length_from_array_still_rejects_tlv_element():
    """length_from 数组仍要求全定长元素（TLV 请用 count_from）。"""
    p = make_proto([
        Field("rlen", type="uint16"),
        Field("tlvs", type="array", length_from="rlen", label="TLV", element=[
            Field("t", type="uint8"),
            Field("l", type="uint8"),
            Field("v", type="bytes", length_from="l"),
        ]),
    ])
    errs = validate(p)
    assert any("全为定长字段" in e and "count_from" in e for e in errs)
    with pytest.raises(ValidationError):
        generate_lua(p)


def test_tlv_json_roundtrip():
    spec = {
        "meta": {"name": "tlvrt", "long_name": "TLVRT"},
        "bindings": [{"table": "udp.port", "ports": [5566]}],
        "fields": [
            {"name": "n", "type": "uint8"},
            {"name": "tlvs", "type": "array", "count_from": "n", "element": [
                {"name": "t", "type": "uint8"},
                {"name": "l", "type": "uint8"},
                {"name": "v", "type": "bytes", "length_from": "l"},
            ]},
        ],
    }
    p = load_protocol_dict(spec)
    assert validate(p) == []
    d = protocol_to_dict(p)
    p2 = load_protocol_dict(d)
    assert p2.fields[1].element[2].length_from == "l"


# ---------- TCP 解段（mock 层） ----------
def _desegment_proto():
    return Protocol(
        name="dsdemo", long_name="DSDEMO", desegment=True,
        length_check={"field": "plen", "region": "payload"},
        bindings=[Binding("tcp.port", [7000])],
        fields=[
            Field("magic", type="uint16", display="hex", const="0xCAFE"),
            Field("plen", type="uint16"),
            Field("payload", type="bytes", length_from="plen"),
        ])


def test_desegment_validation_rules():
    p = _desegment_proto()
    assert validate(p) == []
    # 缺 tcp 绑定
    p2 = _desegment_proto()
    p2.bindings = [Binding("udp.port", [7000])]
    assert any("tcp.port 绑定" in e for e in validate(p2))
    # 缺 length_check
    p3 = _desegment_proto()
    p3.length_check = None
    assert any("length_check" in e for e in validate(p3))
    # 长度字段前有变长字段（无法静态定位）
    p4 = _desegment_proto()
    p4.fields.insert(1, Field("name", type="string", length_from="magic"))
    assert any("无法静态定位" in e for e in validate(p4))


def test_desegment_requests_more_bytes():
    p = _desegment_proto()
    eng = LuaEngine()
    eng.load(generate_lua(p))
    full = b"\xca\xfe\x00\x04" + b"\x11\x22\x33\x44"
    r_ok = eng.dissect(full)
    assert r_ok.ok and r_ok.desegment == 0
    # 截断：缺 2 字节 → 请求 +2
    r_short = eng.dissect(full[:6])
    assert r_short.desegment == 2
    # 连长度字段都读不到 → 请求"再来一个分段"（mock 哨兵 -1；真机为 DESEGMENT_ONE_MORE_SEGMENT）
    r_tiny = eng.dissect(b"\xca")
    assert r_tiny.desegment == -1
    assert r_tiny.protocol == ""      # 未认领（等待重组）


# ---------- 抓包写出与 TCP 流重组 ----------
def _udp_wrap(payload, sport=40000, dport=5566):
    from protoforge.core.pcapio import build_udp_packet
    return build_udp_packet(payload, sport, dport)


def _write_pcap_bytes(pkts):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, pkt in enumerate(pkts):
        out += struct.pack("<IIII", 1770000000 + i, 0, len(pkt), len(pkt)) + pkt
    return out


def test_write_capture_roundtrip_both_formats(tmp_path):
    payloads = [b"\x01\x02\x03", b"\xff" * 9, b"x"]
    for fmt in ("pcap", "pcapng"):
        path = tmp_path / f"out.{fmt}"
        n = write_capture(path, payloads, dport=5566, fmt=fmt)
        assert n == 3
        pkts = read_pcap(path)
        assert [x.payload for x in pkts] == payloads
        assert pkts[0].dport == 5566


def test_write_capture_bad_format(tmp_path):
    with pytest.raises(PcapError):
        write_capture(tmp_path / "x.pcap", [b"\x01"], fmt="snoop")


def test_tcp_stream_reassembly():
    """同一 TCP 流的两个分段按 seq 拼接；反向为独立方向。"""
    from protoforge.core.pcapio import ip_checksum

    def tcp_pkt(payload, sport, dport, seq, src="10.0.0.1", dst="10.0.0.2"):
        tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18, 8192, 0, 0) + payload
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0) + \
            bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
        # TCP 校验和（伪首部）
        pseudo = ip[12:20] + struct.pack(">BBH", 0, 6, len(tcp))
        s = 0
        blob = pseudo + tcp
        if len(blob) % 2:
            blob += b"\x00"
        for i in range(0, len(blob), 2):
            s += (blob[i] << 8) | blob[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        ck = (~s) & 0xFFFF
        tcp = tcp[:16] + struct.pack(">H", ck) + tcp[18:]
        ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
        return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp

    part1, part2 = b"\xca\xfe\x00", b"\x04\x11\x22\x33\x44"
    pkts = [
        tcp_pkt(part1, 7000, 5000, seq=1),
        tcp_pkt(part2, 7000, 5000, seq=4),
        # 反向（服务端→客户端）：同一流、另一方向
        tcp_pkt(b"\xaa\xbb", 5000, 7000, seq=1, src="10.0.0.2", dst="10.0.0.1"),
    ]
    pcap = _write_pcap_bytes(pkts)
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".pcap")
    with os.fdopen(fd, "wb") as fh:
        fh.write(pcap)
    try:
        packets = read_pcap(path)
        assert len(packets) == 3
        # 普通模式：三帧分开
        assert extract_frames(packets, {7000, 5000}) == [part1, part2, b"\xaa\xbb"]
        # 流模式：同向拼接、反向独立
        merged = extract_frames(packets, {7000, 5000}, tcp_stream=True)
        assert merged == [part1 + part2, b"\xaa\xbb"]
    finally:
        os.unlink(path)


def test_cli_verify_export(tmp_path):
    """verify --export：hex 帧导出为 pcap/pcapng，读回载荷一致（issue 复现链路）。"""
    import os
    import subprocess
    import sys
    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lua = tmp_path / "s.lua"
    r = subprocess.run([sys.executable, "-m", "protoforge", "generate",
                        os.path.join(REPO, "examples", "smsp.json"), "-o", str(lua)],
                       capture_output=True, text=True, cwd=REPO,
                       env={**os.environ, "PYTHONUTF8": "1"})
    assert r.returncode == 0, r.stderr
    from tests.conftest import smsp_frame, telemetry_payload
    hx = smsp_frame(1, 2, 2, struct.pack(">BH3h", 7, 5000, 100, -50, 75)).hex()
    for fmt in ("pcap", "pcapng"):
        out = tmp_path / f"repro.{fmt}"
        r = subprocess.run([sys.executable, "-m", "protoforge", "verify", str(lua),
                            "--hex", hx, "--export", str(out)],
                           capture_output=True, text=True, cwd=REPO,
                           env={**os.environ, "PYTHONUTF8": "1"})
        assert r.returncode == 0, r.stderr
        assert f"已导出 1 帧" in r.stdout
        pkts = read_pcap(out)
        assert [p.payload for p in pkts] == [bytes.fromhex(hx)]
