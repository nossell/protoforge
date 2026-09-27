# -*- coding: utf-8 -*-
"""R5 v0.14.0 回归：启发式注册 + 车载示例协议。"""
import os

import pytest

from protoforge.core.generator import generate_lua
from protoforge.core.jsonio import load_protocol
from protoforge.core.luaengine import LuaEngine
from protoforge.core.model import Binding, Field, Protocol, validate

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SADP = os.path.join(REPO, "examples", "automotive_sadp.json")


def make_proto(fields, name="heurdemo", long_name="HEURDEMO", heuristic="udp"):
    return Protocol(name=name, long_name=long_name, heuristic=heuristic,
                    bindings=[Binding("udp.port", [5566])], fields=fields)


def tree_text(r):
    out = []

    def rec(n):
        out.append((n.label or "") + (": " + str(n.value) if n.value is not None else ""))
        for c in n.children:
            rec(c)
    if r.tree:
        rec(r.tree)
    return "\n".join(out)


def test_heuristic_generated_and_registered():
    p = make_proto([
        Field("magic", type="uint16", display="hex", const="0x0D5A"),
        Field("a", type="uint8"),
    ])
    lua = generate_lua(p)
    assert "register_heuristic" in lua
    assert "proto_heur" in lua
    eng = LuaEngine()
    eng.load(lua)
    assert len(eng._proto.heuristics) == 1
    table, fn = eng._proto.heuristics[0]
    assert table == "udp"
    # 启发式函数自身能判别：命中 → 解析并返回 true；未命中 → false
    import protoforge.core.luaengine as LE
    hit = fn(LE._Tvb(list(b"\x0d\x5a\x01")), LE._PInfo(), LE._TreeItem("H"))
    assert hit is True
    miss = fn(LE._Tvb(list(b"\x00\x01\x01")), LE._PInfo(), LE._TreeItem("H"))
    assert miss is False


def test_heuristic_requires_const_first_field():
    p = make_proto([Field("a", type="uint8")])
    errs = validate(p)
    assert any("const" in e for e in errs)


def test_heuristic_requires_matching_binding():
    p = make_proto([Field("magic", type="uint16", const="0x0D5A")], heuristic="tcp")
    errs = validate(p)
    assert any("tcp.port 端口绑定" in e for e in errs)


def test_heuristic_invalid_value_rejected():
    p = make_proto([Field("magic", type="uint16", const="0x0D5A")], heuristic="icmp")
    assert any("udp/tcp" in e for e in validate(p))


def test_automotive_example_loads_and_parses():
    p = load_protocol(SADP)
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    # 构造 Request 帧：读 2 个 DID
    payload = b"\x02\x22\x33" + b"\x01\xA0"
    body = b"\x0d\x5a" + bytes([0x11, 1, 34, 0, len(payload)]) + payload
    from tests.conftest import crc16_ccitt_false
    frame = body + crc16_ccitt_false(body).to_bytes(2, "big")
    # 注意：CRC 算法是 modbus，需用 modbus 计算
    def modbus(data):
        crc = 0xFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ 0xA001 if (crc & 1) else crc >> 1
        return crc
    frame = body + modbus(body).to_bytes(2, "little")
    r = eng.dissect(frame)
    text = tree_text(r)
    assert "Request" in text
    assert "DID Count: 2" in text
    assert "[correct]" in text
    assert r.error is None


def test_automotive_error_response_uses_default():
    p = load_protocol(SADP)
    eng = LuaEngine()
    eng.load(generate_lua(p))

    def modbus(data):
        crc = 0xFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ 0xA001 if (crc & 1) else crc >> 1
        return crc

    payload = b"\x11"
    body = b"\x0d\x5a" + bytes([0x13, 3, 17, 0, len(payload)]) + payload
    r = eng.dissect(body + modbus(body).to_bytes(2, "little"))
    text = tree_text(r)
    assert "Error Code" in text
