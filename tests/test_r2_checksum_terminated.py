# -*- coding: utf-8 -*-
"""R2 v0.11.0 回归：校验和家族（modbus/xmodem/sum8/sum16）+ 终止符字符串。"""
import pytest

from protoforge.core.generator import generate_lua
from protoforge.core.luaengine import LuaEngine
from protoforge.core.model import Binding, Field, Protocol, validate


def make_proto(fields, name="ckdemo", long_name="CKDEMO"):
    return Protocol(name=name, long_name=long_name,
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


def crc16_ccitt_false(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


def crc16_modbus(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else crc >> 1
    return crc


def crc16_xmodem(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


PAYLOAD = b"123456789"          # 经典校验向量：MODBUS=0x4B37, XMODEM=0x31C3, CCITT-F=0x29B1


def test_modbus_checksum():
    p = make_proto([
        Field("payload", type="bytes", size=len(PAYLOAD)),
        Field("crc", type="uint16", crc16="modbus", display="hex"),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(PAYLOAD + struct_pack_le(crc16_modbus(PAYLOAD)))
    assert r.error is None and "[correct]" in tree_text(r)
    r2 = eng.dissect(PAYLOAD + struct_pack_le((crc16_modbus(PAYLOAD) ^ 0xFFFF)))
    assert "incorrect" in tree_text(r2)


def test_xmodem_checksum():
    p = make_proto([
        Field("payload", type="bytes", size=len(PAYLOAD)),
        Field("crc", type="uint16", crc16="xmodem", display="hex"),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(PAYLOAD + struct_pack_be(crc16_xmodem(PAYLOAD)))
    assert r.error is None and "[correct]" in tree_text(r)


def test_sum8_sum16_checksum():
    for algo, ftype, csize in (("sum8", "uint8", 1), ("sum16", "uint16", 2)):
        p = make_proto([
            Field("payload", type="bytes", size=len(PAYLOAD)),
            Field("ck", type=ftype, crc16=algo),
        ])
        eng = LuaEngine()
        eng.load(generate_lua(p))
        mask = 0xFF if algo == "sum8" else 0xFFFF
        total = sum(PAYLOAD) & mask
        r = eng.dissect(PAYLOAD + total.to_bytes(csize, "big"))
        assert r.error is None, algo
        assert "[correct]" in tree_text(r), algo


def test_checksum_wrong_type_rejected():
    p = make_proto([Field("ck", type="uint8", crc16="modbus")])
    assert any("要求字段类型 uint16" in e for e in validate(p))


def test_unknown_checksum_rejected():
    p = make_proto([Field("ck", type="uint16", crc16="crc32")])
    assert any("不支持的校验和算法" in e for e in validate(p))


# ---------- 终止符字符串 ----------
def test_terminated_string_with_terminator():
    p = make_proto([
        Field("s", type="string", terminated_by=0, label="S"),
        Field("n", type="uint8"),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"HELLO\x00\x07")
    text = tree_text(r)
    assert 'S: "HELLO"' in text
    assert "N: 7" in text or "n: 7" in text
    assert r.error is None


def test_terminated_string_unterminated_at_end():
    p = make_proto([Field("s", type="string", terminated_by=0, label="S")])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"NOEND")
    assert r.ok
    text = tree_text(r)
    assert '"NOEND"' in text
    assert "unterminated" in text


def test_terminated_custom_byte():
    p = make_proto([
        Field("s", type="string", terminated_by=0x0D, label="S"),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"AB\x0dCD")
    assert 'S: "AB"' in tree_text(r)


def test_terminated_wrong_type_rejected():
    p = make_proto([Field("b", type="bytes", terminated_by=0)])
    assert any("仅支持 string" in e for e in validate(p))


def test_terminated_range_rejected():
    p = make_proto([Field("s", type="string", terminated_by=300)])
    assert any("0-255" in e for e in validate(p))


def test_terminated_exclusive_with_size():
    p = make_proto([Field("s", type="string", size=4, terminated_by=0)])
    assert any("三选一" in e for e in validate(p))


def struct_pack_be(v):
    return v.to_bytes(2, "big") if isinstance(v, int) and v < 256 * 256 else bytes([v])


def struct_pack_le(v):
    return v.to_bytes(2, "little")
