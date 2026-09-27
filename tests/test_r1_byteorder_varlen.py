# -*- coding: utf-8 -*-
"""R1 v0.10.0 回归：字节序（大/小端）+ length_from 变长字段/数组。"""
import pytest

from protoforge.core.generator import generate_lua
from protoforge.core.jsonio import load_protocol, protocol_to_dict, save_protocol
from protoforge.core.luaengine import LuaEngine
from protoforge.core.model import Binding, Field, Protocol, validate


def make_proto(fields, name="ledemo", long_name="LEDEMO", byte_order="big"):
    return Protocol(name=name, long_name=long_name, byte_order=byte_order,
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


# ---------- 字节序 ----------
def test_little_endian_uint16():
    p = make_proto([Field("v", type="uint16")], byte_order="little")
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x34\x12")            # LE 存储的 0x1234
    assert "v: 4660" in tree_text(r)


def test_field_level_be_override_on_le_protocol():
    p = make_proto([
        Field("a", type="uint16", byte_order="big"),
        Field("b", type="uint16"),
    ], byte_order="little")
    lua = generate_lua(p)
    assert ":add(pf_a," in lua              # a 大端覆盖 → 普通 add
    assert ":add_le(pf_b," in lua           # b 继承协议小端 → add_le
    eng = LuaEngine()
    eng.load(lua)
    r = eng.dissect(b"\x12\x34\x34\x12")
    text = tree_text(r)
    assert "a: 4660" in text and "b: 4660" in text


def test_le_int_signed():
    p = make_proto([Field("v", type="int16")], byte_order="little")
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\xff\xff")
    assert "v: -1" in tree_text(r)


def test_byte_order_roundtrip(tmp_path):
    p = make_proto([Field("v", type="uint16", byte_order="little")], byte_order="little")
    path = tmp_path / "rt.json"
    save_protocol(p, path)
    p2 = load_protocol(path)
    assert p2.byte_order == "little"
    assert p2.fields[0].byte_order == "little"
    assert protocol_to_dict(p2)["meta"]["byte_order"] == "little"


def test_bitfield_byte_order_rejected():
    p = make_proto([Field("f", type="uint", width=4, byte_order="little")])
    assert any("byte_order" in e for e in validate(p))


def test_invalid_byte_order_rejected():
    p = make_proto([Field("v", type="uint16", byte_order="middle")])
    assert any("byte_order" in e for e in validate(p))


# ---------- length_from ----------
def test_string_length_from():
    p = make_proto([
        Field("n", type="uint8"),
        Field("s", type="string", length_from="n", label="S"),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x03ABC")
    assert "S: \"ABC\"" in tree_text(r)
    assert r.error is None


def test_string_length_from_overflow_clamped():
    p = make_proto([
        Field("n", type="uint8"),
        Field("s", type="bytes", length_from="n", label="S"),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x20AB")              # 声明 32 字节，只有 2 字节可用
    assert r.ok
    assert "超出剩余" in (r.error or "")


def test_array_length_from():
    p = make_proto([
        Field("total", type="uint8"),
        Field("items", type="array", length_from="total", label="Items",
              element=[Field("e", type="uint8")]),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x06abcdef")
    text = tree_text(r)
    assert "Items [0]" in text and "Items [2]" in text
    assert "e: 97" in text and "e: 99" in text   # a, c
    assert r.error is None


def test_length_from_non_numeric_rejected():
    p = make_proto([
        Field("s", type="string", size=2),
        Field("v", type="string", length_from="s", size=0),
    ])
    assert any("length_from" in e and "数值" in e for e in validate(p))


def test_size_and_length_from_both_rejected():
    p = make_proto([Field("v", type="bytes", size=4, length_from="x")])
    assert any("二选一" in e for e in validate(p))


def test_string_without_size_or_length_from_rejected():
    p = make_proto([Field("s", type="string")])
    assert any("length_from" in e for e in validate(p))
