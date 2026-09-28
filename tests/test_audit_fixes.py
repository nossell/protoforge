# -*- coding: utf-8 -*-
"""独立审阅（2026-09-27）发现问题的回归测试。

覆盖：Lua 字符串转义/注入、引用字段类型与作用域校验、协议名长度、
顶层结构契约、count/const 校验、CSV 转义与 long_name、jsonio 枚举进制、
pcap 截断守卫、mock 枚举显示与真机对齐。
"""
import struct
import pytest

from protoforge.core.csvimport import CsvUnsupported, export_csv, import_csv
from protoforge.core.generator import generate_lua
from protoforge.core.jsonio import load_protocol
from protoforge.core.luaengine import LuaEngine, LuaError
from protoforge.core.model import Binding, Field, Protocol, ValidationError, validate
from protoforge.core.pcapio import PcapError, read_pcap


def make_proto(fields, name="demo", long_name="DEMO", bindings=None):
    return Protocol(name=name, long_name=long_name,
                    bindings=bindings or [Binding("udp.port", [5566])], fields=fields)


# ---------- F1: Lua 字符串转义 / 注入 ----------
def test_label_escaping_survives_lua():
    p = make_proto([
        Field("a", label='He said "hi" \\ and\nnewline', type="uint8"),
    ])
    lua = generate_lua(p)
    eng = LuaEngine()
    eng.load(lua)  # 不抛 LuaError 即通过
    r = eng.dissect(b"\x01")
    assert r.ok


def test_label_injection_cannot_execute(tmp_path):
    evil = 'x"); io.open("' + str(tmp_path / "pwned.txt").replace("\\", "/") + '","w")'
    p = make_proto([Field("a", label=evil, type="uint8")])
    lua = generate_lua(p)
    eng = LuaEngine()
    eng.load(lua)
    r = eng.dissect(b"\x01")
    assert r.ok
    assert not (tmp_path / "pwned.txt").exists()


def test_long_name_comment_safe():
    p = make_proto([Field("a")], long_name="Evil ]] local x = ")
    lua = generate_lua(p)
    eng = LuaEngine()
    eng.load(lua)
    assert eng.dissect(b"\x01").ok


def test_enum_value_escaping():
    p = make_proto([Field("a", type="uint8", enum={1: 'say "one"'})])
    lua = generate_lua(p)
    eng = LuaEngine()
    eng.load(lua)
    r = eng.dissect(b"\x01")
    assert r.ok
    assert 'say "one" (1)' in _tree_text(r)


def _tree_text(r):
    out = []

    def rec(n):
        out.append((n.label or "") + (": " + str(n.value) if n.value is not None else ""))
        for c in n.children:
            rec(c)
    if r.tree:
        rec(r.tree)
    return "\n".join(out)


# ---------- F2: 引用字段类型 / 作用域 ----------
def test_switch_on_string_rejected():
    p = make_proto([
        Field("s", type="string", size=2),
        Field("sw", type="switch", on="s", cases={1: [Field("x")]}),
    ])
    assert any("必须是数值" in e for e in validate(p))


def test_switch_on_other_case_scope_rejected():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [Field("deep", type="uint8")],
            2: [Field("sw2", type="switch", on="deep", cases={0: [Field("y")]})],
        }),
    ])
    assert any("不可见作用域" in e for e in validate(p))


def test_count_from_non_numeric_rejected():
    p = make_proto([
        Field("s", type="string", size=2),
        Field("arr", type="array", count_from="s", element=[Field("e", type="uint8")]),
    ])
    assert any("count_from" in e and "数值" in e for e in validate(p))


def test_seqNum_wrong_type_does_not_crash_engine():
    """seqNum 为 string 时 Info 列应省略而不是每帧报错。"""
    p = make_proto([
        Field("seqNum", type="string", size=2),
        Field("a", type="uint8"),
    ])
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"AB\x01")
    assert r.ok and r.error is None
    assert r.info == ""   # Info 列被安全省略


def test_seqNum_inside_case_does_not_crash():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [Field("seqNum", type="uint8")],
        }),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x01\x05")
    assert r.ok


def test_length_check_inside_case_rejected():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={1: [Field("ln", type="uint8")]}),
    ])
    p.length_check = {"field": "ln", "region": "payload"}
    assert any("顶层字段" in e for e in validate(p))


def test_length_check_non_numeric_rejected():
    p = make_proto([Field("ln", type="string", size=2)])
    p.length_check = {"field": "ln", "region": "payload"}
    assert any("必须是数值" in e for e in validate(p))


# ---------- F3: 协议名长度 ----------
def test_single_char_protocol_name_rejected():
    p = make_proto([Field("a")], name="x")
    assert any("至少 2 个字符" in e for e in validate(p))


# ---------- F4: 顶层结构契约 ----------
def test_second_top_switch_rejected():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw1", type="switch", on="m", cases={1: [Field("x")]}),
        Field("m2", type="uint8"),
        Field("sw2", type="switch", on="m2", cases={1: [Field("y")]}),
    ])
    assert any("最多允许一个 switch" in e for e in validate(p))


def test_top_level_boundary_array_rules():
    """v1.1 起：顶层 count/count_from 数组作为运行时边界合法（裸 TLV 链），
    但边界之后仅允许 crc16 收尾。"""
    from protoforge.core.model import is_top_boundary
    p = make_proto([Field("arr", type="array", count=2, element=[Field("e", type="uint8")])])
    assert validate(p) == []                      # 边界数组本身合法
    assert is_top_boundary(p.fields[0])
    # 边界后带非 crc 字段 → 拒绝
    p2 = make_proto([
        Field("n", type="uint8"),
        Field("arr", type="array", count_from="n", element=[Field("e", type="uint8")]),
        Field("tail", type="uint8"),
    ])
    assert any("仅允许 crc16 收尾" in e for e in validate(p2))
    # 边界后 crc16 收尾 → 合法
    p3 = make_proto([
        Field("n", type="uint8"),
        Field("arr", type="array", count_from="n",
              element=[Field("e", type="uint16")]),
        Field("ck", type="uint16", crc16="sum16"),
    ])
    assert validate(p3) == []


def test_field_after_switch_rejected():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={1: [Field("x")]}),
        Field("tail", type="uint8"),
    ])
    assert any("switch" in e and "之后" in e for e in validate(p))


def test_switch_must_be_last_in_case():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [Field("inner", type="uint8"),
                Field("sw2", type="switch", on="inner", cases={0: [Field("z")]}),
                Field("after", type="uint8")],
        }),
    ])
    assert any("之后不允许" in e for e in validate(p))


def test_crc16_inside_case_rejected():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [Field("crc", type="uint16", crc16="ccitt_false")],
        }),
    ])
    assert any("crc16 字段只能位于顶层末尾" in e for e in validate(p))


# ---------- F5: count / const ----------
def test_count_must_be_int():
    p = make_proto([Field("arr", type="array", count="abc", element=[Field("e", type="uint8")])])
    assert any("count 必须是整数" in e for e in validate(p))


def test_count_negative_rejected():
    p = make_proto([Field("arr", type="array", count=-1, element=[Field("e", type="uint8")])])
    assert any("超出范围" in e for e in validate(p))


def test_const_on_string_rejected():
    p = make_proto([Field("s", type="string", size=2, const="0x41")])
    assert any("const 仅支持数值" in e for e in validate(p))


def test_negative_const_rejected():
    p = make_proto([Field("a", type="uint8", const="-1")])
    assert any("不能为负数" in e for e in validate(p))


# ---------- F6: CSV ----------
def test_csv_long_name_with_spaces():
    p = import_csv("# proto: name=flat long_name=My Long Protocol Name\nname,type\na,uint8\n")
    assert p.name == "flat"
    assert p.long_name == "My Long Protocol Name"


def test_csv_bom_text_input():
    p = import_csv("\ufeff# proto: name=flat\nname,type\na,uint8\n")
    assert p.name == "flat"


def test_csv_export_quotes_roundtrip(tmp_path):
    p = make_proto([Field("v", label='Voltage, phase "A"', type="uint16")], name="csvq")
    out = tmp_path / "q.csv"
    export_csv(p, out)
    p2 = import_csv(out)
    assert p2.fields[0].label == 'Voltage, phase "A"'


def test_csv_newline_label_roundtrip(tmp_path):
    p = make_proto([Field("v", label="line1\nline2", type="uint8")], name="csvn")
    out = tmp_path / "n.csv"
    export_csv(p, out)
    p2 = import_csv(out)
    assert p2.fields[0].label == "line1\nline2"


def test_jsonio_enum_hex_key():
    p = load_protocol('{"meta":{"name":"hexe"},"bindings":[{"table":"udp.port","ports":[1]}],'
                      '"fields":[{"name":"a","type":"uint8","enum":{"0x10":"Sixteen"}}]}')
    assert p.fields[0].enum == {16: "Sixteen"}


# ---------- F(低): pcap 截断 ----------
def test_pcap_truncated_raises(tmp_path):
    p = tmp_path / "t.pcap"
    good = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    p.write_bytes(good + struct.pack("<IIII", 1, 0, 100, 100) + b"\x00" * 30)
    with pytest.raises(PcapError):
        read_pcap(p)


# ---------- mock 枚举显示与真机对齐（Name (value)） ----------
def test_masked_enum_display_matches_real():
    p = make_proto([
        Field("m4", label="M4", type="uint", width=4, enum={5: "Five"}),
        Field("pad", label="Pad", type="uint", width=4),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x50")
    assert "Five (5)" in _tree_text(r)
