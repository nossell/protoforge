# -*- coding: utf-8 -*-
"""R3 v0.12.0 回归：嵌套 switch + default 分支。"""
from protoforge.core.generator import generate_lua
from protoforge.core.jsonio import load_protocol, protocol_to_dict
from protoforge.core.luaengine import LuaEngine
from protoforge.core.model import Binding, Field, Protocol, validate


def make_proto(fields, name="nstdemo", long_name="NSTDEMO"):
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


def test_nested_switch_dissect():
    """case 内嵌套 switch（作为 case 最后字段）：两级条件分支正确解析。"""
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [
                Field("sub", type="uint8"),
                Field("sw2", type="switch", on="sub", cases={
                    1: [Field("a", type="uint8")],
                    2: [Field("b", type="uint16")],
                }),
            ],
        }),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x01\x02\x00\x05")     # m=1, sub=2, b=5
    text = tree_text(r)
    assert "B: 5" in text or "b: 5" in text
    assert r.error is None


def test_default_branch_used_on_unknown():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [Field("x", type="uint8")],
        }, default=[Field("fallback", type="uint16")]),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x09\x00\x07")          # m=9 未命中 → default
    text = tree_text(r)
    assert "fallback: 7" in text
    assert "unknown" not in text.lower()


def test_no_default_still_annotates_unknown():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={1: [Field("x", type="uint8")]}),
    ])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x09\x00\x00")
    assert "unknown" in tree_text(r).lower()


def test_default_case_visible_refs():
    """default 分支内可引用 switch 之前的字段（count_from 语义）。"""
    p = make_proto([
        Field("n", type="uint8"),
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [Field("x", type="uint8")],
        }, default=[Field("arr", type="array", count_from="n",
                          element=[Field("e", type="uint8")])]),
    ])
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x02\x09\x41\x42")
    text = tree_text(r)
    assert "E: 65" in text or "e: 65" in text


def test_default_list_validated():
    """default 列表内的非法定义同样被校验（重名/缺引用等）。"""
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={1: [Field("x")]},
              default=[Field("bad", type="string")]),   # string 缺 size/length_from/terminated_by
    ])
    errs = validate(p)
    assert any("default" in e and "size" in e for e in errs)


def test_default_json_roundtrip():
    import json
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={1: [Field("x", type="uint8")]},
              default=[Field("fb", type="uint16")]),
    ])
    d = protocol_to_dict(p)
    sw = d["fields"][1]
    assert sw["cases"]["default"] == [{"name": "fb", "label": "", "type": "uint16"}]
    p2 = load_protocol(json.dumps(d))
    assert p2.fields[1].default[0].name == "fb"


def test_deeply_nested_switch_three_levels():
    p = make_proto([
        Field("m", type="uint8"),
        Field("sw", type="switch", on="m", cases={
            1: [
                Field("s1", type="uint8"),
                Field("sw2", type="switch", on="s1", cases={
                    1: [
                        Field("s2", type="uint8"),
                        Field("sw3", type="switch", on="s2", cases={
                            1: [Field("deep", type="uint32")],
                        }),
                    ],
                }),
            ],
        }),
    ])
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x01\x01\x01\x00\x00\x00\x2A")   # 7 字节: 1,1,1 + uint32=42
    text = tree_text(r)
    assert "42" in text
    assert r.error is None
