# -*- coding: utf-8 -*-
import pytest

from protoforge.core.model import (
    Binding, Field, Protocol, ValidationError,
    field_size, static_size, validate, validate_or_raise, walk,
)


def make_proto(fields, name="demo", bindings=None):
    return Protocol(
        name=name, long_name="DEMO",
        bindings=bindings or [Binding("udp.port", [5566])],
        fields=fields,
    )


def test_valid_smsp(smsp):
    assert validate(smsp) == []


def test_duplicate_name():
    p = make_proto([Field("a", type="uint8"), Field("a", type="uint8")])
    errs = validate(p)
    assert any("重复" in e for e in errs)


def test_bad_identifier():
    p = make_proto([Field("2fast", type="uint8")])
    assert any("非法字段名" in e for e in validate(p))


def test_unknown_type():
    p = make_proto([Field("x", type="float16")])
    assert any("未知类型" in e for e in validate(p))


def test_bitfield_group_not_byte_aligned():
    p = make_proto([
        Field("a", type="uint", width=3),
        Field("b", type="uint", width=4),
    ])
    assert any("不成字节边界" in e for e in validate(p))


def test_bitfield_ok_packs_to_byte():
    p = make_proto([
        Field("a", type="uint", width=3),
        Field("b", type="uint", width=5),
        Field("c", type="uint8"),
    ])
    assert validate(p) == []
    assert static_size(p.fields) == 2


def test_switch_on_missing():
    p = make_proto([Field("p", type="switch", on="nothere", cases={1: [Field("x")]})])
    assert any("未在其之前声明" in e for e in validate(p))


def test_switch_on_declared_after():
    p = make_proto([
        Field("p", type="switch", on="later", cases={1: [Field("x")]}),
        Field("later", type="uint8"),
    ])
    assert any("未在其之前声明" in e for e in validate(p))


def test_array_count_conflict():
    p = make_proto([
        Field("n", type="uint8"),
        Field("arr", type="array", count=2, count_from="n", element=[Field("e", type="uint8")]),
    ])
    assert any("三选一" in e for e in validate(p))


def test_array_count_from_missing():
    p = make_proto([Field("arr", type="array", count_from="n", element=[Field("e", type="uint8")])])
    assert any("未在其之前声明" in e for e in validate(p))


def test_crc_must_be_last():
    p = make_proto([
        Field("crc", type="uint16", crc16="ccitt_false"),
        Field("tail", type="uint8"),
    ])
    assert any("最后一个" in e for e in validate(p))


def test_crc_must_be_uint16():
    p = make_proto([Field("crc", type="uint32", crc16="ccitt_false")])
    assert any("要求字段类型" in e for e in validate(p))


def test_string_needs_size():
    p = make_proto([Field("s", type="string")])
    assert any("定长 size" in e for e in validate(p))


def test_no_binding():
    p = Protocol(name="x", long_name="X", bindings=[], fields=[Field("a", type="uint8")])
    assert any("缺少绑定" in e for e in validate(p))


def test_bad_port():
    p = make_proto([Field("a", type="uint8")], bindings=[Binding("udp.port", [70000])])
    assert any("超范围" in e for e in validate(p))


def test_bad_const():
    p = make_proto([Field("m", type="uint16", const="zzz")])
    assert any("const" in e for e in validate(p))


def test_length_check_ref():
    p = make_proto([Field("a", type="uint8")])
    p.length_check = {"field": "ghost", "region": "payload"}
    assert any("length_check" in e for e in validate(p))


def test_element_cannot_nest_switch():
    p = make_proto([
        Field("n", type="uint8"),
        Field("arr", type="array", count_from="n",
              element=[Field("s", type="switch", on="n", cases={1: [Field("x")]})]),
    ])
    assert any("元素内不允许嵌" in e for e in validate(p))


def test_walk_and_sizes(smsp):
    names = [f.name for f in walk(smsp.fields)]
    assert names[:5] == ["magic", "version", "msgType", "seqNum", "payloadLen"]
    assert "sensorId" in names and "crc16" in names
    assert field_size(Field("x", type="uint24")) == 3
    assert field_size(Field("x", type="string", size=8)) == 8
    assert field_size(Field("x", type="switch", on="y", cases={1: []})) is None


def test_validate_or_raise(smsp):
    validate_or_raise(smsp)  # 不抛
    with pytest.raises(ValidationError):
        validate_or_raise(make_proto([Field("a"), Field("a")]))
