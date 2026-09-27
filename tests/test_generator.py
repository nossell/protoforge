# -*- coding: utf-8 -*-
import pytest

from protoforge.core.generator import generate_lua
from protoforge.core.model import Binding, Field, Protocol, ValidationError


def test_smsp_generated_key_lines(smsp):
    lua = generate_lua(smsp)
    assert 'local proto = Proto("smsp", "SmartMesh Sensor Protocol")' in lua
    # 位域掩码
    assert "0xF0" in lua and "0x0F" in lua          # version / msgType
    assert "0x80" in lua and "0x1F" in lua          # online / flagsRsv
    # bitfield 读取（MSB 起算；仅被引用字段生成读取表达式）
    assert ":bitfield(4, 4)" in lua
    # spike 踩坑回归
    assert "get_index(" in lua                       # ByteArray API
    assert "append_text" in lua                      # CRC 说明追加
    assert "-- [[" not in lua                        # 块注释无空格
    assert "%%" not in lua                           # 无双重百分号
    assert "GPLv2+" in lua                           # 授权声明
    # 绑定
    assert 'DissectorTable.get("udp.port")' in lua
    assert ":add(5566, proto)" in lua and ":add(5567, proto)" in lua
    # 数组与条件
    assert "for i = 1, v_sensorCount do" in lua
    assert "if v_msgType == 1 then" in lua
    assert "elseif v_msgType == 2 then" in lua


def test_string_bytes_types():
    p = Protocol(
        name="sb", long_name="SB",
        bindings=[Binding("udp.port", [9000])],
        fields=[
            Field("tag", type="string", size=4),
            Field("blob", type="bytes", size=6),
            Field("n", type="uint8"),
        ],
    )
    lua = generate_lua(p)
    assert 'ProtoField.string("sb.tag"' in lua
    assert 'ProtoField.bytes("sb.blob"' in lua
    assert "buffer(off, 4))" in lua and "buffer(off, 6))" in lua


def test_tcp_binding():
    p = Protocol(
        name="tcpdemo", long_name="TCPDEMO",
        bindings=[Binding("tcp.port", [7000, 7001])],
        fields=[Field("a", type="uint8")],
    )
    lua = generate_lua(p)
    assert 'DissectorTable.get("tcp.port")' in lua
    assert "tbl_tcp_port:add(7000, proto)" in lua


def test_invalid_protocol_raises():
    p = Protocol(name="bad", long_name="BAD", bindings=[], fields=[Field("a")])
    with pytest.raises(ValidationError):
        generate_lua(p)


def test_min_length_guard():
    p = Protocol(
        name="mm", long_name="M",
        bindings=[Binding("udp.port", [1])],
        fields=[Field("a", type="uint16"), Field("b", type="uint8")],
    )
    lua = generate_lua(p)
    assert "if len < 3 then" in lua
