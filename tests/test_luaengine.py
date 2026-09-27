# -*- coding: utf-8 -*-
"""集成：JSON → Lua → mock 引擎执行 → 树断言（spike 全场景 + 扩展类型）。"""
import struct

import pytest

from protoforge.core.generator import generate_lua
from protoforge.core.luaengine import LuaEngine, LuaError
from protoforge.core.model import Binding, Field, Protocol

from conftest import crc16_ccitt_false, smsp_frame


@pytest.fixture(scope="module")
def engine(smsp_module):
    eng = LuaEngine()
    eng.load(generate_lua(smsp_module))
    return eng


@pytest.fixture(scope="module")
def smsp_module():
    from protoforge.core.jsonio import load_protocol
    import os
    ex = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "smsp.json")
    return load_protocol(ex)


def find(node, label):
    """先全树精确匹配 label；找不到再退化为前缀匹配。"""
    stack = [node]
    while stack:
        n = stack.pop(0)
        if n.label == label:
            return n
        stack.extend(n.children)
    stack = [node]
    while stack:
        n = stack.pop(0)
        if n.label.startswith(label):
            return n
        stack.extend(n.children)
    return None


def collect(node, out=None):
    out = out if out is not None else []
    out.append((node.label, node.value))
    for c in node.children:
        collect(c, out)
    return out


def test_bindings(engine):
    assert ("udp.port", 5566, "smsp") in engine.bindings
    assert ("udp.port", 5567, "smsp") in engine.bindings


def test_telemetry(engine, smsp_frames):
    r = engine.dissect(smsp_frames["telemetry"])
    assert r.ok and r.error is None
    assert r.protocol == "SMSP"
    assert r.info == "Telemetry, Seq=1"
    items = dict(collect(r.tree))
    assert items.get("Magic") == "0x5A5A"
    assert items.get("Protocol Version") == "1"
    assert items.get("Message Type") == "Telemetry (1)"
    assert items.get("Sensor Count") == "2"
    assert items.get("Sensor ID") == "0x0304"      # dict 后写覆盖：第二个传感器
    assert items.get("Battery Low") == "False"     # 第二个传感器
    assert items.get("Calibrated") == "True"       # 第二个传感器
    assert items.get("Raw Value") == "4200"
    assert items.get("Quality") == "Excellent (3)"
    assert items.get("CRC-16/CCITT [correct]") == "0x875A"
    s0 = find(r.tree, "Sensor [0]")
    s0v = {c.label: c.value for c in s0.children}
    assert s0v["Sensor ID"] == "0x0102"
    assert s0v["Battery Low"] == "True"            # 第一个传感器低电量
    assert s0v["Raw Value"] == "-125"
    assert " [correct]" in [l for l, _ in collect(r.tree) if l.startswith("CRC")][0]
    assert r.consumed == 21
    # 字节范围（GUI hex 联动）
    m = find(r.tree, "Magic")
    assert m.offset == 0 and m.length == 2
    s0 = find(r.tree, "Sensor [0]")
    assert s0.offset == 7 and s0.length == 6


def test_config(engine, smsp_frames):
    r = engine.dissect(smsp_frames["config"])
    items = dict(collect(r.tree))
    assert items.get("Report Interval (ms)") == "5000"
    ths = [v for l, v in collect(r.tree) if l.startswith("Alert Threshold")]
    assert ths == ["100", "-50", "75"]
    assert r.info == "Config, Seq=2"


def test_event(engine, smsp_frames):
    r = engine.dissect(smsp_frames["event"])
    items = dict(collect(r.tree))
    assert items.get("Event Code") == "Low Battery (3)"
    assert items.get("Timestamp (UTC)") == "1770000000"


def test_bad_crc_expert(engine, smsp_frames):
    r = engine.dissect(smsp_frames["bad_crc"])
    assert r.ok  # 解析完成但带 expert
    assert r.error and "Checksum" in r.error
    crc_line = [l for l, _ in collect(r.tree) if l.startswith("CRC")][0]
    assert "[incorrect, expected 0x875A]" in crc_line


def test_too_short(engine):
    r = engine.dissect(b"\x5a\x5a\x11")
    assert r.ok
    assert r.error and "too short" in r.error.lower() or "Packet too short" in r.error


def test_magic_mismatch_expert(engine):
    payload = struct.pack(">B", 0)  # 0 sensors
    frame = bytearray(smsp_frame(1, 1, 9, payload))
    frame[0] = 0x11  # 破坏 magic
    # 重算 CRC 使其余部分一致（magic 也参与 CRC，重算后 crc 对，只有 const 告警）
    body = bytes(frame[:-2])
    frame[-2:] = struct.pack(">H", crc16_ccitt_false(body))
    r = engine.dissect(bytes(frame))
    assert r.ok
    assert r.error and "Constant mismatch" in r.error


def test_trailing_bytes_expert(engine):
    payload = struct.pack(">B", 0)
    frame = smsp_frame(1, 1, 9, payload)
    r = engine.dissect(frame + b"\x00\x00")  # 尾部塞 2 字节垃圾（CRC 在前，解析后剩尾随）
    assert r.ok
    assert r.error and "trailing" in r.error


def test_unknown_msgtype(engine):
    payload = b"\x01\x02"
    frame = smsp_frame(1, 9, 4, payload)  # msgType=9 未知
    r = engine.dissect(frame)
    assert r.ok
    labels = [l for l, _ in collect(r.tree)]
    assert any("unknown msgType 9" in l for l in labels)


def test_lua_syntax_error():
    eng = LuaEngine()
    with pytest.raises(LuaError):
        eng.load("local x = (")


def test_string_bytes_protocol():
    p = Protocol(
        name="sb", long_name="SB",
        bindings=[Binding("udp.port", [9000])],
        fields=[
            Field("tag", type="string", size=4, label="Tag"),
            Field("blob", type="bytes", size=3, label="Blob"),
        ],
    )
    eng = LuaEngine()
    eng.load(generate_lua(p))
    frame = b"ABD" + b"\x00\x01\x02"
    # tag(4)="ABD\x00" + blob(3)
    frame = b"ABD\x00" + b"\x01\x02\x03"
    r = eng.dissect(frame)
    items = dict(collect(r.tree))
    assert items.get("Tag") == '"ABD\\x00"' or items.get("Tag").startswith('"ABD')
    assert items.get("Blob") == "010203"


def test_info_column(engine, smsp_frames):
    r = engine.dissect(smsp_frames["event"])
    assert r.info == "Event, Seq=3"
