# -*- coding: utf-8 -*-
"""v0.14.0 独立审查（deepseek）修复回归：F-A/F-B/F-C/F-D/F-E/F-G。

每个用例对应一条审查发现，先复现缺陷形态再断言修复后的行为。
"""
import os
import struct

import pytest

from protoforge.core.generator import generate_lua
from protoforge.core.luaengine import LuaEngine
from protoforge.core.model import Binding, Field, Protocol, ValidationError, validate
from protoforge.core.pcapio import PcapError, read_pcap


def tree_text(r):
    out = []

    def rec(n):
        out.append((n.label or "") + (": " + str(n.value) if n.value is not None else ""))
        for c in n.children:
            rec(c)
    if r.tree:
        rec(r.tree)
    return "\n".join(out)


# ---------- F-A：heuristic 首字段为位域（曾 KeyError: 'uint' 崩溃） ----------
def test_heuristic_bitfield_first_field_generates():
    p = Protocol(name="heurbf", long_name="HEURBF", heuristic="udp",
                 bindings=[Binding("udp.port", [5566])],
                 fields=[
                     Field("ver", type="uint", width=4, const="0x5"),
                     Field("flags", type="uint", width=4),
                     Field("payload", type="bytes", size=2),
                 ])
    assert validate(p) == []
    lua = generate_lua(p)                     # 修复前：KeyError 'uint'
    assert "bitfield(0, 4)" in lua
    eng = LuaEngine()
    eng.load(lua)
    table, fn = eng._proto.heuristics[0]
    assert table == "udp"
    import protoforge.core.luaengine as LE
    assert fn(LE._Tvb(list(b"\x51\xaa\xbb")), LE._PInfo(), LE._TreeItem("H")) is True
    assert fn(LE._Tvb(list(b"\x11\xaa\xbb")), LE._PInfo(), LE._TreeItem("H")) is False


# ---------- F-B：length_from 数组的变长元素（曾生成 math.floor(rgn/0) 死循环） ----------
def _lenfrom_array(elem):
    return Protocol(name="arrz", long_name="ARRZ",
                    bindings=[Binding("udp.port", [5566])],
                    fields=[Field("rlen", type="uint16"),
                            Field("items", type="array", length_from="rlen", element=elem)])


def test_length_from_array_variable_element_rejected():
    p = _lenfrom_array([Field("s", type="string", terminated_by=0)])
    errs = validate(p)
    assert any("全为定长字段" in e for e in errs)
    with pytest.raises(ValidationError):
        generate_lua(p)


def test_length_from_array_length_from_element_rejected():
    p = _lenfrom_array([Field("n", type="uint8"),
                        Field("s", type="string", length_from="n")])
    assert any("全为定长字段" in e for e in validate(p))


def test_length_from_array_fixed_element_still_ok():
    p = _lenfrom_array([Field("a", type="uint8"), Field("b", type="uint16")])
    assert validate(p) == []
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x00\x06" + b"\x01\x00\x02" + b"\x03\x00\x04")   # rlen=6 → 2×3 字节元素
    text = tree_text(r)
    assert "a: 1" in text and "b: 2" in text
    assert "a: 3" in text and "b: 4" in text
    assert r.error is None


# ---------- F-C：过短帧应认领并显示 expert（曾 return 0 → 真机丢弃树节点） ----------
def test_too_short_claims_packet_and_shows_expert():
    p = Protocol(name="shorty", long_name="SHORTY",
                 bindings=[Binding("udp.port", [5566])],
                 fields=[Field("magic", type="uint32"), Field("tail", type="uint32")])
    eng = LuaEngine()
    eng.load(generate_lua(p))
    r = eng.dissect(b"\x01\x02")              # 2 字节 < min_len(8)
    assert r.ok
    assert r.consumed == 2                    # 修复前为 0（真机上等于放弃该帧）
    assert r.protocol == "SHORTY"             # 认领后 protocol 列有值
    assert "too short" in (r.error or "")


# ---------- F-D：GUI 数组 length_from 可编辑且不被改写 ----------
def _gui():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from protoforge.app.main_window import MainWindow
    return MainWindow()


def test_gui_array_length_from_roundtrip():
    from protoforge.core.jsonio import load_protocol_dict
    spec = {"meta": {"name": "guip3", "long_name": "GUIP3"},
            "bindings": [{"table": "udp.port", "ports": [9101]}],
            "fields": [{"name": "rlen", "label": "RLen", "type": "uint16"},
                       {"name": "items", "label": "Item", "type": "array",
                        "length_from": "rlen",
                        "element": [{"name": "e", "label": "E", "type": "uint8"}]}]}
    w = _gui()
    w.protocol = load_protocol_dict(spec)
    w._reload_all()
    arr = w.protocol.fields[1]
    w._on_field_selected(arr)
    assert w.props.count_mode.currentIndex() == 2      # 区域长度模式
    assert w.props.length_from_combo.currentText() == "rlen"
    w.props.label_edit.setText("Renamed")
    w.props._apply()
    # 修复前：这里会注入 count=1，模型变非法
    assert arr.length_from == "rlen" and arr.count is None and arr.count_from is None
    assert validate(w.protocol) == []
    w.close()


# ---------- F-E：GUI 加载 heuristic=tcp 不再被静默清除 ----------
def test_gui_heuristic_tcp_survives_load():
    from protoforge.core.jsonio import load_protocol_dict

    def spec(mode, name, table):
        return {"meta": {"name": name, "long_name": name.upper(), "heuristic": mode},
                "bindings": [{"table": table, "ports": [9100]}],
                "fields": [{"name": "magic", "type": "uint16", "const": "0xABCD"},
                           {"name": "v", "type": "uint8"}]}

    w = _gui()
    w.protocol = load_protocol_dict(spec("udp", "guip1", "udp.port"))
    w._reload_all()
    assert w.protocol.heuristic == "udp"
    w.protocol = load_protocol_dict(spec("tcp", "guip2", "tcp.port"))
    w._reload_all()
    # 修复前：勾选框从选中变未选中会触发回写，heuristic 被清成 None
    assert w.protocol.heuristic == "tcp"
    assert w.heur_combo.currentText() == "tcp"
    w.close()


# ---------- F-G：pcapng 畸形块应报 PcapError，而非 struct.error ----------
def test_pcapng_tiny_idb_raises_pcaperror(tmp_path):
    I = struct.Struct("<I").pack
    H = struct.Struct("<H").pack

    def block(btype, body):
        total = 12 + len(body) + ((4 - len(body) % 4) % 4)
        pad = b"\x00" * ((4 - len(body) % 4) % 4)
        return I(btype) + I(total) + body + pad + I(total)

    shb = block(0x0A0D0D0A, I(0x1A2B3C4D) + H(1) + H(0) + I(0xFFFFFFFF))
    tiny_idb = block(0x00000001, b"")          # 空 body：规格上非法
    p = tmp_path / "bad.pcapng"
    p.write_bytes(shb + tiny_idb)
    with pytest.raises(PcapError):
        read_pcap(p)


# ---------- F-J：手改 JSON 里的非法枚举值不应让 GUI 崩溃 ----------
def test_gui_load_invalid_enum_values_does_not_crash():
    from protoforge.core.jsonio import load_protocol_dict
    spec = {"meta": {"name": "guip4", "long_name": "GUIP4", "heuristic": "icmp"},
            "bindings": [{"table": "udp.port", "ports": [9102]}],
            "fields": [{"name": "magic", "type": "uint16", "const": "0xABCD"},
                       {"name": "ck", "type": "uint16", "crc16": "crc32"}]}
    w = _gui()
    w.protocol = load_protocol_dict(spec)
    w._reload_all()                            # 修复前：list.index 抛 ValueError
    w._on_field_selected(w.protocol.fields[1])
    assert validate(w.protocol)                  # 非法值只应体现为校验错误
    assert w.heur_combo.currentIndex() == 0      # 非法 heuristic 回落到「无」
    w.close()
