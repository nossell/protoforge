# -*- coding: utf-8 -*-
import json
import os

from protoforge.core.jsonio import load_protocol, protocol_to_dict, save_protocol

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "smsp.json")


def test_load_example_from_path():
    p = load_protocol(EXAMPLE)
    assert p.name == "smsp"
    assert p.long_name == "SmartMesh Sensor Protocol"
    assert p.bindings[0].table == "udp.port"
    assert p.bindings[0].ports == [5566, 5567]
    assert len(p.fields) == 7
    sw = p.fields[5]
    assert sw.type == "switch" and sw.on == "msgType"
    assert set(sw.cases.keys()) == {1, 2, 3}
    arr = sw.cases[1][1]
    assert arr.type == "array" and arr.count_from == "sensorCount"
    assert len(arr.element) == 7
    assert p.fields[-1].crc16 == "ccitt_false"
    assert p.fields[2].enum == {1: "Telemetry", 2: "Config", 3: "Event"}


def test_load_from_text():
    with open(EXAMPLE, "r", encoding="utf-8") as fh:
        p = load_protocol(fh.read())
    assert p.name == "smsp"


def test_roundtrip(tmp_path):
    p = load_protocol(EXAMPLE)
    save_protocol(p, tmp_path / "rt.json")
    p2 = load_protocol(tmp_path / "rt.json")
    assert protocol_to_dict(p) == protocol_to_dict(p2)


def test_long_name_default():
    p = load_protocol(json.dumps({"meta": {"name": "xx"}, "bindings": [], "fields": []}))
    assert p.long_name == "XX"
