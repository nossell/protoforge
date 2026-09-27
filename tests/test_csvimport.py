# -*- coding: utf-8 -*-
import pytest

from protoforge.core.csvimport import CsvUnsupported, export_csv, import_csv
from protoforge.core.model import validate

CSV_TEXT = """\
# proto: name=flat long_name=FlatDemo
# bind: udp.port 7777 8888
name,label,type,width,display,enum,const,size
magic,Magic,uint16,,hex,,0x5A5A,
ver,Version,uint,4,,,,
kind,Kind,uint,4,,1=A;2=B;3=C,,
seq,Seq,uint8,,,,,
blob,Blob,bytes,,,,,4
tag,Tag,string,,,,,3
"""


def test_import_flat():
    p = import_csv(CSV_TEXT)
    assert p.name == "flat" and p.long_name == "FlatDemo"
    assert p.bindings[0].table == "udp.port"
    assert p.bindings[0].ports == [7777, 8888]
    assert len(p.fields) == 6
    f0 = p.fields[0]
    assert f0.name == "magic" and f0.const == "0x5A5A" and f0.display == "hex"
    assert p.fields[1].width == 4 and p.fields[1].type == "uint"
    assert p.fields[2].enum == {1: "A", 2: "B", 3: "C"}
    assert p.fields[4].size == 4 and p.fields[4].type == "bytes"
    assert p.fields[5].type == "string" and p.fields[5].size == 3


def test_import_validates():
    p = import_csv(CSV_TEXT)
    assert validate(p) == []


def test_default_binding_when_missing():
    p = import_csv("name,type\nx,uint8\n")
    assert p.bindings[0].ports == [5566]


def test_roundtrip(tmp_path):
    p = import_csv(CSV_TEXT)
    out = tmp_path / "rt.csv"
    export_csv(p, out)
    p2 = import_csv(out)
    assert [f.name for f in p2.fields] == [f.name for f in p.fields]
    assert p2.bindings == p.bindings
    assert p2.fields[2].enum == {1: "A", 2: "B", 3: "C"}


def test_export_nested_rejected(smsp, tmp_path):
    with pytest.raises(CsvUnsupported):
        export_csv(smsp, tmp_path / "x.csv")


def test_bad_enum():
    with pytest.raises(CsvUnsupported):
        import_csv("name,type,enum\nx,uint8,BROKEN\n")


def test_missing_header_columns():
    with pytest.raises(CsvUnsupported):
        import_csv("name\nx\n")


def test_load_from_file(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text(CSV_TEXT, encoding="utf-8")
    p = import_csv(f)
    assert p.name == "flat"
