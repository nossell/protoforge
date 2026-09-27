# -*- coding: utf-8 -*-
"""JSON ↔ Protocol 模型（兼容 spike 的 smsp.json 格式）。"""
from __future__ import annotations

import json
import os
from typing import Union

from .model import Binding, Field, Protocol, ValidationError


def _parse_field(d: dict) -> Field:
    f = Field(
        name=d.get("name", ""),
        label=d.get("label", ""),
        type=d.get("type", "uint8"),
        width=int(d.get("width", 0) or 0),
        display=d.get("display", "dec"),
        const=d.get("const"),
        size=int(d.get("size", 0) or 0),
        on=d.get("on"),
        count=d.get("count"),
        count_from=d.get("count_from"),
        crc16=d.get("crc16"),
    )
    if d.get("enum"):
        f.enum = {int(k, 0) if isinstance(k, str) else int(k): str(v) for k, v in d["enum"].items()}
    if d.get("cases"):
        f.cases = {int(k): [_parse_field(x) for x in v] for k, v in d["cases"].items()}
    if d.get("element"):
        f.element = [_parse_field(x) for x in d["element"]]
    return f


def _field_to_dict(f: Field) -> dict:
    d = {"name": f.name, "label": f.label, "type": f.type}
    if f.width:
        d["width"] = f.width
    if f.display != "dec":
        d["display"] = f.display
    if f.enum:
        d["enum"] = {str(k): v for k, v in f.enum.items()}
    if f.const is not None:
        d["const"] = f.const
    if f.size:
        d["size"] = f.size
    if f.on:
        d["on"] = f.on
    if f.cases:
        d["cases"] = {str(k): [_field_to_dict(x) for x in v] for k, v in f.cases.items()}
    if f.count is not None:
        d["count"] = f.count
    if f.count_from:
        d["count_from"] = f.count_from
    if f.element:
        d["element"] = [_field_to_dict(x) for x in f.element]
    if f.crc16:
        d["crc16"] = f.crc16
    return d


def load_protocol(src: Union[str, os.PathLike]) -> Protocol:
    """src 为 JSON 文件路径或 JSON 文本。"""
    s = str(src)
    if os.path.exists(s):
        with open(s, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = json.loads(s)
    return load_protocol_dict(data)


def load_protocol_dict(data: dict) -> Protocol:
    meta = data.get("meta", {}) or {}
    p = Protocol(
        name=meta.get("name", "myproto"),
        long_name=meta.get("long_name", ""),
        desc=meta.get("desc", ""),
        length_check=meta.get("length_check"),
    )
    if not p.long_name:
        p.long_name = p.name.upper()
    for b in data.get("bindings", []):
        p.bindings.append(Binding(table=b.get("table", "udp.port"), ports=list(b.get("ports", []))))
    p.fields = [_parse_field(f) for f in data.get("fields", [])]
    return p


def protocol_to_dict(p: Protocol) -> dict:
    meta = {"name": p.name, "long_name": p.long_name, "desc": p.desc}
    if p.length_check:
        meta["length_check"] = p.length_check
    return {
        "meta": meta,
        "bindings": [{"table": b.table, "ports": list(b.ports)} for b in p.bindings],
        "fields": [_field_to_dict(f) for f in p.fields],
    }


def save_protocol(p: Protocol, path: os.PathLike) -> None:
    errs_ok = True  # 保存允许半成品，读取方负责校验
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(protocol_to_dict(p), fh, ensure_ascii=False, indent=2)
        fh.write("\n")
