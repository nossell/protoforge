# -*- coding: utf-8 -*-
"""CSV ↔ Protocol（平铺字段子集）。

约定：
- 首行表头（列名固定子集，顺序不限）：name,label,type,width,display,enum,const,size
- '#' 开头为指令/注释行：
    # proto: name=smsp long_name=SmartMesh Sensor Protocol
    # bind: udp.port 5566 5567        （可多行；tcp.port 同理）
- enum 单元格语法：1=Telemetry;2=Config
- CSV 只表达平铺字段；switch/array 等嵌套结构请用 JSON（导出时抛 CsvUnsupported）。
"""
from __future__ import annotations

import csv
import io
import os
import re
from typing import Union

from .model import Binding, Field, Protocol

CSV_COLUMNS = ["name", "label", "type", "width", "display", "enum", "const", "size"]


class CsvUnsupported(ValueError):
    """协议含 CSV 无法表达的结构。"""


def _parse_enum(cell: str):
    cell = (cell or "").strip()
    if not cell:
        return None
    out = {}
    for part in cell.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise CsvUnsupported(f"enum 项 '{part}' 缺少 '='（语法：1=Telemetry;2=Config）")
        k, v = part.split("=", 1)
        out[int(k.strip(), 0)] = v.strip()
    return out or None


def import_csv(src: Union[str, os.PathLike]) -> Protocol:
    """src 为 CSV 文件路径或 CSV 文本。"""
    s = str(src)
    if os.path.exists(s):
        with open(s, "r", encoding="utf-8-sig", newline="") as fh:
            text = fh.read()
    else:
        text = s
    text = text.lstrip("\ufeff")  # 文本入口同样容忍 BOM

    p = Protocol(name="csvproto", long_name="CSVPROTO")
    rows: list[dict] = []
    header: list[str] | None = None

    # 第一遍：剥离头部指令/注释行，定位表头；表头之后全部交给 csv.reader
    # （整体解析以正确支持带换行/逗号的引号单元格）
    lines = text.splitlines(keepends=True)
    body_start = len(lines)
    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#"):
            m = re.match(r"#\s*proto:\s*(.*)", s)
            if m:
                rest = m.group(1).strip()
                lm = re.search(r"long_name=(.*)$", rest)
                if lm:
                    p.long_name = lm.group(1).strip() or p.long_name
                    rest = rest[: lm.start()].strip()
                nm = re.search(r"name=(\S+)", rest)
                if nm:
                    p.name = nm.group(1)
                    if not lm:
                        p.long_name = p.name.upper()
                continue
            m = re.match(r"#\s*bind:\s*(\S+)\s+(.*)", s)
            if m:
                table = m.group(1)
                ports = [int(x, 0) for x in m.group(2).replace(",", " ").split()]
                p.bindings.append(Binding(table=table, ports=ports))
            continue  # 其余 # 行为注释
        header = [h.strip() for h in next(csv.reader(io.StringIO(s)))]
        missing = {"name", "type"} - set(header)
        if missing:
            raise CsvUnsupported(f"表头缺少必需列: {sorted(missing)}")
        body_start = i + 1
        break

    if header is not None:
        body = "".join(lines[body_start:])
        for row in csv.reader(io.StringIO(body)):
            if not row or all(not str(x).strip() for x in row):
                continue
            rows.append(dict(zip(header, row)))

    if not p.bindings:
        p.bindings = [Binding("udp.port", [5566])]  # 默认端口，导入后可在 GUI 修改

    for r in rows:
        f = Field(
            name=(r.get("name") or "").strip(),
            label=(r.get("label") or "").strip(),
            type=(r.get("type") or "uint8").strip(),
            width=int(r["width"] or 0) if (r.get("width") or "").strip() else 0,
            display=(r.get("display") or "dec").strip(),
            const=(r.get("const") or "").strip() or None,
            size=int(r["size"] or 0) if (r.get("size") or "").strip() else 0,
        )
        f.enum = _parse_enum(r.get("enum") or "")
        p.fields.append(f)
    return p


def export_csv(p: Protocol, path: os.PathLike) -> None:
    from .model import walk

    nested = [f.name for f in p.fields if f.type in ("switch", "array")]
    if nested:
        raise CsvUnsupported(
            f"字段 {nested} 为嵌套结构，CSV 无法表达；请保存为 JSON")

    lines = [f"# proto: name={p.name} long_name={p.long_name}"]
    for b in p.bindings:
        lines.append(f"# bind: {b.table} " + " ".join(str(x) for x in b.ports))
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for f in p.fields:
        enum = ";".join(f"{k}={v}" for k, v in (f.enum or {}).items())
        w.writerow([
            f.name, f.label, f.type, f.width or "", f.display, enum,
            f.const or "", f.size or "",
        ])
    lines.append(out.getvalue().rstrip("\n"))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
