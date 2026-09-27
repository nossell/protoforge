# -*- coding: utf-8 -*-
"""Lua 执行引擎：用 lupa(lua54) + 模拟 Wireshark Lua API 真实执行生成的 dissector。

用途：GUI 测试台与 CI——无 Wireshark 环境下验证生成的 Lua 代码是否正确。
mock 覆盖：Proto / ProtoField(含 bool/string/bytes/none) / ProtoExpert / DissectorTable /
Tvb(TvbRange/ByteArray) / TreeItem(含 range 追踪) / pinfo.cols / base / expert。
已按真实 Wireshark 4.6 行为校准：
- ByteArray 字节访问 get_index()（get() 不存在）
- 位域显示先掩码后右移
- add(field, range, string) 不适用数值字段（引擎直接不支持该形态，与真机一致）
"""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Optional


class LuaError(RuntimeError):
    """Lua 代码加载或执行失败。"""


@dataclass
class TreeNode:
    """GUI 可直接消费的解析树节点（含字节范围，供 hex 高亮联动）。"""
    label: str = ""
    value: Optional[str] = None
    offset: int = 0
    length: int = 0
    expert: bool = False
    expert_tag: str = ""
    children: list = dc_field(default_factory=list)


@dataclass
class DissectResult:
    ok: bool = True
    error: Optional[str] = None
    info: str = ""
    protocol: str = ""
    consumed: int = 0
    tree: Optional[TreeNode] = None


# ---------------- mock Wireshark 对象 ----------------
class _ByteArray:
    def __init__(self, data):
        self._d = data

    def get_index(self, i):
        return self._d[i]

    def len(self):
        return len(self._d)


class _TvbRange:
    def __init__(self, data, off, ln):
        self.data, self.off, self.ln = data, off, ln

    def uint(self):
        v = 0
        for i in range(self.ln):
            v = (v << 8) | self.data[self.off + i]
        return v

    def int(self):
        v = self.uint()
        bits = self.ln * 8
        return v - (1 << bits) if v >= (1 << (bits - 1)) else v

    def bitfield(self, bitoff, bitcount):
        v = self.uint()
        shift = self.ln * 8 - bitoff - bitcount
        return (v >> shift) & ((1 << bitcount) - 1)

    def le_uint(self):
        v = 0
        for i in range(self.ln - 1, -1, -1):
            v = (v << 8) | self.data[self.off + i]
        return v

    def le_int(self):
        v = self.le_uint()
        bits = self.ln * 8
        return v - (1 << bits) if v >= (1 << (bits - 1)) else v

    def bytes(self):
        return _ByteArray(self.data[self.off:self.off + self.ln])

    def len(self):
        return self.ln

    def string(self):
        return bytes(self.data[self.off:self.off + self.ln]).decode("latin-1")

    def _mask_shift(self, mask):
        return (mask & -mask).bit_length() - 1 if mask else 0


class _Tvb:
    def __init__(self, data):
        self._d = data

    def len(self):
        return len(self._d)

    def __call__(self, off=None, ln=None):
        if off is None:
            return _TvbRange(self._d, 0, len(self._d))
        if ln is None:
            ln = len(self._d) - off
        return _TvbRange(self._d, off, ln)

    def bytes(self):
        return _ByteArray(self._d)


class _ProtoField:
    def __init__(self, abbr, label, kind, size, base, valuestring, mask):
        self.abbr, self.label, self.kind = abbr, label, kind
        self.size, self.base, self.valuestring, self.mask = size, base, valuestring, mask

    def _fmt(self, rng, override=None, le=False):
        if override is not None:
            return str(override)
        if self.kind == "none":
            return None
        if self.kind == "string":
            return '"%s"' % rng.string()
        if self.kind == "bytes":
            return bytes(rng.data[rng.off:rng.off + rng.ln]).hex()
        v = rng.le_uint() if le else rng.uint()
        if self.mask:
            shift = _TvbRange._mask_shift(rng, self.mask)
            v = (v & self.mask) >> shift
        if self.kind == "bool":
            return "True" if v & 1 else "False"
        if self.kind.startswith("int"):
            v = rng.le_int() if le else rng.int()
            if self.mask:
                v = (v & self.mask) >> shift
        s = ("0x%0*X" % (rng.ln * 2, v)) if self.base == "HEX" else str(v)
        if self.valuestring and v in self.valuestring:
            # 与真实 Wireshark 4.6 行为对齐：枚举显示为 "Name (value)"
            return "%s (%s)" % (self.valuestring[v], s)
        return s


def _pf_ctor(kind, size):
    def ctor(abbr, label, base="DEC", valuestring=None, mask=None, desc=None):
        return _ProtoField(abbr, label, kind, size, base, valuestring, mask)
    return staticmethod(ctor)


def _pf_bool(abbr, label, width=8, valuestring=None, mask=None, desc=None):
    return _ProtoField(abbr, label, "bool", 1, "DEC", valuestring, mask)


def _pf_none(abbr, label, display=None):
    return _ProtoField(abbr, label, "none", 0, None, None, None)


for _k, _sz in (("uint8", 1), ("uint16", 2), ("uint24", 3), ("uint32", 4),
                ("int8", 1), ("int16", 2), ("int32", 4),
                ("string", 0), ("bytes", 0)):
    setattr(_ProtoField, _k, _pf_ctor(_k, _sz))
_ProtoField.bool = staticmethod(_pf_bool)
_ProtoField.none = staticmethod(_pf_none)


class _Proto:
    def __init__(self, abbr, long_name):
        self.abbr, self.long_name = abbr, long_name
        self.heuristics: list[tuple[str, object]] = []

    def register_heuristic(self, table, fn):
        self.heuristics.append((table, fn))
        return fn


class _ProtoExpert:
    def __init__(self, abbr, label, group, severity):
        self.abbr, self.label = abbr, label
        self.tag = "Expert %s(%s)" % (severity, group)

    @staticmethod
    def new(abbr, label, group, severity):
        return _ProtoExpert(abbr, label, group, severity)


class _DissectorTable:
    bound: list = []

    @staticmethod
    def get(name):
        return _DissectorTable(name)

    def __init__(self, name):
        self.name = name

    def add(self, port, proto):
        _DissectorTable.bound.append((self.name, int(port), proto.abbr))


class _Cols:
    protocol = ""
    info = ""


class _PInfo:
    def __init__(self):
        self.cols = _Cols()


class _TreeItem:
    def __init__(self, label, value=None, off=0, ln=0, expert=False, expert_tag=""):
        self.label, self.value = label, value
        self.off, self.ln, self.expert, self.expert_tag = off, ln, expert, expert_tag
        self.children = []

    def add(self, a, b=None, c=None, le=False):
        if isinstance(a, _Proto):
            child = _TreeItem(a.long_name, off=getattr(b, "off", 0), ln=getattr(b, "ln", 0))
        elif isinstance(a, _TvbRange):
            child = _TreeItem(str(b), off=a.off, ln=a.ln)
        else:
            override = None
            if c is not None and not isinstance(c, (_TvbRange, _Tvb)):
                override = c
            child = _TreeItem(a.label, a._fmt(b, override, le), off=b.off, ln=b.ln)
        self.children.append(child)
        return child

    def add_le(self, a, b=None, c=None):
        return self.add(a, b, c, le=True)

    def add_proto_expert_info(self, pe, text=None):
        self.children.append(_TreeItem(
            "[%s] %s" % (pe.tag, pe.label), text, expert=True, expert_tag=pe.tag))

    def append_text(self, s):
        self.label = (self.label or "") + str(s)


class _NS:
    pass


def _make_globals():
    base_ns = _NS()
    base_ns.HEX, base_ns.DEC, base_ns.OCT = "HEX", "DEC", "OCT"
    expert_ns = _NS()
    expert_ns.group = _NS()
    expert_ns.severity = _NS()
    for n in ("CHECKSUM", "PROTOCOL", "MALFORMED"):
        setattr(expert_ns.group, n, n.title())
    for n in ("ERROR", "WARN", "NOTE"):
        setattr(expert_ns.severity, n, n.title())
    return {
        "Proto": _Proto, "ProtoField": _ProtoField, "ProtoExpert": _ProtoExpert,
        "DissectorTable": _DissectorTable, "base": base_ns, "expert": expert_ns,
    }


def _to_treenode(item: _TreeItem) -> TreeNode:
    return TreeNode(
        label=item.label, value=item.value, offset=item.off, length=item.ln,
        expert=item.expert, expert_tag=item.expert_tag,
        children=[_to_treenode(c) for c in item.children],
    )


def _flatten_experts(node: TreeNode, out: list):
    if node.expert:
        out.append("%s %s: %s" % (node.expert_tag, node.label, node.value or ""))
    for c in node.children:
        _flatten_experts(c, out)


class LuaEngine:
    """加载一次 Lua dissector，反复 dissect 多帧。"""

    def __init__(self):
        try:
            from lupa import lua54 as _lua
        except ImportError as e:  # pragma: no cover
            raise LuaError("需要 lupa 的 lua54 运行时：pip install lupa") from e
        self.lua = _lua.LuaRuntime(unpack_returned_tuples=True)
        self.g = self.lua.globals()
        for k, v in _make_globals().items():
            self.g[k] = v
        self.bindings: list[tuple[str, int, str]] = []

    def load(self, lua_code: str) -> None:
        _DissectorTable.bound = []
        code = lua_code.replace("local proto = Proto(", "proto = Proto(", 1)
        try:
            self.lua.execute(code)
        except Exception as e:  # lupa 抛 LuaError/Python 侧异常统一包装
            raise LuaError(str(e)) from e
        proto = self.g["proto"]
        if proto is None or not hasattr(proto, "dissector"):
            raise LuaError("脚本未定义 proto.dissector")
        self._proto = proto
        self.bindings = list(_DissectorTable.bound)

    def dissect(self, frame: bytes) -> DissectResult:
        tvb = _Tvb(list(frame))
        pinfo = _PInfo()
        root = _TreeItem("Frame (%d bytes)" % len(frame))
        try:
            rc = self._proto.dissector(tvb, pinfo, root)
        except Exception as e:
            return DissectResult(ok=False, error=str(e))
        res = DissectResult(
            ok=True, info=str(pinfo.cols.info), protocol=str(pinfo.cols.protocol),
            consumed=int(rc) if isinstance(rc, (int, float)) else 0,
            tree=_to_treenode(root),
        )
        experts: list[str] = []
        _flatten_experts(res.tree, experts)
        if experts:
            res.error = "\n".join(experts)  # 非致命：expert 提示汇总
        return res
