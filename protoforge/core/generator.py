# -*- coding: utf-8 -*-
"""Protocol 模型 → Wireshark Lua dissector 代码生成。

吸收 spike 阶段全部踩坑结论：
- ByteArray 字节访问用 get_index()（4.6 实测 get() 不存在）
- 数值字段不能以字符串作 value，追加说明用 append_text
- 块注释必须 --[[（无空格）；注释体内的 ]] 会被消毒
- 数组元素偏移由元素字段各自推进，循环尾不得重复加
- 仅 Lua 5.3+ 语法（原生位运算，对应 Wireshark 4.4+）
- 所有自由文本（label/long_name/enum 值）经 _lua() 转义后写入 Lua 字符串字面量
"""
from __future__ import annotations

import datetime

from .model import (
    Field, Protocol, ValidationError, is_bitfield, local_bit_groups,
    static_size, validate, walk,
)

PRIM_CTORS = {
    "uint8": ("uint8", 1, False), "uint16": ("uint16", 2, False),
    "uint24": ("uint24", 3, False), "uint32": ("uint32", 4, False),
    "int8": ("int8", 1, True), "int16": ("int16", 2, True), "int32": ("int32", 4, True),
}


def _lua(s) -> str:
    """转义为 Lua 字符串字面量内容（不含引号）。防注入/防语法破坏。"""
    out = []
    for ch in str(s):
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\%03d" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _comment(s) -> str:
    """块注释体消毒：防止 ]] 提前闭合注释；控制字符替换为空格。"""
    text = str(s).replace("]]", "] ]")
    return "".join(ch if ord(ch) >= 0x20 else " " for ch in text)


def generate_lua(p: Protocol) -> str:
    return Generator(p).generate()


class Generator:
    def __init__(self, p: Protocol):
        errs = validate(p)
        if errs:
            raise ValidationError("；".join(errs))
        self.p = p
        self.abbr = p.name
        self.L: list[str] = []
        self.i = 0
        self.captured: set[str] = set()
        self.frame_trailer = 0
        self._analyze()

    # ---------- 分析 ----------
    def _analyze(self):
        for f in walk(self.p.fields):
            if f.type == "switch":
                self.captured.add(f.on)
            elif f.type == "array" and f.count_from:
                self.captured.add(f.count_from)
            if f.length_from:
                self.captured.add(f.length_from)
        for f in walk(self.p.fields):
            if f.const is not None:
                self.captured.add(f.name)
        if self.p.length_check:
            self.captured.add(self.p.length_check["field"])
        # Info 列的 Seq：仅当存在【顶层且数值】的 seqNum（validate 已保证其余引用合法）
        for f in self.p.fields:
            if f.name == "seqNum" and f.type in ("uint8", "uint16", "uint24", "uint32"):
                self.captured.add("seqNum")
                break

    def _bo(self, f: Field) -> str:
        """字段有效字节序前缀：LE 返回 'le_'，BE 返回 ''。"""
        bo = f.byte_order or self.p.byte_order
        return "le_" if bo == "little" else ""

    def _split_frame(self):
        """顶层切分为 (固定头, 尾部)。切分点：首个 switch；无 switch 则末尾 crc 字段。"""
        fields = self.p.fields
        for i, f in enumerate(fields):
            if f.type == "switch":
                return fields[:i], fields[i:]
        if fields and fields[-1].crc16:
            return fields[:-1], fields[-1:]
        return fields, []

    # ---------- 基础 ----------
    def w(self, s: str = ""):
        self.L.append("    " * self.i + s if s else "")

    def _base(self, f: Field) -> str:
        return "base.HEX" if f.display == "hex" else "base.DEC"

    # ---------- 段落 ----------
    def generate(self) -> str:
        self._header()
        self._enums()
        self._field_decls()
        self._experts()
        self._crc_helper()
        self._dissector()
        self._registration()
        return "\n".join(self.L) + "\n"

    def _header(self):
        from protoforge import __version__
        self.w("--[[")
        self.w(f"    {self.abbr.upper()} - {_comment(self.p.long_name)} dissector")
        self.w(f"    由 ProtoForge v{__version__} 生成于 {datetime.date.today().isoformat()}")
        self.w("    目标：Wireshark 4.4+（Lua 5.3/5.4）")
        self.w("    授权：使用 Wireshark Lua 绑定的脚本须按 GPLv2+ 分发")
        self.w("    （官方 wiki「Beware the GPL」口径）；可自由使用与修改。")
        self.w("--]]")
        self.w()
        self.w(f'local proto = Proto("{_lua(self.abbr)}", "{_lua(self.p.long_name)}")')
        self.w()

    def _enums(self):
        seen = set()
        for f in walk(self.p.fields):
            if f.enum and f.name not in seen:
                seen.add(f.name)
                self.w(f"local vs_{f.name} = {{")
                self.i += 1
                for k, v in f.enum.items():
                    self.w(f'[{k}] = "{_lua(v)}",')
                self.i -= 1
                self.w("}")
        if seen:
            self.w()

    def _field_decls(self):
        self._annotate(self.p.fields)
        uniq: dict[str, Field] = {}
        for f in walk(self.p.fields):
            uniq.setdefault(f.name, f)
        for f in uniq.values():
            self._decl(f)
        self.w()
        self.w("proto.fields = {")
        self.i += 1
        for nm in uniq:
            self.w(f"pf_{nm},")
        self.i -= 1
        self.w("}")
        self.w()

    def _decl(self, f: Field):
        ab, lb = f"{self.abbr}.{f.name}", _lua(f.label or f.name)
        if f.type in PRIM_CTORS:
            ctor = PRIM_CTORS[f.type][0]
            vs = f"vs_{f.name}" if f.enum else "nil"
            self.w(f'local pf_{f.name} = ProtoField.{ctor}("{ab}", "{lb}", {self._base(f)}, {vs})')
        elif is_bitfield(f):
            if f.width == 1:
                self.w(f'local pf_{f.name} = ProtoField.bool("{ab}", "{lb}", 8, nil, 0x{f._mask:02X})')
            else:
                vs = f"vs_{f.name}" if f.enum else "nil"
                self.w(f'local pf_{f.name} = ProtoField.uint{f._bits}("{ab}", "{lb}", {self._base(f)}, {vs}, 0x{f._mask:02X})')
        elif f.type == "string":
            self.w(f'local pf_{f.name} = ProtoField.string("{ab}", "{lb}")')
        elif f.type == "bytes":
            self.w(f'local pf_{f.name} = ProtoField.bytes("{ab}", "{lb}")')
        elif f.type in ("switch", "array"):
            self.w(f'local pf_{f.name} = ProtoField.none("{ab}", "{lb}")')

    def _annotate(self, fields: list):
        for grp in local_bit_groups(fields):
            bits = sum(m.width for m in grp)
            pos = 0
            for m in grp:
                m._bitoff = pos
                m._mask = ((1 << m.width) - 1) << (bits - pos - m.width)
                m._bits = bits
                m._last = m is grp[-1]
                pos += m.width
        for f in fields:
            if f.type == "switch":
                for case in f.cases.values():
                    self._annotate(case)
            elif f.type == "array" and f.element:
                self._annotate(f.element)

    def _experts(self):
        a = self.abbr
        self.w(f'local pe_crc_bad    = ProtoExpert.new("{a}.crc.bad",    "CRC-16 mismatch",   expert.group.CHECKSUM, expert.severity.ERROR)')
        self.w(f'local pe_const_bad  = ProtoExpert.new("{a}.const.bad", "Constant mismatch", expert.group.PROTOCOL, expert.severity.WARN)')
        self.w(f'local pe_len_bad    = ProtoExpert.new("{a}.len.bad",   "Length mismatch",   expert.group.MALFORMED, expert.severity.WARN)')
        self.w(f'local pe_too_short  = ProtoExpert.new("{a}.short",     "Packet too short",  expert.group.MALFORMED, expert.severity.ERROR)')
        self.w("proto.experts = { pe_crc_bad, pe_const_bad, pe_len_bad, pe_too_short }")
        self.w()

    def _crc_helper(self):
        algos = {f.crc16 for f in walk(self.p.fields) if f.crc16}
        if not algos:
            return
        if "ccitt_false" in algos:
            self.w("-- CRC-16/CCITT-FALSE（poly 0x1021, init 0xFFFF）")
            self.w("local function crc16_ccitt(bytes, from, to)")
            self._emit_crc_body(init="0xFFFF", msb=True)
        if "xmodem" in algos:
            self.w("-- CRC-16/XMODEM（poly 0x1021, init 0x0000）")
            self.w("local function crc16_xmodem(bytes, from, to)")
            self._emit_crc_body(init="0x0000", msb=True)
        if "modbus" in algos:
            self.w("-- CRC-16/MODBUS（reflected, poly 0xA001, init 0xFFFF，传输低字节在前）")
            self.w("local function crc16_modbus(bytes, from, to)")
            self._emit_crc_body(init="0xFFFF", msb=False)
        if "sum8" in algos:
            self.w("-- 8 位累加和")
            self.w("local function checksum_sum8(bytes, from, to)")
            self.i += 1
            self.w("local s = 0")
            self.w("for i = from, to do s = (s + bytes:get_index(i)) & 0xFF end")
            self.w("return s")
            self.i -= 1
            self.w("end")
            self.w()
        if "sum16" in algos:
            self.w("-- 16 位累加和")
            self.w("local function checksum_sum16(bytes, from, to)")
            self.i += 1
            self.w("local s = 0")
            self.w("for i = from, to do s = (s + bytes:get_index(i)) & 0xFFFF end")
            self.w("return s")
            self.i -= 1
            self.w("end")
            self.w()

    def _emit_crc_body(self, init: str, msb: bool):
        """发射 CRC16 函数体（已发出函数签名行）。msb=True 为逐位左移式，False 为反射式。"""
        self.i += 1
        self.w(f"local crc = {init}")
        self.w("for i = from, to do")
        self.i += 1
        if msb:
            self.w("crc = (crc ~ (bytes:get_index(i) << 8)) & 0xFFFF")
            self.w("for _ = 1, 8 do")
            self.i += 1
            self.w("if (crc & 0x8000) ~= 0 then")
            self.i += 1
            self.w("crc = ((crc << 1) ~ 0x1021) & 0xFFFF")
            self.i -= 1
            self.w("else")
            self.i += 1
            self.w("crc = (crc << 1) & 0xFFFF")
            self.i -= 1
            self.w("end")
            self.i -= 1
            self.w("end")
        else:
            self.w("crc = (crc ~ bytes:get_index(i)) & 0xFFFF")
            self.w("for _ = 1, 8 do")
            self.i += 1
            self.w("if (crc & 1) ~= 0 then")
            self.i += 1
            self.w("crc = (crc >> 1) ~ 0xA001")
            self.i -= 1
            self.w("else")
            self.i += 1
            self.w("crc = crc >> 1")
            self.i -= 1
            self.w("end")
            self.i -= 1
            self.w("end")
        self.i -= 1
        self.w("end")
        self.w("return crc")
        self.i -= 1
        self.w("end")
        self.w()

    # ---------- dissect 主体 ----------
    def _emit_read(self, f: Field, size: int, signed: bool) -> str:
        if is_bitfield(f):
            return f"buffer(off, {f._bits // 8}):bitfield({f._bitoff}, {f.width})"
        le = self._bo(f)
        return f"buffer(off, {size}):{le}{'int()' if signed else 'uint()'}"

    def _emit_fields(self, fields: list, parent: str):
        for f in fields:
            nm = f.name
            if is_bitfield(f):
                nbytes = f._bits // 8
                if nm in self.captured:
                    self.w(f"local v_{nm} = buffer(off, {nbytes}):bitfield({f._bitoff}, {f.width})")
                self.w(f"{parent}:add(pf_{nm}, buffer(off, {nbytes}))")
                if f._last:
                    self.w(f"off = off + {nbytes}")
            elif f.type in PRIM_CTORS:
                _, size, signed = PRIM_CTORS[f.type]
                le = self._bo(f) == "le_"
                add_fn = "add_le" if le else "add"
                if nm in self.captured:
                    self.w(f"local v_{nm} = {self._emit_read(f, size, signed)}")
                self.w(f"{parent}:{add_fn}(pf_{nm}, buffer(off, {size}))")
                if f.const is not None:
                    cv = int(f.const, 0)
                    self.w(f"if v_{nm} ~= {hex(cv)} then")
                    self.i += 1
                    self.w(f'{parent}:add_proto_expert_info(pe_const_bad, string.format("expected {hex(cv)}, got 0x%04X", v_{nm}))')
                    self.i -= 1
                    self.w("end")
                self.w(f"off = off + {size}")
            elif f.type in ("string", "bytes"):
                if f.terminated_by is not None:
                    n = f"n_{nm}"
                    tb = int(f.terminated_by)
                    self.w(f"local {n} = 0")
                    self.w(f"while off + {n} < len and buffer(off + {n}, 1):uint() ~= {tb} do")
                    self.i += 1
                    self.w(f"{n} = {n} + 1")
                    self.i -= 1
                    self.w("end")
                    self.w(f"local it_{nm} = {parent}:add(pf_{nm}, buffer(off, {n}))")
                    self.w(f"if off + {n} < len then")
                    self.i += 1
                    self.w(f"{n} = {n} + 1")          # 跳过终止符
                    self.i -= 1
                    self.w("else")
                    self.i += 1
                    self.w(f'it_{nm}:append_text(" (unterminated)")')
                    self.i -= 1
                    self.w("end")
                    self.w(f"off = off + {n}")
                elif f.length_from:
                    n = f"n_{nm}"
                    self.w(f"local {n} = v_{f.length_from}")
                    self.w(f"if off + {n} > len then")
                    self.i += 1
                    self.w(f'{parent}:add_proto_expert_info(pe_len_bad, string.format("{nm} 长度 %d 超出剩余字节", {n}))')
                    self.w(f"{n} = len - off")
                    self.i -= 1
                    self.w("end")
                    self.w(f"{parent}:add(pf_{nm}, buffer(off, {n}))")
                    self.w(f"off = off + {n}")
                else:
                    self.w(f"{parent}:add(pf_{nm}, buffer(off, {f.size}))")
                    self.w(f"off = off + {f.size}")
            elif f.type == "switch":
                self._emit_switch(f, parent)
            elif f.type == "array":
                self._emit_array(f, parent)

    def _emit_switch(self, f: Field, parent: str):
        nm, on = f.name, f.on
        tr = self.frame_trailer
        self.w(f"local st_{nm} = {parent}:add(pf_{nm}, buffer(off, math.max(0, len - off - {tr})))")
        first = True
        for key, case_fields in f.cases.items():
            kw = "if" if first else "elseif"
            first = False
            self.w(f"{kw} v_{on} == {int(key)} then")
            self.i += 1
            self._emit_fields(case_fields, f"st_{nm}")
            self.i -= 1
        self.w("else")
        self.i += 1
        self.w(f'st_{nm}:append_text(string.format(" (unknown {on} %d)", v_{on}))')
        self.i -= 1
        self.w("end")

    def _emit_array(self, f: Field, parent: str):
        nm = f.name
        esize = static_size(f.element)
        label = _lua(f.label or "Element")
        if f.length_from:
            rgn = f"rgn_{nm}"
            self.w(f"local {rgn} = v_{f.length_from}")
            self.w(f"if off + {rgn} > len then")
            self.i += 1
            self.w(f'{parent}:add_proto_expert_info(pe_len_bad, string.format("{nm} 区域 %d 超出剩余字节", {rgn}))')
            self.w(f"{rgn} = len - off")
            self.i -= 1
            self.w("end")
            cnt = f"math.floor({rgn} / {esize})"
        elif f.count_from:
            cnt = f"v_{f.count_from}"
        else:
            cnt = str(f.count)
        self.w(f"for i = 1, {cnt} do")
        self.i += 1
        self.w(f'local st_{nm} = {parent}:add(buffer(off, {esize}), "{label} [" .. (i - 1) .. "]")')
        self._emit_fields(f.element, f"st_{nm}")
        self.i -= 1
        self.w("end")

    def _emit_crc(self, f: Field):
        nm = f.name
        algo = f.crc16
        csize = 1 if algo == "sum8" else 2
        le = "le_" if algo == "modbus" else ""
        self.w(f"local v_{nm} = buffer(off, {csize}):{le}uint()")
        fn = {"ccitt_false": "crc16_ccitt", "xmodem": "crc16_xmodem", "modbus": "crc16_modbus",
              "sum8": "checksum_sum8", "sum16": "checksum_sum16"}[algo]
        self.w(f"local c_{nm} = {fn}(buffer:bytes(), 0, off - 1)")
        self.w(f"local it_{nm} = st:add(pf_{nm}, buffer(off, {csize}))")
        self.w(f"if c_{nm} == v_{nm} then")
        self.i += 1
        self.w(f'it_{nm}:append_text(" [correct]")')
        self.i -= 1
        self.w("else")
        self.i += 1
        self.w(f'it_{nm}:append_text(string.format(" [incorrect, expected 0x%04X]", c_{nm}))')
        self.w(f'st:add_proto_expert_info(pe_crc_bad, string.format("got 0x%04X, computed 0x%04X", v_{nm}, c_{nm}))')
        self.i -= 1
        self.w("end")
        self.w(f"off = off + {csize}")

    def _dissector(self):
        fields = self.p.fields
        header_fields, rest = self._split_frame()   # rest 以 switch 开头，或只含尾部 crc，或空
        top_switch = rest[0] if rest and rest[0].type == "switch" else None
        trailer_fields = rest[1:] if top_switch else rest
        header = static_size(header_fields)
        trailer = static_size(trailer_fields) if trailer_fields else 0
        self.frame_trailer = trailer
        min_len = header + trailer

        self.w("function proto.dissector(buffer, pinfo, tree)")
        self.i += 1
        self.w("local len = buffer:len()")
        self.w(f"if len < {min_len} then")
        self.i += 1
        self.w(f'tree:add_proto_expert_info(pe_too_short, string.format("packet too short: %d bytes (need >= {min_len})", len))')
        self.w("return 0")
        self.i -= 1
        self.w("end")
        self.w(f'pinfo.cols.protocol = "{_lua(self.abbr.upper())}"')
        self.w("local st = tree:add(proto, buffer())")
        self.w("local off = 0")
        self._emit_fields(header_fields, "st")
        # Info 列（seqNum 已在 _analyze 中确认顶层数值类型）
        parts = []
        if top_switch and top_switch.on:
            on = top_switch.on
            if any(f.name == on and f.enum for f in walk(fields)):
                parts.append(f'string.format("%s", vs_{on}[v_{on}] or string.format("Unknown(%d)", v_{on}))')
        if "seqNum" in self.captured:
            parts.append('string.format("Seq=%d", v_seqNum)')
        if parts:
            self.w('pinfo.cols.info = table.concat({' + ", ".join(parts) + '}, ", ")')
        # payloadLen 语义检查（validate 已保证 length_check.field 为顶层数值字段）
        if self.p.length_check:
            lf = self.p.length_check["field"]
            self.w(f"if v_{lf} ~= len - {header} - {trailer} then")
            self.i += 1
            self.w(f'st:add_proto_expert_info(pe_len_bad, string.format("{lf}=%d, 但按帧长 %d 应为 %d", v_{lf}, len, len - {header} - {trailer}))')
            self.i -= 1
            self.w("end")
        if top_switch:
            self._emit_switch(top_switch, "st")
        for f in trailer_fields:
            if f.crc16:
                self._emit_crc(f)
            else:  # validate 保证不会走到这里，防御性保留
                self._emit_fields([f], "st")
        self.w("if off ~= len then")
        self.i += 1
        self.w('st:add_proto_expert_info(pe_len_bad, string.format("%d trailing bytes", len - off))')
        self.i -= 1
        self.w("end")
        self.w("return len")
        self.i -= 1
        self.w("end")
        self.w()

    def _registration(self):
        for b in self.p.bindings:
            var = "tbl_" + b.table.replace(".", "_")
            self.w(f'local {var} = DissectorTable.get("{b.table}")')
            for port in b.ports:
                self.w(f"{var}:add({port}, proto)")
        if self.p.bindings:
            self.w()
