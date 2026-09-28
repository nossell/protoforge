# -*- coding: utf-8 -*-
"""协议数据模型与校验（纯逻辑，无 GUI 依赖）。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Iterator, Optional

PRIM_SIZES = {
    "uint8": 1, "uint16": 2, "uint24": 3, "uint32": 4,
    "int8": 1, "int16": 2, "int32": 4,
}
NUMERIC_TYPES = set(PRIM_SIZES) | {"uint"}   # 可作为引用依据（switch.on / count_from / 长度字段）
VALID_TYPES = set(PRIM_SIZES) | {"uint", "string", "bytes", "switch", "array"}
VALID_DISPLAYS = {"dec", "hex"}
VALID_TABLES = {"udp.port", "tcp.port"}
VALID_BYTE_ORDERS = {"big", "little"}
# 校验和算法 → 必需的字段类型
CHECKSUM_TYPES = {
    "ccitt_false": "uint16", "modbus": "uint16", "xmodem": "uint16",
    "sum16": "uint16", "sum8": "uint8",
}
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ValidationError(ValueError):
    """协议定义不合法。"""


@dataclass
class Field:
    name: str
    label: str = ""
    type: str = "uint8"
    width: int = 0                 # bitfield：1-7 bit
    display: str = "dec"           # dec | hex
    enum: Optional[dict] = None    # {int: str}
    const: Optional[str] = None    # 幻数，如 "0x5A5A"
    size: int = 0                  # string/bytes 定长
    on: Optional[str] = None       # switch：判断依据字段名
    cases: dict = dc_field(default_factory=dict)      # {int: [Field]}
    count: Optional[int] = None    # array：固定次数
    count_from: Optional[str] = None                  # array：次数来源字段名
    element: Optional[list] = None                    # array：元素字段列表
    crc16: Optional[str] = None    # 校验和算法：ccitt_false/modbus/xmodem/sum8/sum16
    byte_order: Optional[str] = None                  # 覆盖协议默认字节序（数值字段）
    length_from: Optional[str] = None                 # string/bytes/array：区域长度来源字段名
    terminated_by: Optional[int] = None               # string：终止符字节（如 0x00）
    default: Optional[list] = None                    # switch：未命中任何 case 时的字段列表


@dataclass
class Binding:
    table: str = "udp.port"
    ports: list = dc_field(default_factory=list)


@dataclass
class Protocol:
    name: str = "myproto"
    long_name: str = ""
    desc: str = ""
    bindings: list = dc_field(default_factory=list)
    fields: list = dc_field(default_factory=list)
    length_check: Optional[dict] = None   # {"field": name, "region": "payload"}
    byte_order: str = "big"               # 协议默认字节序：big | little
    heuristic: Optional[str] = None       # 启发式注册表："udp" | "tcp"（启用时首字段必须带 const）
    desegment: bool = False               # TCP 解段：按 length_check 请求 Wireshark 重组（v1.1）


def is_bitfield(f: Field) -> bool:
    return f.type == "uint" and 1 <= f.width < 8


def is_numeric(f: Field) -> bool:
    return f.type in PRIM_SIZES or is_bitfield(f)


def field_size(f: Field) -> Optional[int]:
    """固定尺寸字段的字节数；可变结构（switch/array）与未定长返回 None。"""
    if is_bitfield(f):
        return None
    if f.type in PRIM_SIZES:
        return PRIM_SIZES[f.type]
    if f.type in ("string", "bytes"):
        return f.size if f.size >= 1 else None
    return None


def walk(fields: list) -> Iterator[Field]:
    """深度优先遍历全部字段（含 switch case、default 与 array element 内部）。"""
    for f in fields:
        yield f
        if f.type == "switch":
            for case in f.cases.values():
                yield from walk(case)
            if f.default:
                yield from walk(f.default)
        elif f.type == "array" and f.element:
            yield from walk(f.element)


def _scan_bit_groups(fields: list, errors: list, where: str) -> list:
    """收集连续 bitfield 打包组并校验字节边界；返回组列表。"""
    groups, grp = [], []
    for f in fields:
        if is_bitfield(f):
            grp.append(f)
        else:
            bits = sum(x.width for x in grp)
            if bits not in (0, 8, 16, 24, 32):
                errors.append(f"{where}: bitfield 组 '{grp[0].name}…' 共 {bits} bit，不成字节边界")
            if grp:
                groups.append(grp)
            grp = []
            if f.type == "switch":
                for key, case in f.cases.items():
                    groups.extend(_scan_bit_groups(case, errors, f"{where}/case {key}"))
                if f.default:
                    groups.extend(_scan_bit_groups(f.default, errors, f"{where}/default"))
            elif f.type == "array" and f.element:
                groups.extend(_scan_bit_groups(f.element, errors, f"{where}/{f.name} 元素"))
    bits = sum(x.width for x in grp)
    if bits not in (0, 8, 16, 24, 32):
        errors.append(f"{where}: bitfield 组 '{grp[0].name}…' 共 {bits} bit，不成字节边界")
    if grp:
        groups.append(grp)
    return groups


def is_top_boundary(f: "Field") -> bool:
    """顶层运行时边界：switch，或 count/count_from 计数的数组（裸 TLV 链）。
    边界之后仅允许 crc16 收尾。model.validate / generator._split_frame 共用。"""
    return f.type == "switch" or (f.type == "array"
                                  and (f.count is not None or f.count_from is not None))


def is_fixed_layout(fields: list) -> bool:
    """列表是否全为定长字段（用于数组元素容器范围的静态计算）。
    注意与 static_size 的区别：static_size 对变长字段按 0 贡献"宽容"计算最小长度，
    不能用于判定定长——含 length_from/terminated_by 的元素必须走运行时 set_len 路径。"""
    for f in fields:
        if is_bitfield(f):
            continue                     # 位域按组计入，视为定长
        if f.type == "switch":
            return False
        if f.type == "array":
            if f.count is None:          # count_from/length_from 数组依赖运行时值
                return False
            if not is_fixed_layout(f.element or []):
                return False
            continue
        if f.type in ("string", "bytes") and (f.length_from or f.terminated_by is not None):
            return False
    return True


def bitfield_groups(fields: list) -> list:
    """连续 bitfield 的打包组（含 switch/array 内部，递归）。"""
    return _scan_bit_groups(fields, [], "")


def local_bit_groups(fields: list) -> list:
    """仅当前层级的连续 bitfield 打包组（不递归）；供生成器逐层发射。"""
    groups, grp = [], []
    for f in fields:
        if is_bitfield(f):
            grp.append(f)
        elif grp:
            groups.append(grp)
            grp = []
    if grp:
        groups.append(grp)
    return groups


def static_size(fields: list) -> int:
    """固定布局总字节数；含可变结构或位域不成界时抛 ValidationError。"""
    errs = []
    _scan_bit_groups(fields, errs, "")
    for e in errs:
        raise ValidationError(e)
    total = 0
    for f in fields:
        if is_bitfield(f):
            continue  # 打包组字节数在下方统一计入
        if f.type == "switch":
            raise ValidationError(f"静态布局中出现可变结构: {f.name}")
        if f.type == "array" and not f.length_from:
            raise ValidationError(f"静态布局中出现可变结构: {f.name}")
        if f.type == "array" and f.length_from:
            continue  # 变长区域按最小 0 贡献计入
        if f.type in ("string", "bytes") and (f.length_from or f.terminated_by is not None):
            continue  # 变长字段按最小 0 贡献计入
        s = field_size(f)
        if s is None:
            raise ValidationError(f"字段 {f.type} '{f.name}' 缺少定长 size")
        total += s
    for g in bitfield_groups(fields):
        total += sum(x.width for x in g) // 8
    return total


def validate(p: Protocol) -> list:
    """全量校验；返回错误信息列表（空 = 合法）。规则与生成器契约严格一致。"""
    errors: list[str] = []

    def check_common(f: Field, where: str):
        if not NAME_RE.match(f.name or ""):
            errors.append(f"{where}: 非法字段名 '{f.name}'（需 [A-Za-z_][A-Za-z0-9_]*）")
        if f.type not in VALID_TYPES:
            errors.append(f"{where}/{f.name}: 未知类型 '{f.type}'")
            return
        if f.type == "uint" and not (1 <= f.width < 8):
            errors.append(f"{where}/{f.name}: bitfield 需 width 1-7")
        if f.type in ("string", "bytes") and f.size < 1 and f.length_from is None \
                and f.terminated_by is None:
            errors.append(f"{where}/{f.name}: {f.type} 需要定长 size / length_from / terminated_by 之一")
        if f.display not in VALID_DISPLAYS:
            errors.append(f"{where}/{f.name}: display 只能是 dec/hex")
        if f.enum is not None:
            for k, v in f.enum.items():
                if not isinstance(k, int):
                    errors.append(f"{where}/{f.name}: enum 键必须是整数")
                    break
        if f.const is not None:
            try:
                cv = int(f.const, 0)
            except (TypeError, ValueError):
                errors.append(f"{where}/{f.name}: const '{f.const}' 不是合法整数")
            else:
                if not is_numeric(f):
                    errors.append(f"{where}/{f.name}: const 仅支持数值/位域字段")
                elif cv < 0:
                    errors.append(f"{where}/{f.name}: const 不能为负数（无符号字段）")
        if f.byte_order is not None:
            if f.byte_order not in VALID_BYTE_ORDERS:
                errors.append(f"{where}/{f.name}: byte_order 只能是 big/little")
            elif is_bitfield(f):
                errors.append(f"{where}/{f.name}: byte_order 仅支持数值字段（位域不适用）")
            elif f.type not in PRIM_SIZES:
                errors.append(f"{where}/{f.name}: byte_order 仅支持数值字段（位域/字符串等不适用）")
        if f.type in ("string", "bytes") and f.length_from is not None and f.size >= 1:
            errors.append(f"{where}/{f.name}: size 与 length_from 只能二选一")
        if f.type == "uint" and f.length_from is not None:
            errors.append(f"{where}/{f.name}: length_from 不适用于位域")
        if f.terminated_by is not None:
            if f.type != "string":
                errors.append(f"{where}/{f.name}: terminated_by 仅支持 string 字段")
            elif isinstance(f.terminated_by, bool) or not isinstance(f.terminated_by, int) \
                    or not (0 <= f.terminated_by <= 255):
                errors.append(f"{where}/{f.name}: terminated_by 必须是 0-255 的整数")
        if f.type == "string" and f.terminated_by is not None \
                and (f.size >= 1 or f.length_from is not None):
            errors.append(f"{where}/{f.name}: string 的 size / length_from / terminated_by 只能三选一")

    def check_list(fields: list, where: str, visible: dict, top_level: bool):
        """visible: 进入本列表时可见的字段名→Field（外层作用域继承）。
        switch 之后不得再有字段（顶层例外：仅允许 crc16 收尾，见顶层检查）。"""
        seen_switch = None
        for idx, f in enumerate(fields):
            check_common(f, where)
            if seen_switch is not None and not f.crc16:
                errors.append(f"{where}: switch '{seen_switch.name}' 之后不允许再出现字段 '{f.name}'"
                              f"（switch 长度运行时可变，后续字段无法定位；请把 switch 放到列表末尾）")
            if f.type == "switch":
                seen_switch = f
                if not f.on:
                    errors.append(f"{where}/{f.name}: switch 缺少 on")
                if not f.cases and not f.default:
                    errors.append(f"{where}/{f.name}: switch 至少需要一个 case 或 default")
                ref = visible.get(f.on or "")
                if f.on and ref is None:
                    errors.append(f"{where}/{f.name}: on 字段 '{f.on}' 未在其之前声明（或在不可见作用域）")
                elif ref is not None and not is_numeric(ref):
                    errors.append(f"{where}/{f.name}: on 字段 '{f.on}' 必须是数值/位域类型")
                for key, case in f.cases.items():
                    if not isinstance(key, int):
                        errors.append(f"{where}/{f.name}: case 键必须是整数")
                    check_list(case, f"{where}/{f.name}/case {key}", dict(visible), False)
                if f.default is not None:
                    check_list(f.default, f"{where}/{f.name}/default", dict(visible), False)
            elif f.type == "array":
                sizing = sum(x is not None for x in (f.count, f.count_from, f.length_from))
                if sizing == 0:
                    errors.append(f"{where}/{f.name}: array 需要 count / count_from / length_from 之一")
                elif sizing > 1:
                    errors.append(f"{where}/{f.name}: count / count_from / length_from 只能三选一")
                if f.count is not None:
                    if isinstance(f.count, bool) or not isinstance(f.count, int):
                        errors.append(f"{where}/{f.name}: count 必须是整数（当前 {f.count!r}）")
                    elif not (0 <= f.count <= 65535):
                        errors.append(f"{where}/{f.name}: count 超出范围 0-65535")
                if f.count_from:
                    ref = visible.get(f.count_from)
                    if ref is None:
                        errors.append(f"{where}/{f.name}: count_from 字段 '{f.count_from}' 未在其之前声明（或在不可见作用域）")
                    elif not is_numeric(ref):
                        errors.append(f"{where}/{f.name}: count_from 字段 '{f.count_from}' 必须是数值/位域类型")
                if f.length_from:
                    ref = visible.get(f.length_from)
                    if ref is None:
                        errors.append(f"{where}/{f.name}: length_from 字段 '{f.length_from}' 未在其之前声明（或在不可见作用域）")
                    elif not is_numeric(ref):
                        errors.append(f"{where}/{f.name}: length_from 字段 '{f.length_from}' 必须是数值/位域类型")
                if not f.element:
                    errors.append(f"{where}/{f.name}: array 缺少 element 字段列表")
                else:
                    # v1.1：元素内允许变长字段与 switch/array（TLV 等真实协议形态），
                    # 元素局部作用域与外层一致地递归校验
                    check_list(f.element, f"{where}/{f.name} 元素", dict(visible), False)
                    # length_from 按「区域字节数 ÷ 元素尺寸」计数：元素必须全定长且尺寸 > 0，
                    # 否则生成 math.floor(rgn / 0)（Lua 得 inf，循环失控）。
                    # count/count_from 数组无此限制（逐字段推进偏移，天然支持 TLV）。
                    if f.length_from:
                        var = next((e for e in walk(f.element)
                                    if e.length_from or e.terminated_by is not None
                                    or e.type in ("switch", "array")), None)
                        if var is not None:
                            errors.append(f"{where}/{f.name}: length_from 数组的元素必须全为定长字段"
                                          f"（'{var.name}' 是变长/嵌套结构，无法按字节区域计数）"
                                          f"（TLV 形态请改用 count_from/count 计数）")
                        else:
                            try:
                                esz = static_size(f.element)
                            except ValidationError:
                                esz = 0
                            if esz <= 0:
                                errors.append(f"{where}/{f.name}: length_from 数组的元素尺寸为 0，"
                                              f"无法按字节区域计数")
            else:
                if f.crc16 and not top_level:
                    errors.append(f"{where}/{f.name}: crc16 字段只能位于顶层末尾")
                if f.type in ("string", "bytes") and f.length_from:
                    ref = visible.get(f.length_from)
                    if ref is None:
                        errors.append(f"{where}/{f.name}: length_from 字段 '{f.length_from}' 未在其之前声明（或在不可见作用域）")
                    elif not is_numeric(ref):
                        errors.append(f"{where}/{f.name}: length_from 字段 '{f.length_from}' 必须是数值/位域类型")
            visible[f.name] = f

    # ---- 顶层 ----
    if not NAME_RE.match(p.name or ""):
        errors.append(f"协议名 '{p.name}' 不合法")
    elif len(p.name) < 2:
        errors.append(f"协议名 '{p.name}' 过短：Wireshark 要求过滤名至少 2 个字符")
    if not p.bindings:
        errors.append("缺少绑定（bindings）：至少一个 udp.port / tcp.port")
    if p.byte_order not in VALID_BYTE_ORDERS:
        errors.append(f"协议字节序 '{p.byte_order}' 不合法（big/little）")
    if p.heuristic:
        if p.heuristic not in ("udp", "tcp"):
            errors.append(f"heuristic 只能是 udp/tcp（当前 '{p.heuristic}'）")
        else:
            first = p.fields[0] if p.fields else None
            if first is None or first.const is None or not is_numeric(first):
                errors.append("启用 heuristic 时，第一个字段必须是带 const 的数值字段"
                              "（作为启发式快速判别依据）")
            table = "udp.port" if p.heuristic == "udp" else "tcp.port"
            if not any(b.table == table for b in p.bindings):
                errors.append(f"heuristic('{p.heuristic}') 要求同时存在对应的 {table} 端口绑定")
    for b in p.bindings:
        if b.table not in VALID_TABLES:
            errors.append(f"绑定表 '{b.table}' 不受支持（仅 udp.port/tcp.port）")
        for port in b.ports:
            if not (1 <= int(port) <= 65535):
                errors.append(f"端口 {port} 超范围 1-65535")

    check_list(p.fields, "顶层", {}, True)

    # 顶层结构约束（与 generator._split_frame 契约一致）
    top_switches = [f for f in p.fields if f.type == "switch"]
    if len(top_switches) > 1:
        errors.append("顶层最多允许一个 switch（多分支请用同一 switch 的多个 case 表达）")
    # 运行时边界 = 首个 switch 或 count/count_from 数组（裸 TLV 链形态）；
    # 边界之后仅允许 crc16 收尾（长度运行时可变，后续字段无法定位）
    boundary_idx = None
    for i, f in enumerate(p.fields):
        if is_top_boundary(f):
            boundary_idx = i
            break
    if boundary_idx is not None:
        bf = p.fields[boundary_idx]
        kind = "switch" if bf.type == "switch" else "count/count_from 数组"
        for f in p.fields[boundary_idx + 1:]:
            if not f.crc16:
                errors.append(f"顶层{kind} '{bf.name}' 之后的字段 '{f.name}' 不受支持"
                              f"（运行时可变结构后仅允许 crc16 收尾）")

    # 重名（全树唯一）
    seen = {}
    for f in walk(p.fields):
        if f.name in seen:
            errors.append(f"字段名重复: {f.name}")
        seen[f.name] = f

    # 位域边界
    _scan_bit_groups(p.fields, errors, "顶层")

    # crc 约定：必须是最后一个顶层字段且类型与算法匹配
    crcs = [f for f in p.fields if f.crc16]
    if crcs:
        last = p.fields[-1] if p.fields else None
        if last is None or not last.crc16:
            errors.append("crc16 字段必须是最后一个顶层字段")
        for f in crcs:
            required = CHECKSUM_TYPES.get(f.crc16 or "")
            if required is None:
                errors.append(f"不支持的校验和算法 '{f.crc16}'"
                              f"（可选：{'/'.join(sorted(CHECKSUM_TYPES))}）")
            elif f.type != required:
                errors.append(f"校验和 '{f.crc16}' 要求字段类型 {required}（当前 {f.type}）")

    # length_check 引用：必须是顶层数值字段
    if p.length_check:
        lf = p.length_check.get("field")
        if lf:
            ref = next((f for f in p.fields if f.name == lf), None)
            if ref is None:
                errors.append(f"length_check.field '{lf}' 不存在（须为顶层字段）")
            elif not is_numeric(ref):
                errors.append(f"length_check.field '{lf}' 必须是数值字段")

    # TCP 解段（v1.1）：需要 tcp 绑定 + length_check，且长度字段前布局可静态定位
    if p.desegment:
        if not any(b.table == "tcp.port" for b in p.bindings):
            errors.append("meta.desegment = true 需要至少一个 tcp.port 绑定（UDP 帧天然完整无需重组）")
        if not p.length_check:
            errors.append("meta.desegment = true 需要 meta.length_check（重组目标长度依据长度字段计算）")
        else:
            lf = p.length_check.get("field")
            consumed = 0
            for f in p.fields:
                if f.name == lf:
                    if not is_numeric(f) or is_bitfield(f):
                        errors.append(f"meta.desegment 的长度字段 '{lf}' 必须是非位域数值字段")
                    break
                if field_size(f) is None:
                    errors.append(f"meta.desegment 的长度字段 '{lf}' 之前存在无法静态定位的字段"
                                  f" '{f.name}'（解段前导需要按固定偏移读取长度）")
                    break
                consumed += field_size(f) or 0
            else:
                errors.append(f"meta.desegment 的长度字段 '{lf}' 不存在")

    return errors


def validate_or_raise(p: Protocol) -> None:
    errs = validate(p)
    if errs:
        raise ValidationError("；".join(errs))
