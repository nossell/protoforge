# -*- coding: utf-8 -*-
"""ProtoForge CLI：generate / verify / deploy / selftest。

用法：
  python -m protoforge generate spec.json -o out.lua
  python -m protoforge generate spec.csv -o out.lua
  python -m protoforge verify out.lua --hex 5a5a1101...
  python -m protoforge verify out.lua --pcap demo.pcap --port 5566
  python -m protoforge deploy out.lua --name smsp [--dir 插件目录]
  python -m protoforge selftest
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import deploy as deploy_mod
from .core.csvimport import import_csv
from .core.jsonio import load_protocol
from .core.luaengine import DissectResult, LuaEngine, LuaError
from .core.model import ValidationError
from .core.pcapio import extract_frames, read_pcap


def _load_spec(path: str):
    if path.lower().endswith(".csv"):
        return import_csv(path)
    return load_protocol(path)


def _render_tree(node, depth=0, out=None):
    out = out if out is not None else []
    text = "  " * depth + node.label
    if node.value is not None:
        text += ": " + node.value
    out.append(text)
    for c in node.children:
        _render_tree(c, depth + 1, out)
    return out


def _print_result(i: int, r: DissectResult):
    status = "PASS" if r.ok else "FAIL"
    print(f"--- 帧 {i}: {status}  protocol={r.protocol} info={r.info!r} consumed={r.consumed}")
    if r.tree:
        for line in _render_tree(r.tree):
            print("  " + line)
    if r.error:
        print(f"  [expert/error] {r.error}")


def cmd_generate(args) -> int:
    from .core.generator import generate_lua
    try:
        p = _load_spec(args.spec)
        code = generate_lua(p)
    except (ValidationError, ValueError, OSError, json.JSONDecodeError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 2
    if args.output == "-":
        sys.stdout.write(code)
    else:
        import os
        parent = os.path.dirname(os.path.abspath(args.output))
        os.makedirs(parent, exist_ok=True)
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code)
        print(f"[OK] 已生成 {args.output}（协议 {p.name}，绑定 {[b.table for b in p.bindings]}）")
    return 0


def _collect_frames(args):
    if args.hex:
        hx = args.hex.replace(" ", "").replace("0x", "")
        try:
            return [bytes.fromhex(hx)]
        except ValueError:
            print("[错误] --hex 不是合法十六进制", file=sys.stderr)
            return None
    if args.pcap:
        try:
            pkts = read_pcap(args.pcap)
        except (ValueError, OSError) as e:
            print(f"[错误] 读取 pcap 失败: {e}", file=sys.stderr)
            return None
        return extract_frames(pkts, {args.port})
    return None


def cmd_verify(args) -> int:
    try:
        with open(args.lua, "r", encoding="utf-8") as fh:
            code = fh.read()
        eng = LuaEngine()
        eng.load(code)
    except (OSError, LuaError) as e:
        print(f"[错误] 加载 Lua 失败: {e}", file=sys.stderr)
        return 2
    frames = _collect_frames(args)
    if frames is None:
        print("[错误] 需要 --hex 或 --pcap 之一", file=sys.stderr)
        return 2
    if not frames:
        print("[提示] pcap 中没有匹配端口的帧", file=sys.stderr)
        return 1
    hard_fail = 0
    for i, f in enumerate(frames, 1):
        r = eng.dissect(f)
        _print_result(i, r)
        if not r.ok:
            hard_fail += 1
    print(f"绑定: {eng.bindings}")
    return 1 if hard_fail else 0


def cmd_deploy(args) -> int:
    try:
        with open(args.lua, "r", encoding="utf-8") as fh:
            code = fh.read()
    except OSError as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 2
    target = args.dir
    if not target:
        target = deploy_mod.default_plugin_dir()
        if target is None:
            print("[错误] 未找到 Wireshark 个人插件目录，请用 --dir 指定", file=sys.stderr)
            return 2
    try:
        path = deploy_mod.install(code, args.name, target)
    except (ValueError, OSError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 2
    print(f"[OK] 已安装 {path}")
    print("     重启 Wireshark 后生效（Lua 插件放个人目录根，跨大版本保留）")
    return 0


SELFTEST_SPEC = {
    "meta": {"name": "selft", "long_name": "SelfTest Proto"},
    "bindings": [{"table": "udp.port", "ports": [65500]}],
    "fields": [
        {"name": "magic", "label": "Magic", "type": "uint16", "display": "hex", "const": "0xAB12"},
        {"name": "hi", "label": "Hi", "type": "uint", "width": 4},
        {"name": "lo", "label": "Lo", "type": "uint", "width": 4, "enum": {"1": "One"}},
        {"name": "crc", "label": "CRC", "type": "uint16", "crc16": "ccitt_false"},
    ],
}


def cmd_selftest(args) -> int:
    import struct
    from .core.generator import generate_lua

    p = load_protocol(json.dumps(SELFTEST_SPEC))
    try:
        code = generate_lua(p)
    except ValidationError as e:
        print(f"[FAIL] 生成失败: {e}")
        return 1
    eng = LuaEngine()
    try:
        eng.load(code)
    except LuaError as e:
        print(f"[FAIL] 引擎加载失败: {e}")
        return 1

    body = struct.pack(">HB", 0xAB12, 0x11)  # magic, hi=1 lo=1
    x = 0xFFFF
    for b in body:
        x ^= b << 8
        for _ in range(8):
            x = ((x << 1) ^ 0x1021) if (x & 0x8000) else (x << 1)
            x &= 0xFFFF
    r = eng.dissect(body + struct.pack(">H", x))
    text = "\n".join(_render_tree(r.tree)) if r.tree else ""
    if not r.ok or "One (1)" not in text or "[correct]" not in text:
        print(f"[FAIL] 解析结果异常: {r.error}")
        for line in (_render_tree(r.tree) if r.tree else []):
            print("  " + line)
        return 1
    print(f"[PASS] selftest OK（ProtoForge v{__version__}，绑定 {eng.bindings}）")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="protoforge", description="ProtoForge — Wireshark Lua dissector 生成器")
    ap.add_argument("--version", action="version", version=f"ProtoForge {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="从 JSON/CSV 定义生成 Lua dissector")
    g.add_argument("spec", help="协议定义文件（.json 或 .csv）")
    g.add_argument("-o", "--output", default="-", help="输出 .lua 路径（- = stdout）")
    g.set_defaults(func=cmd_generate)

    v = sub.add_parser("verify", help="用内置引擎执行 Lua 并解析测试帧")
    v.add_argument("lua", help="生成的 .lua 文件")
    v.add_argument("--hex", help="十六进制帧（空格可选）")
    v.add_argument("--pcap", help="pcap 文件（classic pcap）")
    v.add_argument("--port", type=int, default=5566, help="pcap 提取端口（默认 5566）")
    v.set_defaults(func=cmd_verify)

    d = sub.add_parser("deploy", help="安装 Lua 到 Wireshark 个人插件目录")
    d.add_argument("lua", help=".lua 文件")
    d.add_argument("--name", required=True, help="插件名（生成 <name>.lua）")
    d.add_argument("--dir", default=None, help="目标插件目录（默认自动发现）")
    d.set_defaults(func=cmd_deploy)

    s = sub.add_parser("selftest", help="内置端到端自检")
    s.set_defaults(func=cmd_selftest)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
