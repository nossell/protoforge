# -*- coding: utf-8 -*-
"""部署：Wireshark 个人插件目录发现 / Lua 安装卸载 / tshark 检测。

Lua 脚本放个人插件目录根（不分版本子目录），大版本升级不丢失
（WSUG B.4 PluginFolders：Windows %APPDATA%\\Wireshark\\plugins；
Linux/macOS ~/.local/lib/wireshark/plugins）。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark", "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
]


def plugin_dirs() -> list[Path]:
    """按平台返回候选个人插件目录（按优先序）。"""
    dirs: list[Path] = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            dirs.append(Path(appdata) / "Wireshark" / "plugins")
    dirs.append(Path.home() / ".local" / "lib" / "wireshark" / "plugins")
    dirs.append(Path.home() / ".wireshark" / "plugins")  # 旧版兼容
    return dirs


def default_plugin_dir() -> Path | None:
    """第一个「可用」的目录：已存在，或其父目录存在（可创建）。"""
    for d in plugin_dirs():
        if d.exists():
            return d
        if d.parent.exists():
            return d
    return None


def install(lua_text: str, name: str, target: Path) -> Path:
    """写入 target/name.lua；返回文件路径。"""
    if not name or not all(c.isalnum() or c in "_-" for c in name):
        raise ValueError(f"非法插件名: {name!r}")
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{name}.lua"
    path.write_text(lua_text, encoding="utf-8", newline="\n")
    return path


def uninstall(name: str, target: Path) -> bool:
    path = Path(target) / f"{name}.lua"
    if path.exists():
        path.unlink()
        return True
    return False


def find_tshark() -> str | None:
    exe = shutil.which("tshark")
    if exe:
        return exe
    for cand in TSHARK_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return None


def tshark_version(exe: str) -> str | None:
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15)
        first = (out.stdout or out.stderr or "").splitlines()
        return first[0].strip() if first else None
    except (OSError, subprocess.SubprocessError):
        return None
