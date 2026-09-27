# -*- coding: utf-8 -*-
"""E2E：协议定义 → 生成 Lua → 真实 tshark 解析。

独立性设计（防"假通过"）：
- 随机化协议名与长名，避免与本机已安装的个人插件同名导致 -X 脚本被拒载
- 自建临时 pcap，绑定专用端口 5598，不依赖 examples/demo.pcap
"""
import os
import struct
import subprocess
import sys

import pytest

TSHARK_CANDIDATES = [
    os.environ.get("TSHARK", ""),
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]
TSHARK = next((t for t in TSHARK_CANDIDATES if t and os.path.isfile(t)), None)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

pytestmark = pytest.mark.skipif(TSHARK is None, reason="本机无 tshark")

E2E_NAME = "pfprobe9x"          # 唯一短名，杜绝与本机插件冲突
E2E_LONG = "ProtoForge E2E Probe"
E2E_PORT = 5598


def _build(tmp_path):
    from protoforge.core.generator import generate_lua
    from protoforge.core.jsonio import load_protocol
    from examples.make_demo import wrap_udp
    from tests.conftest import smsp_frame, telemetry_payload
    import json

    p = load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    p.name = E2E_NAME
    p.long_name = E2E_LONG
    p.bindings[0].ports = [E2E_PORT]
    lua_path = tmp_path / "probe.lua"
    lua_path.write_text(generate_lua(p), encoding="utf-8")

    good = smsp_frame(1, 1, 1, telemetry_payload([(0x0102, 1, 1, 0, -125, 2)]))
    corrupt = bytearray(good)
    corrupt[-1] ^= 0xFF
    frames = [
        good,
        smsp_frame(1, 2, 2, struct.pack(">BH3h", 7, 5000, 100, -50, 75)),
        bytes(corrupt),
    ]
    pcap_path = tmp_path / "probe.pcap"
    with open(pcap_path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            pkt = wrap_udp(f, 40000 + i, E2E_PORT)
            fh.write(struct.pack("<IIII", 1770000000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)
    return lua_path, pcap_path


@pytest.fixture(scope="module")
def e2e(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pf_e2e")
    lua_path, pcap_path = _build(tmp)
    verbose = subprocess.run(
        [TSHARK, "-r", str(pcap_path), "-X", f"lua_script:{lua_path}", "-V"],
        capture_output=True, text=True, timeout=60,
    )
    summary = subprocess.run(
        [TSHARK, "-r", str(pcap_path), "-X", f"lua_script:{lua_path}"],
        capture_output=True, text=True, timeout=60,
    )
    return verbose, summary


def test_script_loads_without_errors(e2e):
    verbose, summary = e2e
    assert "Lua Error" not in verbose.stdout
    assert "Dissector bug" not in verbose.stdout
    assert "Lua Error" not in summary.stdout


def test_unique_protocol_actually_loaded(e2e):
    """解析树根节点必须是本次生成的唯一长名（防止用户插件顶替）。"""
    verbose, _ = e2e
    assert E2E_LONG in verbose.stdout


def test_native_bitfield_and_enum_rendering(e2e):
    verbose, _ = e2e
    out = verbose.stdout
    assert "0001 .... = Protocol Version: 1" in out
    assert "Telemetry (1)" in out          # 真机枚举格式 Name (value)
    assert "1... .... = Online: True" in out


def test_crc_correct_and_incorrect(e2e):
    verbose, _ = e2e
    out = verbose.stdout
    assert " [correct]" in out
    assert "[incorrect, expected 0x" in out
    assert "Expert Info (Error/Checksum)" in out


def test_info_column(e2e):
    _, summary = e2e
    assert "Telemetry, Seq=1" in summary.stdout
    assert "Config, Seq=2" in summary.stdout
