# -*- coding: utf-8 -*-
"""GUI offscreen 冒烟测试：QT_QPA_PLATFORM=offscreen 下驱动主窗口核心链路。"""
import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from protoforge.app.main_window import MainWindow  # noqa: E402
from tests.conftest import smsp_frame, telemetry_payload  # noqa: E402


@pytest.fixture(scope="module")
def app():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def win(app):
    w = MainWindow()
    yield w
    w.close()


def test_load_smsp_and_generate(win):
    win.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    assert win.editor.tree.topLevelItemCount() == 7
    # 顶层 switch 节点含 3 个 case
    sw_items = [win.editor.tree.topLevelItem(i) for i in range(7)]
    sw = next(it for it in sw_items if "switch" in it.text(1))
    assert sw.childCount() == 3
    # 生成
    lua = win.current_lua()
    assert 'Proto("smsp"' in lua and "ProtoField.uint8" in lua
    win._generate_to_view()
    assert "crc16_ccitt" in win.lua_view.toPlainText()


def test_statusbar_validation(win):
    win.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    assert "定义合法" in win.statusBar().currentMessage()
    # 弄坏定义
    win.protocol.fields[0].name = win.protocol.fields[1].name  # 重名
    win._refresh()
    assert "定义问题" in win.statusBar().currentMessage()


def test_bench_run(win):
    win.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    frame = smsp_frame(1, 1, 3, telemetry_payload([]))
    win.bench.hex_edit.setText(frame.hex())
    win.bench.run_hex()
    assert win.bench.frame_list.topLevelItemCount() == 1
    assert win.bench.frame_list.topLevelItem(0).text(1) == "PASS"
    assert win.bench.detail.topLevelItemCount() >= 1
    labels = collect_labels(win.bench.detail.topLevelItem(0))
    assert any(l.startswith("Magic: 0x5A5A") for l in labels)
    assert any("[correct]" in l for l in labels)


def test_bench_bad_crc(win):
    win.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    frame = bytearray(smsp_frame(1, 1, 3, telemetry_payload([])))
    frame[-1] ^= 0xFF
    win.bench.hex_edit.setText(bytes(frame).hex())
    win.bench.run_hex()
    item = win.bench.frame_list.topLevelItem(0)
    assert item.text(1) == "PASS"  # 解析完成
    assert "Checksum" in item.text(3)


def test_bench_pcap(win):
    pcap = os.path.join(REPO, "examples", "demo.pcap")
    if not os.path.exists(pcap):
        pytest.skip("demo.pcap 未生成")
    win.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    from protoforge.core.pcapio import extract_frames, read_pcap
    win.bench.run_frames(extract_frames(read_pcap(pcap), {5566}))
    assert win.bench.frame_list.topLevelItemCount() == 4
    assert win.bench.frame_list.topLevelItem(3).text(3).startswith("Expert")


def test_property_edit_propagates(win):
    win.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    # 选中第一个字段（magic）
    win.editor.tree.setCurrentItem(win.editor.tree.topLevelItem(0))
    assert win.props.field is not None and win.props.field.name == "magic"
    win.props.label_edit.setText("幻数")
    win.props._apply()
    assert win.protocol.fields[0].label == "幻数"
    lua = win.current_lua()
    assert '"幻数"' in lua


def test_deploy_core_via_dialog_provider(win, tmp_path):
    """对话框的 lua_provider 即主窗口 current_lua；用 core.deploy 验证落盘链路。"""
    from protoforge.core import deploy as dep
    from protoforge.app.deploy_dialog import DeployDialog
    win.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
    dlg = DeployDialog(win.current_lua, win)
    code = dlg.lua_provider()
    assert 'Proto("smsp"' in code
    path = dep.install(code, "smsp", tmp_path)
    assert path.exists() and "Proto(" in path.read_text(encoding="utf-8")
    assert dep.uninstall("smsp", tmp_path) is True


def collect_labels(item):
    out = [item.text(0)]
    for i in range(item.childCount()):
        out.extend(collect_labels(item.child(i)))
    return out
