#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成使用手册截图（offscreen grab，无需显示器）。用法：python tools/make_screens.py"""
import os
import sys

os.environ["QT_QPA_PLATFORM"] = "offscreen"
if sys.platform == "win32" and os.path.isdir(r"C:\Windows\Fonts"):
    os.environ["QT_QPA_FONTDIR"] = r"C:\Windows\Fonts"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
OUT = os.path.join(REPO, "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)

from PySide6.QtWidgets import QApplication

app = QApplication([])
from protoforge.app.main_window import MainWindow
from protoforge.app.deploy_dialog import DeployDialog
from protoforge.core.pcapio import extract_frames, read_pcap
from protoforge.core import deploy as _deploy

# 截图脱敏：部署对话框用合成路径，避免手册/仓库泄露开发机真实用户名
from pathlib import Path as _Path
_FAKE_PLUGIN_DIR = _Path(r"C:\Users\developer\AppData\Roaming\Wireshark\plugins")
_deploy.plugin_dirs = lambda: [_FAKE_PLUGIN_DIR]
_deploy.default_plugin_dir = lambda: _FAKE_PLUGIN_DIR

w = MainWindow()
w.resize(1280, 800)
w.show()
app.processEvents()

# 1) 主窗口：字段编辑器
w.load_protocol(os.path.join(REPO, "examples", "smsp.json"))
app.processEvents()
w.grab().save(os.path.join(OUT, "main_window.png"))

# 2) 生成的 Lua
w._generate_to_view()
app.processEvents()
w.tabs.setCurrentIndex(0)
app.processEvents()
w.grab().save(os.path.join(OUT, "generated_lua.png"))

# 3) 测试台（pcap 4 帧，选中损坏 CRC 帧）
w.tabs.setCurrentIndex(1)
pkts = read_pcap(os.path.join(REPO, "examples", "demo.pcap"))
w.bench.run_frames(extract_frames(pkts, {5566}))
app.processEvents()
w.bench.frame_list.setCurrentItem(w.bench.frame_list.topLevelItem(3))
app.processEvents()
w.grab().save(os.path.join(OUT, "testbench.png"))

# 4) 部署对话框
dlg = DeployDialog(w.current_lua, w)
dlg.resize(600, 260)
dlg.show()
app.processEvents()
dlg.grab().save(os.path.join(OUT, "deploy_dialog.png"))

print("[OK] screenshots ->", OUT)
for f in sorted(os.listdir(OUT)):
    print("   -", f)
