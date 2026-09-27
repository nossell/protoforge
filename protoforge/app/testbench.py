# -*- coding: utf-8 -*-
"""测试台：hex / pcap 输入 → 引擎执行 → 解析树 + 十六进制联动高亮。"""
from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox,
    QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)
from PySide6.QtCore import Qt

from ..core.luaengine import DissectResult, LuaEngine, LuaError, TreeNode
from ..core.pcapio import extract_frames, read_pcap


def _fmt_hex(data: bytes, hl_off: int = -1, hl_len: int = 0) -> str:
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart, ascii_part = [], []
        for j, b in enumerate(chunk):
            on = hl_off >= 0 and i + j >= hl_off and i + j < hl_off + hl_len
            cell = f"{b:02x}"
            if on:
                cell = f'<span style="background:#2563eb;color:#fff">{cell}</span>'
            hexpart.append(cell)
            ch = chr(b) if 32 <= b < 127 else "·"
            ascii_part.append(f'<span style="background:#2563eb;color:#fff">{ch}</span>'
                              if on else ch)
        rows.append(f'<pre style="margin:0">{i:04x}  {" ".join(hexpart):<47}  {"".join(ascii_part)}</pre>')
    return "".join(rows) or "<pre>(空)</pre>"


class TestBench(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.results: list[DissectResult] = []
        self.frames: list[bytes] = []
        self.get_lua = None  # callback() -> str（由主窗口注入，返回当前生成代码）

        self.hex_edit = QLineEdit()
        self.hex_edit.setPlaceholderText("粘贴十六进制帧，如 5a5a1101000d00…")
        self.run_btn = QPushButton("运行 hex ▶")
        self.pcap_btn = QPushButton("从 pcap 提取…")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(5566)

        top = QHBoxLayout()
        top.addWidget(QLabel("hex:"))
        top.addWidget(self.hex_edit, 1)
        top.addWidget(self.run_btn)
        top.addWidget(QLabel("pcap 端口:"))
        top.addWidget(self.port_spin)
        top.addWidget(self.pcap_btn)

        self.frame_list = QTreeWidget()
        self.frame_list.setHeaderLabels(["#", "结果", "Info", "expert"])
        self.frame_list.setColumnWidth(0, 40)
        self.frame_list.setColumnWidth(1, 60)
        self.frame_list.setColumnWidth(2, 220)
        self.frame_list.itemSelectionChanged.connect(self._show_frame)

        self.detail = QTreeWidget()
        self.detail.setHeaderLabel("解析树（点击节点 → 右侧高亮对应字节）")
        self.detail.itemSelectionChanged.connect(self._highlight)

        self.hex_view = QLabel()
        self.hex_view.setTextFormat(Qt.RichText)
        self.hex_view.setFont(QFont("Consolas"))
        self.hex_view.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.hex_view.setWordWrap(True)

        split = QSplitter()
        split.addWidget(self.detail)
        wrap = QWidget()
        vl = QVBoxLayout(wrap)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.addWidget(QLabel("十六进制"))
        vl.addWidget(self.hex_view)
        split.addWidget(wrap)
        split.setSizes([520, 400])

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(top)
        lay.addWidget(self.frame_list)
        lay.addWidget(split, 1)

        self.run_btn.clicked.connect(self.run_hex)
        self.pcap_btn.clicked.connect(self._load_pcap)

    # ---------- 执行 ----------
    def _lua(self) -> tuple[LuaEngine | None, str]:
        if not self.get_lua:
            return None, "未接入生成器"
        code = self.get_lua()
        if not code:
            return None, "生成失败（请先修正协议定义）"
        try:
            eng = LuaEngine()
            eng.load(code)
            return eng, ""
        except LuaError as e:
            return None, str(e)

    def run_frames(self, frames: list[bytes]):
        self.frames = frames
        eng, err = self._lua()
        self.frame_list.clear()
        self.detail.clear()
        self.results = []
        if eng is None:
            self.frame_list.addTopLevelItem(QTreeWidgetItem(["-", "ERR", err[:60], ""]))
            return
        for i, f in enumerate(frames, 1):
            r = eng.dissect(f)
            self.results.append(r)
            it = QTreeWidgetItem([
                str(i), "PASS" if r.ok else "FAIL",
                r.info, (r.error or "").replace("\n", " ; ")[:80],
            ])
            self.frame_list.addTopLevelItem(it)
        if self.frame_list.topLevelItemCount():
            self.frame_list.setCurrentItem(self.frame_list.topLevelItem(0))

    def run_hex(self):
        hx = self.hex_edit.text().replace(" ", "").replace("0x", "")
        try:
            frame = bytes.fromhex(hx)
        except ValueError:
            self.frame_list.clear()
            self.detail.clear()
            self.hex_view.setText("<pre>hex 输入不合法</pre>")
            return
        self.run_frames([frame])

    def _load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择 pcap", "", "pcap (*.pcap);;All (*)")
        if not path:
            return
        try:
            pkts = read_pcap(path)
        except (ValueError, OSError) as e:
            self.frame_list.clear()
            self.frame_list.addTopLevelItem(QTreeWidgetItem(["-", "ERR", str(e)[:80], ""]))
            return
        self.run_frames(extract_frames(pkts, {self.port_spin.value()}))

    # ---------- 展示 ----------
    def _show_frame(self):
        idx = -1
        root = self.frame_list.indexOfTopLevelItem(self.frame_list.currentItem())
        if root < 0 or root >= len(self.results):
            return
        r = self.results[root]
        self.detail.clear()
        if r.tree:
            self._fill(self.detail, r.tree)
            self.detail.expandAll()
        self.hex_view.setText(_fmt_hex(self.frames[root] if root < len(self.frames) else b""))

    def _fill(self, parent, node: TreeNode):
        text = node.label + (f": {node.value}" if node.value is not None else "")
        it = QTreeWidgetItem([text])
        it.setData(0, Qt.UserRole, node)
        if node.expert:
            it.setForeground(0, Qt.red)
        if isinstance(parent, QTreeWidget):
            parent.addTopLevelItem(it)
        else:
            parent.addChild(it)
        for c in node.children:
            self._fill(it, c)

    def _highlight(self):
        items = self.detail.selectedItems()
        idx = self.frame_list.indexOfTopLevelItem(self.frame_list.currentItem())
        if not items or idx < 0 or idx >= len(self.frames):
            return
        node = items[0].data(0, Qt.UserRole)
        data = self.frames[idx]
        off = node.offset if node else -1
        ln = node.length if node else 0
        self.hex_view.setText(_fmt_hex(data, off, ln))
