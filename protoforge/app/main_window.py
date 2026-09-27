# -*- coding: utf-8 -*-
"""ProtoForge 主窗口。"""
from __future__ import annotations

import os

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
    QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import __version__
from ..core.csvimport import CsvUnsupported, export_csv, import_csv
from ..core.generator import generate_lua
from ..core.jsonio import load_protocol, save_protocol
from ..core.model import Binding, Field, Protocol, validate, walk
from .deploy_dialog import DeployDialog
from .field_editor import FieldEditor
from .property_panel import PropertyPanel
from .testbench import TestBench

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"ProtoForge v{__version__} — Wireshark Lua 解析器生成器")
        self.resize(1280, 800)
        self.protocol = Protocol(
            name="myproto", long_name="MYPROTO",
            bindings=[Binding("udp.port", [5566])],
            fields=[Field("magic", label="Magic", type="uint16", display="hex"),
                    Field("payload", label="Payload", type="uint8")],
        )

        # ---- 顶部协议元信息 ----
        self._loading_bindings = False
        self.name_edit = QLineEdit(self.protocol.name)
        self.long_edit = QLineEdit(self.protocol.long_name)
        self.heur_check = QCheckBox("启发式注册（首字段须带 const）")
        self.bind_table = QTableWidget(0, 2)
        self.bind_table.setHorizontalHeaderLabels(["绑定表", "端口（逗号分隔）"])
        self.bind_table.setMaximumHeight(96)
        self.btn_add_bind = QPushButton("＋绑定")
        self.btn_del_bind = QPushButton("删除绑定")
        self.btn_add_bind.clicked.connect(self._add_binding_row)
        self.btn_del_bind.clicked.connect(self._del_binding_row)
        self.bind_table.itemChanged.connect(self._bindings_from_table)
        meta = QVBoxLayout()
        row1 = QVBoxLayout()
        row1.addWidget(QLabel("协议名（Lua 前缀）"))
        row1.addWidget(self.name_edit)
        row1.addWidget(QLabel("协议全名"))
        row1.addWidget(self.long_edit)
        row1.addWidget(self.heur_check)
        row2 = QVBoxLayout()
        row2.addWidget(QLabel("端口绑定（可多条：udp/tcp 同时监听）"))
        btns = QHBoxLayout()
        btns.addWidget(self.btn_add_bind)
        btns.addWidget(self.btn_del_bind)
        btns.addStretch(1)
        row2.addLayout(btns)
        row2.addWidget(self.bind_table)
        meta_wrap = QWidget()
        mrow = QSplitter()
        w1, w2 = QWidget(), QWidget()
        w1.setLayout(row1)
        w2.setLayout(row2)
        mrow.addWidget(w1)
        mrow.addWidget(w2)
        meta.addWidget(QLabel("协议定义（meta）"))
        meta.addWidget(mrow)
        meta_wrap.setLayout(meta)
        meta_wrap.setMaximumHeight(150)

        for w in (self.name_edit, self.long_edit):
            w.editingFinished.connect(self._meta_changed)
        self.heur_check.toggled.connect(self._meta_changed)

        # ---- 中部 ----
        self.editor = FieldEditor()
        self.props = PropertyPanel()
        self.editor.on_select = self._on_field_selected
        self.editor.on_change = self._refresh
        self.props.on_change = self._refresh

        self.lua_view = QPlainTextEdit()
        self.lua_view.setReadOnly(True)
        self.lua_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.gen_btn = QPushButton("生成 / 刷新 Lua ▶")
        self.gen_btn.clicked.connect(self._generate_to_view)
        lua_tab = QWidget()
        lv = QVBoxLayout(lua_tab)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(self.gen_btn)
        lv.addWidget(self.lua_view)

        self.bench = TestBench()
        self.bench.get_lua = self.current_lua

        self.tabs = QTabWidget()
        self.tabs.addTab(lua_tab, "生成的 Lua")
        self.tabs.addTab(self.bench, "测试台")

        right = QSplitter(Qt.Vertical)
        props_wrap = QWidget()
        pv = QVBoxLayout(props_wrap)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.addWidget(QLabel("字段属性"))
        pv.addWidget(self.props)
        right.addWidget(props_wrap)
        right.addWidget(self.tabs)
        right.setSizes([360, 440])

        left = QSplitter(Qt.Horizontal)
        ew = QWidget()
        ev = QVBoxLayout(ew)
        ev.setContentsMargins(0, 0, 0, 0)
        ev.addWidget(QLabel("字段结构"))
        ev.addWidget(self.editor)
        left.addWidget(ew)
        left.addWidget(right)
        left.setSizes([500, 760])

        central = QWidget()
        cv = QVBoxLayout(central)
        cv.setContentsMargins(8, 8, 8, 8)
        cv.addWidget(meta_wrap)
        cv.addWidget(left, 1)
        self.setCentralWidget(central)

        self._build_menus()
        self.editor.bind(self.protocol)
        self._refresh()

    # ---------- 菜单 ----------
    def _build_menus(self):
        mb = self.menuBar()
        m_file = mb.addMenu("文件(&F)")
        for text, fn in (("新建", self._new), ("打开 JSON…", self._open),
                         ("保存 JSON…", self._save_json), ("导入 CSV…", self._import_csv),
                         ("导出 CSV…", self._export_csv), ("导出 Lua…", self._export_lua)):
            a = QAction(text, self)
            a.triggered.connect(fn)
            m_file.addAction(a)
        m_file.addSeparator()
        a = QAction("退出", self)
        a.triggered.connect(self.close)
        m_file.addAction(a)

        m_dep = mb.addMenu("部署(&D)")
        a = QAction("安装到 Wireshark…", self)
        a.triggered.connect(self._deploy)
        m_dep.addAction(a)

        m_help = mb.addMenu("帮助(&H)")
        a = QAction("使用手册…", self)
        a.triggered.connect(self._manual)
        m_help.addAction(a)
        a = QAction(f"关于 ProtoForge v{__version__}", self)
        a.triggered.connect(lambda: QMessageBox.about(
            self, "关于",
            f"ProtoForge v{__version__}\nWireshark Lua 解析器生成器\n\n"
            "生成的 Lua 按 GPLv2+ 分发（使用 Wireshark Lua 绑定）；\n"
            "本工具不链接 Wireshark，可独立分发。"))
        m_help.addAction(a)

    # ---------- 模型同步 ----------
    def _populate_bindings(self):
        self._loading_bindings = True
        rows = len(self.protocol.bindings) or 1
        self.bind_table.setRowCount(rows)
        for i, b in enumerate(self.protocol.bindings):
            self.bind_table.setItem(i, 0, QTableWidgetItem(b.table))
            self.bind_table.setItem(i, 1, QTableWidgetItem(",".join(map(str, b.ports))))
        if not self.protocol.bindings:
            self.bind_table.setItem(0, 0, QTableWidgetItem("udp.port"))
            self.bind_table.setItem(0, 1, QTableWidgetItem(""))
        self._loading_bindings = False

    def _add_binding_row(self):
        self.bind_table.setRowCount(self.bind_table.rowCount() + 1)

    def _del_binding_row(self):
        row = self.bind_table.currentRow()
        if row >= 0:
            self.bind_table.removeRow(row)
            self._bindings_from_table()

    def _bindings_from_table(self):
        if self._loading_bindings:
            return
        bindings = []
        for r in range(self.bind_table.rowCount()):
            t_item = self.bind_table.item(r, 0)
            p_item = self.bind_table.item(r, 1)
            table = (t_item.text().strip() if t_item else "") or "udp.port"
            ports_raw = (p_item.text() if p_item else "").replace("，", ",")
            try:
                ports = [int(x, 0) for x in ports_raw.split(",") if x.strip()]
            except ValueError:
                ports = []
            if ports:
                bindings.append(Binding(table=table, ports=ports))
        if not bindings:
            bindings = [Binding("udp.port", [5566])]
        self.protocol.bindings = bindings
        self._refresh()

    def _meta_changed(self):
        p = self.protocol
        p.name = self.name_edit.text().strip() or p.name
        p.long_name = self.long_edit.text().strip() or p.long_name
        p.heuristic = "udp" if self.heur_check.isChecked() else None
        self._refresh()

    def _on_field_selected(self, field):
        names = []
        if field is not None:
            for f in walk(self.protocol.fields):
                if f is field:
                    break
                names.append(f.name)
        self.props.set_prior_names(names)
        self.props.bind(field)

    def _refresh(self):
        errs = validate(self.protocol)
        if errs:
            self.statusBar().showMessage(f"⚠ {len(errs)} 个定义问题：{errs[0]}" + ("…" if len(errs) > 1 else ""))
        else:
            self.statusBar().showMessage("定义合法 ✓（可生成/部署）")

    # ---------- 生成 ----------
    def current_lua(self) -> str:
        errs = validate(self.protocol)
        if errs:
            QMessageBox.warning(self, "无法生成", "定义存在问题：\n" + "\n".join(errs[:5]))
            return ""
        try:
            return generate_lua(self.protocol)
        except Exception as e:  # pragma: no cover
            QMessageBox.critical(self, "生成异常", str(e))
            return ""

    def _generate_to_view(self):
        code = self.current_lua()
        if code:
            self.lua_view.setPlainText(code)
            self.statusBar().showMessage(f"已生成 {len(code.splitlines())} 行 Lua ✓")

    # ---------- 文件 ----------
    def _new(self):
        self.protocol = Protocol(
            name="myproto", long_name="MYPROTO",
            bindings=[Binding("udp.port", [5566])],
            fields=[Field("magic", label="Magic", type="uint16", display="hex"),
                    Field("payload", label="Payload", type="uint8")],
        )
        self._reload_all()

    def _reload_all(self):
        self._loading_bindings = False
        self.name_edit.setText(self.protocol.name)
        self.long_edit.setText(self.protocol.long_name)
        self.heur_check.setChecked(self.protocol.heuristic == "udp")
        self._populate_bindings()
        self.editor.bind(self.protocol)
        self._refresh()

    def load_protocol(self, path: str):
        try:
            self.protocol = import_csv(path) if path.lower().endswith(".csv") else load_protocol(path)
        except (ValueError, OSError) as e:
            QMessageBox.critical(self, "打开失败", str(e))
            return
        self._reload_all()

    def _open(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开协议定义", "", "ProtoForge (*.json *.csv);;JSON (*.json);;CSV (*.csv)")
        if path:
            self.load_protocol(path)

    def _save_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存协议定义", f"{self.protocol.name}.json", "JSON (*.json)")
        if path:
            save_protocol(self.protocol, path)
            self.statusBar().showMessage(f"已保存 {path}")

    def _import_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入 CSV", "", "CSV (*.csv)")
        if path:
            self.load_protocol(path)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出 CSV", f"{self.protocol.name}.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            export_csv(self.protocol, path)
            self.statusBar().showMessage(f"已导出 {path}")
        except (CsvUnsupported, OSError) as e:
            QMessageBox.warning(self, "无法导出 CSV", str(e))

    def _export_lua(self):
        code = self.current_lua()
        if not code:
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出 Lua", f"{self.protocol.name}.lua", "Lua (*.lua)")
        if path:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code)
            self.statusBar().showMessage(f"已导出 {path}")

    # ---------- 部署/帮助 ----------
    def _deploy(self):
        DeployDialog(self.current_lua, self).exec()

    def _manual(self):
        html_manual = os.path.join(REPO, "docs", "USER_MANUAL.html")
        md_manual = os.path.join(REPO, "docs", "USER_MANUAL.md")
        target = html_manual if os.path.exists(html_manual) else md_manual
        QDesktopServices.openUrl(QUrl.fromLocalFile(target))


def main():  # pragma: no cover
    import sys
    from PySide6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":  # pragma: no cover
    main()
