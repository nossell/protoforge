# -*- coding: utf-8 -*-
"""字段树编辑器：以树形展示/增删/移动协议字段（含 switch case 与 array element 子层）。"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QInputDialog, QLabel, QMessageBox, QPushButton,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..core.model import Field, is_bitfield

FIELD_TYPES = [
    "uint8", "uint16", "uint24", "uint32",
    "int8", "int16", "int32",
    "uint (bitfield)", "string", "bytes",
    "switch", "array",
]


def type_text(f: Field) -> str:
    if is_bitfield(f):
        return f"uint:{f.width}bit"
    if f.type == "string":
        return f"string[{f.size}]"
    if f.type == "bytes":
        return f"bytes[{f.size}]"
    if f.type == "switch":
        return f"switch on {f.on}"
    if f.type == "array":
        src = f"from {f.count_from}" if f.count_from else f"×{f.count}"
        return f"array {src}"
    return f.type + (" ⚑crc" if f.crc16 else "")


class FieldEditor(QWidget):
    """信号：fieldSelected(Field)、protocolChanged()。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.protocol = None
        self.on_select = None       # callback(Field|None)
        self.on_change = None       # callback()

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["字段", "类型", "显示名"])
        self.tree.setColumnWidth(0, 170)
        self.tree.setColumnWidth(1, 150)
        self.tree.itemSelectionChanged.connect(self._emit_select)

        bar = QHBoxLayout()
        self.btn_add = QPushButton("＋字段")
        self.btn_add_case = QPushButton("＋case")
        self.btn_add_elem = QPushButton("＋元素字段")
        self.btn_up = QPushButton("↑")
        self.btn_down = QPushButton("↓")
        self.btn_del = QPushButton("删除")
        for b in (self.btn_add, self.btn_add_case, self.btn_add_elem):
            bar.addWidget(b)
        bar.addStretch(1)
        for b in (self.btn_up, self.btn_down, self.btn_del):
            bar.addWidget(b)

        self.btn_add.clicked.connect(lambda: self._add_field())
        self.btn_add_case.clicked.connect(self._add_case)
        self.btn_add_elem.clicked.connect(lambda: self._add_field(element=True))
        self.btn_up.clicked.connect(lambda: self._move(-1))
        self.btn_down.clicked.connect(lambda: self._move(1))
        self.btn_del.clicked.connect(self._delete)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(bar)
        lay.addWidget(self.tree)

    # ---------- 数据 ----------
    def bind(self, protocol):
        self.protocol = protocol
        self.reload()

    def reload(self):
        self.tree.clear()
        if not self.protocol:
            return
        for f in self.protocol.fields:
            self._add_items(None, f)
        self.tree.expandAll()

    def _add_items(self, parent_item, f: Field):
        it = QTreeWidgetItem([f.name, type_text(f), f.label])
        it.setData(0, Qt.UserRole, ("field", f))
        if parent_item is None:
            self.tree.addTopLevelItem(it)
        else:
            parent_item.addChild(it)
        if f.type == "switch":
            for key, case in f.cases.items():
                cit = QTreeWidgetItem([f"case {key}", f"{len(case)} 字段", ""])
                cit.setData(0, Qt.UserRole, ("case", f, int(key)))
                it.addChild(cit)
                for cf in case:
                    self._add_items(cit, cf)
            if f.default is not None:
                dit = QTreeWidgetItem(["case default", f"{len(f.default)} 字段", ""])
                dit.setData(0, Qt.UserRole, ("default", f))
                it.addChild(dit)
                for cf in f.default:
                    self._add_items(dit, cf)
        elif f.type == "array" and f.element:
            eit = QTreeWidgetItem(["element", f"{len(f.element)} 字段", ""])
            eit.setData(0, Qt.UserRole, ("element", f))
            it.addChild(eit)
            for ef in f.element:
                self._add_items(eit, ef)
        return it

    # ---------- 选择 ----------
    def _selected(self):
        items = self.tree.selectedItems()
        if not items:
            return None
        return items[0].data(0, Qt.UserRole)

    def _emit_select(self):
        sel = self._selected()
        if self.on_select:
            self.on_select(sel[1] if sel and sel[0] in ("field", "element") else None)

    def selected_field(self):
        sel = self._selected()
        if sel and sel[0] in ("field", "element"):
            return sel[1]
        return None

    # ---------- 增删移动 ----------
    def _owner_list(self):
        """返回 (字段所属列表, 对应树节点)；顶层返回 protocol.fields。"""
        sel = self._selected()
        if sel is None:
            return self.protocol.fields, None
        kind, f = sel[0], sel[1]
        if kind == "case":
            key = sel[2]
            return f.cases[key], None
        if kind == "default":
            return f.default, None
        if kind == "element":
            return f.element, None
        # 普通字段：找它的父容器
        parent_item = self.tree.selectedItems()[0].parent()
        if parent_item is None:
            return self.protocol.fields, None
        pdata = parent_item.data(0, Qt.UserRole)
        if pdata and pdata[0] == "case":
            return pdata[1].cases[pdata[2]], parent_item
        if pdata and pdata[0] == "element":
            return pdata[1].element, parent_item
        return self.protocol.fields, None

    def _add_field(self, element=False):
        if not self.protocol:
            return
        target_list, _ = self._owner_list() if not element else (None, None)
        if element:
            sel = self._selected()
            if not sel or sel[0] not in ("element", "array"):
                QMessageBox.information(self, "提示", "请先选中数组或其 element 节点")
                return
            f = sel[1]
            target_list = f.element if sel[0] == "element" else f.element
        names, ok = QInputDialog.getText(
            self, "新增字段", "字段名（英文标识符）：")
        if not ok or not names.strip():
            return
        newf = Field(names.strip(), label=names.strip(), type="uint8")
        target_list.append(newf)
        self._changed()

    def _add_case(self):
        sel = self._selected()
        if not sel or sel[0] != "field" or sel[1].type != "switch":
            QMessageBox.information(self, "提示", "请先选中 switch 字段")
            return
        f = sel[1]
        text, ok = QInputDialog.getText(
            self, "新增 case", "case 键值（整数；输入 default 表示兜底分支）：")
        if not ok:
            return
        t = text.strip().lower()
        if t == "default":
            if f.default is None:
                f.default = []
            return self._changed()
        try:
            key = int(t, 0)
        except ValueError:
            QMessageBox.information(self, "提示", "case 键值必须是整数或 default")
            return
        f.cases[key] = []
        self._changed()

    def _delete(self):
        sel = self._selected()
        if not sel:
            return
        kind, f = sel[0], sel[1]
        lst, _ = self._owner_list()
        if kind == "case":
            key = sel[2]
            f.cases.pop(key, None)
        elif kind == "default":
            f.default = None
        elif kind == "element":
            return  # element 容器节点不可删
        else:
            if f in lst:
                lst.remove(f)
        self._changed()

    def _move(self, delta):
        sel = self._selected()
        if not sel or sel[0] not in ("field", "element"):
            return
        f = sel[1]
        lst, _ = self._owner_list()
        i = lst.index(f)
        j = i + delta
        if 0 <= j < len(lst):
            lst[i], lst[j] = lst[j], lst[i]
            self._changed()

    def _changed(self):
        self.reload()
        if self.on_change:
            self.on_change()
