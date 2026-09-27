# -*- coding: utf-8 -*-
"""属性面板：编辑选中字段的属性，改动即回写模型并通知刷新。"""
from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QSpinBox, QPlainTextEdit,
    QLineEdit, QVBoxLayout, QWidget,
)

from ..core.csvimport import _parse_enum
from ..core.model import Field, is_bitfield


def _enum_to_text(enum: dict | None) -> str:
    return "\n".join(f"{k}={v}" for k, v in (enum or {}).items())


class PropertyPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.field: Field | None = None
        self.on_change = None
        self._building = False

        self.name_edit = QLineEdit()
        self.label_edit = QLineEdit()
        self.type_combo = QComboBox()
        from .field_editor import FIELD_TYPES
        self.type_combo.addItems(FIELD_TYPES)
        self.display_combo = QComboBox()
        self.display_combo.addItems(["dec", "hex"])

        self.width_spin = QSpinBox()
        self.width_spin.setRange(1, 7)
        self.size_spin = QSpinBox()
        self.size_spin.setRange(1, 65535)
        self.const_edit = QLineEdit()
        self.const_edit.setPlaceholderText("如 0x5A5A（留空不校验）")
        self.crc_check = QCheckBox("CRC-16/CCITT-FALSE 校验字段（须为末尾 uint16）")
        self.enum_edit = QPlainTextEdit()
        self.enum_edit.setPlaceholderText("每行一条：1=Telemetry")
        self.enum_edit.setFixedHeight(80)
        self.on_combo = QComboBox()
        self.count_mode = QComboBox()
        self.count_mode.addItems(["固定次数", "按字段计数"])
        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 65535)
        self.count_from_combo = QComboBox()

        form = QFormLayout()
        form.addRow("字段名", self.name_edit)
        form.addRow("显示名", self.label_edit)
        form.addRow("类型", self.type_combo)
        form.addRow("显示进制", self.display_combo)
        form.addRow("位宽 (bit)", self.width_spin)
        form.addRow("长度 (字节)", self.size_spin)
        form.addRow("常量校验", self.const_edit)
        form.addRow(self.crc_check)
        form.addRow("枚举表", self.enum_edit)
        form.addRow("switch 依据", self.on_combo)
        form.addRow("数组计数", self.count_mode)
        form.addRow("固定次数", self.count_spin)
        form.addRow("计数字段", self.count_from_combo)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(form)
        lay.addStretch(1)

        for w in (self.name_edit, self.label_edit, self.const_edit):
            w.editingFinished.connect(self._apply)
        self.type_combo.currentIndexChanged.connect(self._apply)
        self.display_combo.currentIndexChanged.connect(self._apply)
        for w in (self.width_spin, self.size_spin, self.count_spin):
            w.valueChanged.connect(self._apply)
        self.crc_check.toggled.connect(self._apply)
        self.enum_edit.textChanged.connect(self._apply)
        self.on_combo.currentIndexChanged.connect(self._apply)
        self.count_mode.currentIndexChanged.connect(self._apply)
        self.count_from_combo.currentIndexChanged.connect(self._apply)

    def set_prior_names(self, names: list[str]):
        """刷新 switch.on / count_from 的候选（当前字段之前声明的字段名）。"""
        self._building = True
        for combo, is_switch in ((self.on_combo, True), (self.count_from_combo, False)):
            cur = combo.currentText()
            combo.clear()
            combo.addItems(names)
            if cur:
                combo.setCurrentText(cur)
        self._building = False

    def bind(self, field: Field | None):
        self._building = True
        self.field = field
        if field is None:
            self.setEnabled(False)
            self._building = False
            return
        self.setEnabled(True)
        self.name_edit.setText(field.name)
        self.label_edit.setText(field.label)
        if is_bitfield(field):
            self.type_combo.setCurrentText("uint (bitfield)")
        else:
            self.type_combo.setCurrentText(field.type)
        self.display_combo.setCurrentText(field.display)
        self.width_spin.setValue(field.width or 1)
        self.size_spin.setValue(field.size or 1)
        self.const_edit.setText(field.const or "")
        self.crc_check.setChecked(bool(field.crc16))
        self.enum_edit.setPlainText(_enum_to_text(field.enum))
        if field.on:
            self.on_combo.setCurrentText(field.on)
        if field.count_from:
            self.count_mode.setCurrentIndex(1)
            self.count_from_combo.setCurrentText(field.count_from)
        else:
            self.count_mode.setCurrentIndex(0)
            self.count_spin.setValue(field.count or 1)
        self._building = False

    def _apply(self):
        if self._building or self.field is None:
            return
        f = self.field
        f.name = self.name_edit.text().strip() or f.name
        f.label = self.label_edit.text().strip()
        t = self.type_combo.currentText()
        if t == "uint (bitfield)":
            f.type = "uint"
            f.width = self.width_spin.value()
        else:
            f.type = t
            if t not in ("uint",):
                f.width = 0
        f.display = self.display_combo.currentText()
        if t in ("string", "bytes"):
            f.size = self.size_spin.value()
        f.const = self.const_edit.text().strip() or None
        f.crc16 = "ccitt_false" if self.crc_check.isChecked() else None
        try:
            f.enum = _parse_enum(self.enum_edit.toPlainText())
        except ValueError:
            pass  # 输入未完成时不破坏原值
        if f.type == "switch":
            f.on = self.on_combo.currentText() or None
        if f.type == "array":
            if self.count_mode.currentIndex() == 0:
                f.count, f.count_from = self.count_spin.value(), None
            else:
                f.count, f.count_from = None, self.count_from_combo.currentText() or None
        if self.on_change:
            self.on_change()
