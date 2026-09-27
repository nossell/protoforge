# -*- coding: utf-8 -*-
"""部署对话框：插件目录选择、安装/卸载、打开目录、tshark 检测。"""
from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QVBoxLayout,
)

from ..core import deploy as dep


class DeployDialog(QDialog):
    def __init__(self, lua_provider, parent=None):
        super().__init__(parent)
        self.lua_provider = lua_provider  # callback() -> str
        self.setWindowTitle("部署到 Wireshark")

        self.dir_combo = QComboBox()
        for d in dep.plugin_dirs():
            self.dir_combo.addItem(str(d))
        default = dep.default_plugin_dir()
        if default:
            self.dir_combo.setCurrentText(str(default))

        self.name_edit = QLineEdit("myproto")
        self.status = QLabel()
        self._refresh_tshark()

        btn_install = QPushButton("安装 / 覆盖安装")
        btn_uninstall = QPushButton("卸载")
        btn_open = QPushButton("打开插件目录")
        btn_close = QPushButton("关闭")
        btn_install.clicked.connect(self._install)
        btn_uninstall.clicked.connect(self._uninstall)
        btn_open.clicked.connect(self._open_dir)
        btn_close.clicked.connect(self.accept)

        form = QVBoxLayout(self)
        form.addWidget(QLabel("Wireshark 个人插件目录（Lua 放根目录，跨大版本保留）："))
        form.addWidget(self.dir_combo)
        form.addWidget(QLabel("插件名（生成 <名称>.lua）："))
        form.addWidget(self.name_edit)
        form.addWidget(self.status)
        row = QHBoxLayout()
        row.addWidget(btn_install)
        row.addWidget(btn_uninstall)
        row.addWidget(btn_open)
        row.addStretch(1)
        row.addWidget(btn_close)
        form.addLayout(row)

    def _target(self):
        from pathlib import Path
        return Path(self.dir_combo.currentText())

    def _install(self):
        code = self.lua_provider() if self.lua_provider else ""
        if not code:
            QMessageBox.warning(self, "无法部署", "生成 Lua 失败，请先修正协议定义")
            return
        name = self.name_edit.text().strip()
        try:
            path = dep.install(code, name, self._target())
        except (ValueError, OSError) as e:
            QMessageBox.critical(self, "部署失败", str(e))
            return
        QMessageBox.information(
            self, "已安装",
            f"已写入：\n{path}\n\n重启 Wireshark 后生效。\n"
            "提示：Lua 插件放个人目录根，Wireshark 大版本升级不会丢失。")

    def _uninstall(self):
        name = self.name_edit.text().strip()
        if dep.uninstall(name, self._target()):
            QMessageBox.information(self, "已卸载", f"{name}.lua 已删除")
        else:
            QMessageBox.information(self, "未找到", f"{self._target()} 下没有 {name}.lua")

    def _open_dir(self):
        d = self._target()
        d.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(d)))

    def _refresh_tshark(self):
        exe = dep.find_tshark()
        if exe:
            ver = dep.tshark_version(exe) or "未知版本"
            self.status.setText(f"检测到：{ver}")
        else:
            self.status.setText("未检测到 Wireshark/tshark（仍可部署，重启 Wireshark 后生效）")
