# -*- coding: utf-8 -*-
"""AI 生成协议定义对话框：描述(+样本) → LLM → 校验自修复 → 载入主窗口。

- 端点/模型/key 存本机 ~/.protoforge/ai.json（成功生成后自动保存）
- 生成走 QThread，避免阻塞界面；log 信号逐行回显
- caller 可注入（测试离线假 LLM）
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QDialog, QFormLayout, QHBoxLayout, QLineEdit, QPlainTextEdit, QPushButton,
    QSpinBox, QVBoxLayout, QWidget,
)

from ..core import aigen


class _GenThread(QThread):
    log_line = Signal(str)
    finished_ok = Signal(object)      # Protocol
    failed = Signal(str)

    def __init__(self, description, samples, cfg, max_rounds, caller, parent=None):
        super().__init__(parent)
        self._desc, self._samples, self._cfg = description, samples, cfg
        self._rounds, self._caller = max_rounds, caller

    def run(self):
        result = aigen.generate_with_repair(
            self._desc, self._samples, self._cfg, max_rounds=self._rounds,
            call_fn=self._caller, log=self.log_line.emit)
        if result.ok and result.protocol is not None:
            self.finished_ok.emit(result.protocol)
        else:
            self.failed.emit(result.error or "未知错误")


class AiDialog(QDialog):
    """成功生成后 self.protocol 为结果；主窗口在 accept() 后接管。"""

    def __init__(self, parent=None, caller=None):
        super().__init__(parent)
        self.setWindowTitle("AI 生成协议定义")
        self.resize(720, 620)
        self.protocol = None
        self._caller = caller
        self._thread = None

        self.desc_edit = QPlainTextEdit()
        self.desc_edit.setPlaceholderText(
            "用自然语言描述协议，中英皆可。例如：\n"
            "设备通过 UDP 5566 上报传感器数据。帧头魔数 0x5A5A（uint16），高 4 位版本、"
            "低 4 位消息类型（1=遥测 2=配置 3=事件），uint8 序号，uint16 载荷长度，"
            "载荷按消息类型分支：遥测是 1 字节数量 + N 组（uint16 传感器ID、3 位标志位域、int16 数值），"
            "配置是 uint32 上报间隔。末尾 CRC-16/CCITT-FALSE。")
        self.samples_edit = QPlainTextEdit()
        self.samples_edit.setPlaceholderText("可选：样本帧十六进制，每行一帧（如 5a5a 11 01 0004 …）")
        self.samples_edit.setFixedHeight(64)

        cfg = aigen.load_settings()
        self.endpoint_edit = QLineEdit(cfg.endpoint)
        self.model_edit = QLineEdit(cfg.model)
        self.key_edit = QLineEdit(cfg.api_key)
        self.key_edit.setEchoMode(QLineEdit.Password)
        self.key_edit.setPlaceholderText("本地 Ollama 可留空")
        self.rounds_spin = QSpinBox()
        self.rounds_spin.setRange(1, 6)
        self.rounds_spin.setValue(3)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)

        self.gen_btn = QPushButton("生成 ▶")
        self.close_btn = QPushButton("关闭")
        self.gen_btn.clicked.connect(self._generate)
        self.close_btn.clicked.connect(self.reject)

        form = QFormLayout()
        form.addRow("协议描述", self.desc_edit)
        form.addRow("样本帧（可选）", self.samples_edit)
        form.addRow("端点", self.endpoint_edit)
        form.addRow("模型", self.model_edit)
        form.addRow("API key", self.key_edit)
        form.addRow("自修复轮数", self.rounds_spin)

        btns = QHBoxLayout()
        btns.addStretch(1)
        btns.addWidget(self.gen_btn)
        btns.addWidget(self.close_btn)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(QWidget())
        lay.addWidget(self.log_view)
        lay.addLayout(btns)

    def _generate(self):
        desc = self.desc_edit.toPlainText().strip()
        if not desc:
            self.log_view.setPlainText("请先填写协议描述。")
            return
        if not self.model_edit.text().strip():
            self.log_view.setPlainText("请填写模型名（本地 Ollama 如 qwen3:4b）。")
            return
        cfg = aigen.AiConfig(
            endpoint=self.endpoint_edit.text().strip() or aigen.DEFAULT_ENDPOINT,
            model=self.model_edit.text().strip(),
            api_key=self.key_edit.text().strip(),
        )
        self.gen_btn.setEnabled(False)
        self.log_view.appendPlainText(f"配置：{cfg.model} @ {cfg.endpoint}")
        self._thread = _GenThread(desc, self.samples_edit.toPlainText(), cfg,
                                  self.rounds_spin.value(), self._caller, self)
        self._thread.log_line.connect(self.log_view.appendPlainText)
        self._thread.finished_ok.connect(self._on_ok)
        self._thread.failed.connect(self._on_fail)
        self._thread.finished.connect(self._on_done)
        self._thread.start()

    def _on_ok(self, protocol):
        self.protocol = protocol
        aigen.save_settings(aigen.AiConfig(
            endpoint=self.endpoint_edit.text().strip() or aigen.DEFAULT_ENDPOINT,
            model=self.model_edit.text().strip(),
            api_key=self.key_edit.text().strip()))
        self.log_view.appendPlainText(f"设置已保存到 {aigen.SETTINGS_PATH}")

    def _on_fail(self, err):
        self.log_view.appendPlainText(f"[失败] {err}")

    def _on_done(self):
        self.gen_btn.setEnabled(True)
        if self.protocol is not None:
            self.accept()
