# -*- coding: utf-8 -*-
"""v0.15.0 AI 辅助生成回归：prompt/解析/自修复循环/设置读写/GUI 对话框。

全部离线：call_fn 注入假 LLM，不发起网络请求。
"""
import json
import os

import pytest

from protoforge.core import aigen
from protoforge.core.aigen import (
    AiConfig, AiError, build_user_prompt, extract_json, generate_with_repair,
)

VALID = {
    "meta": {"name": "aidev", "long_name": "AI Demo Proto"},
    "bindings": [{"table": "udp.port", "ports": [5566]}],
    "fields": [
        {"name": "magic", "label": "Magic", "type": "uint16", "display": "hex",
         "const": "0x5A5A"},
        {"name": "seq", "label": "Seq", "type": "uint8"},
    ],
}


def fake_llm(responses):
    """按序返回预设回复；记录每次收到的 messages 供断言。"""
    calls = []

    def fn(cfg, messages):
        calls.append(messages)
        if not responses:
            raise AiError("no more canned responses")
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
    return fn, calls


# ---------- prompt 构建 ----------
def test_prompt_contains_description_and_samples():
    text = build_user_prompt("UDP 5566 传感器上报", "5a5a1101")
    assert "UDP 5566 传感器上报" in text
    assert "5a5a1101" in text
    assert "output the ProtoForge JSON definition only" in text


def test_system_prompt_states_output_contract():
    assert "ONLY the JSON object" in aigen.SYSTEM_PROMPT
    assert "length_from" in aigen.SYSTEM_PROMPT
    assert "MUST be the very last top-level field" in aigen.SYSTEM_PROMPT


# ---------- JSON 提取 ----------
def test_extract_json_plain():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced_and_prose():
    text = '好的，这是定义：\n```json\n{"a": {"b": "包含 } 花括号的字符串"}, "c": 2}\n```\n请查收'
    assert extract_json(text) == {"a": {"b": "包含 } 花括号的字符串"}, "c": 2}


def test_extract_json_prose_only():
    assert extract_json("抱歉我无法输出") is None


# ---------- 自修复循环 ----------
def test_first_round_valid_no_retry():
    fn, calls = fake_llm([json.dumps(VALID)])
    result = generate_with_repair("x", cfg=AiConfig(), call_fn=fn)
    assert result.ok and result.protocol.name == "aidev"
    assert result.rounds == 1
    assert len(calls) == 1
    assert "Validation errors" not in calls[0][-1]["content"]


def test_validation_errors_fed_back_and_repaired():
    broken = json.dumps({
        "meta": {"name": "a", "long_name": "Too Short Name"},   # 协议名过短 + switch 缺失等
        "bindings": [{"table": "udp.port", "ports": [5566]}],
        "fields": [{"name": "f", "label": "F", "type": "uint8"}],
    })
    fn, calls = fake_llm([broken, json.dumps(VALID)])
    logs = []
    result = generate_with_repair("x", cfg=AiConfig(), call_fn=fn, log=logs.append)
    assert result.ok and result.rounds == 2
    repair_msg = calls[1][-1]["content"]
    assert "failed ProtoForge validation" in repair_msg
    assert "至少 2 个字符" in repair_msg            # 校验错误原文进入修复提示
    assert any("2 个校验错误" in s or "校验错误" in s for s in logs)


def test_max_rounds_exhausted():
    fn, calls = fake_llm([json.dumps(VALID).replace('"aidev"', '"a"')] * 4)
    result = generate_with_repair("x", cfg=AiConfig(), max_rounds=3, call_fn=fn)
    assert not result.ok and result.rounds == 3
    assert len(calls) == 3


def test_no_json_triggers_repair_round():
    fn, calls = fake_llm(["我不会输出 JSON", json.dumps(VALID)])
    result = generate_with_repair("x", cfg=AiConfig(), call_fn=fn)
    assert result.ok and result.rounds == 2


def test_network_error_fails_fast():
    fn, _ = fake_llm([AiError("无法连接 AI 端点")])
    result = generate_with_repair("x", cfg=AiConfig(), call_fn=fn)
    assert not result.ok
    assert "无法连接" in result.error
    assert result.rounds == 1          # 网络/接口错误不重试（换端点是用户的事）


def test_unmappable_structure_reported():
    fn, calls = fake_llm(['{"fields": "不是列表"}'])
    result = generate_with_repair("x", cfg=AiConfig(), max_rounds=1, call_fn=fn)
    assert not result.ok
    assert "不符合 schema" in result.error
    assert "AttributeError" in result.error


# ---------- 设置读写与端点拼装 ----------
def test_settings_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(aigen, "SETTINGS_PATH", str(tmp_path / "ai.json"))
    aigen.save_settings(AiConfig(endpoint="http://x/v1", model="m1", api_key="k1"))
    cfg = aigen.load_settings()
    assert (cfg.endpoint, cfg.model, cfg.api_key) == ("http://x/v1", "m1", "k1")
    # 环境变量优先于设置文件
    monkeypatch.setenv("PROTOFORGE_AI_MODEL", "env-model")
    assert aigen.load_settings().model == "env-model"


def test_endpoint_url_appends_path():
    from protoforge.core.aigen import _endpoint_url
    assert _endpoint_url("http://h:11434/v1") == "http://h:11434/v1/chat/completions"
    assert _endpoint_url("https://h/v1/chat/completions") == "https://h/v1/chat/completions"


# ---------- CLI 子命令（离线：call_fn 不可注入，走 --help 冒烟 + 参数校验） ----------
def test_cli_ai_requires_describe(capsys):
    from protoforge.cli import main
    assert main(["ai"]) == 2
    assert "--describe" in capsys.readouterr().err


def test_cli_ai_help_smoke(capsys):
    from protoforge.cli import build_parser
    with pytest.raises(SystemExit):
        build_parser().parse_args(["ai", "--help"])
    assert "自修复" in capsys.readouterr().out


# ---------- GUI 对话框（offscreen + 注入假 LLM，走真实 QThread） ----------
def _qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_ai_dialog_generates_and_accepts(tmp_path, monkeypatch):
    monkeypatch.setattr(aigen, "SETTINGS_PATH", str(tmp_path / "ai.json"))
    app = _qapp()
    import time
    from PySide6.QtWidgets import QDialog
    from protoforge.app.ai_dialog import AiDialog
    fn, _ = fake_llm([json.dumps(VALID)])
    dlg = AiDialog(caller=fn)
    dlg.desc_edit.setPlainText("测试描述")
    dlg.model_edit.setText("fake-model")
    dlg._generate()
    for _ in range(1000):                      # QThread 异步：轮询主事件循环
        app.processEvents()
        if dlg.result() == QDialog.DialogCode.Accepted:
            break
        time.sleep(0.01)
    assert dlg.protocol is not None and dlg.protocol.name == "aidev"
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert aigen.load_settings().model == "fake-model"   # 成功后设置已保存
    dlg.close()


def test_ai_dialog_empty_description_blocked():
    app = _qapp()
    from protoforge.app.ai_dialog import AiDialog
    fn, calls = fake_llm([json.dumps(VALID)])
    dlg = AiDialog(caller=fn)
    dlg._generate()
    assert "请先填写协议描述" in dlg.log_view.toPlainText()
    assert calls == []            # 未发起调用
    dlg.close()
