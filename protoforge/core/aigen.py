# -*- coding: utf-8 -*-
"""AI 辅助生成协议定义：自然语言描述 (+ 可选 hex 样本) → ProtoForge JSON。

设计要点：
- 走 OpenAI 兼容 /chat/completions（stdlib urllib，无新增依赖）——
  本地 Ollama（http://127.0.0.1:11434/v1）、GLM、DeepSeek、OpenAI 均可
- 自修复循环：LLM 输出 → 解析 JSON → validate() → 把校验错误回喂 → 重试（默认 3 轮）
- 密钥只存本机 ~/.protoforge/ai.json（明文，权限尽量收紧），不发遥测；
  提示词只会包含用户主动粘贴的协议描述与样本
- 测试可注入 call_fn 假 LLM，全程离线
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field as dc_field
from typing import Callable, Optional

from .jsonio import load_protocol_dict
from .model import Protocol, validate

DEFAULT_ENDPOINT = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "qwen3:4b"
SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".protoforge", "ai.json")
MAX_DESC_CHARS = 12000        # 防提示词失控
MAX_SAMPLE_CHARS = 4000


class AiError(RuntimeError):
    """AI 生成失败（网络/接口/解析）。"""


@dataclass
class AiConfig:
    endpoint: str = DEFAULT_ENDPOINT
    model: str = DEFAULT_MODEL
    api_key: str = ""
    temperature: float = 0.2
    timeout: int = 120


@dataclass
class AiResult:
    ok: bool
    protocol: Optional[Protocol] = None
    rounds: int = 0
    log: list = dc_field(default_factory=list)   # 每轮一行摘要
    error: Optional[str] = None


# ---------------- 设置文件 ----------------
def load_settings() -> AiConfig:
    cfg = AiConfig()
    if os.path.isfile(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            cfg.endpoint = d.get("endpoint") or cfg.endpoint
            cfg.model = d.get("model") or cfg.model
            cfg.api_key = d.get("api_key") or ""
        except (OSError, json.JSONDecodeError):
            pass
    cfg.endpoint = os.environ.get("PROTOFORGE_AI_ENDPOINT", cfg.endpoint)
    cfg.model = os.environ.get("PROTOFORGE_AI_MODEL", cfg.model)
    cfg.api_key = os.environ.get("PROTOFORGE_AI_API_KEY", cfg.api_key)
    return cfg


def save_settings(cfg: AiConfig) -> None:
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    data = {"endpoint": cfg.endpoint, "model": cfg.model, "api_key": cfg.api_key}
    with open(SETTINGS_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    try:
        os.chmod(SETTINGS_PATH, 0o600)
    except OSError:
        pass  # Windows 上 chmod 语义不同，失败可接受


# ---------------- 提示词 ----------------
SYSTEM_PROMPT = """You are a protocol-definition author for ProtoForge, a tool that turns \
declarative JSON definitions into Wireshark Lua dissectors. Your job: read a human \
description of a binary protocol and emit ONE JSON object that ProtoForge can validate \
and compile.

Output contract (strict):
- Output ONLY the JSON object. No prose, no markdown fences, no comments.
- All keys and constraints below are enforced by a validator; anything violating them \
will be rejected and shown back to you for fixing.

Schema:
{
  "meta": {
    "name": "<filter name, 2+ chars, [A-Za-z_][A-Za-z0-9_]*>",
    "long_name": "<human name>",
    "desc": "<optional>",
    "byte_order": "big" | "little",          // optional, default big
    "heuristic": "udp" | "tcp",              // optional; requires first field to have const
    "desegment": true,                       // optional (v1.1): request TCP reassembly;
                                             //   requires a tcp.port binding + length_check
    "length_check": {"field": "<top-level numeric field>"}   // optional payload-length check
  },
  "bindings": [{"table": "udp.port" | "tcp.port", "ports": [int, ...]}, ...],  // required >=1
  "fields": [ <field>, ... ]
}

Field keys (common): "name" (unique, [A-Za-z_][A-Za-z0-9_]*), "label" (display, any text),
"type", "display": "dec"|"hex", "enum": {"1": "Name", ...} (string int keys),
"const": "<int like \\"0x5A5A\\">" (numeric/bitfield fields only), "byte_order": field override.

Types:
- uint8/uint16/uint24/uint32, int8/int16/int32
- "uint" with "width": 1..7  = bitfield. Consecutive bitfields pack MSB-first; each group
  must total exactly 8/16/24/32 bits.
- "string" / "bytes": exactly ONE of "size": int>=1, "length_from": "<prior numeric field>",
  "terminated_by": 0..255 (string only)
- "switch": {"on": "<prior numeric field>", "cases": {"<int>": [fields...], "default": [fields?]}}
  The switch MUST be the LAST field of its list. Max ONE top-level switch. A top-level
  count/count_from array (bare TLV chain) acts as the same kind of boundary; after such a
  boundary only a trailing crc field may follow. Cases may contain a nested switch as
  their last field.
- "array": exactly ONE of "count": int 0..65535, "count_from": "<prior numeric field>",
  "length_from": "<prior numeric field>"; plus "element": [fields...].
  count/count_from arrays MAY have variable elements - the classic TLV pattern is
  element = [type uint8 (with enum), len uint8, value switch on type whose cases use
  length_from=len]. Inside an element the switch must also be the last field.
  length_from arrays still require ALL-FIXED elements (static size > 0).
- checksum field: "crc16": "ccitt_false"|"modbus"|"xmodem"|"sum8"|"sum16", type uint16
  (uint8 for sum8), MUST be the very last top-level field. modbus reads little-endian on wire.

Rules the validator enforces (incomplete output = rejection):
1. Every referenced field (switch.on, count_from, length_from, length_check.field) must be
   declared EARLIER in the same visible scope (top level or the same case); cross-case refs invalid.
2. Field names unique across the whole tree. Protocol name at least 2 characters.
3. const must be non-negative. terminated_by only for string, 0..255.
4. Bindings required; ports 1..65535.
5. Keep labels short and human-readable. Choose display hex for magic/IDs, dec for counters.

Example of a valid definition:
{"meta": {"name": "smsp", "long_name": "SmartMesh Sensor Protocol", "byte_order": "big",
  "length_check": {"field": "payloadLen"}},
 "bindings": [{"table": "udp.port", "ports": [5566]}],
 "fields": [
   {"name": "magic", "label": "Magic", "type": "uint16", "display": "hex", "const": "0x5A5A"},
   {"name": "ver", "label": "Version", "type": "uint", "width": 4},
   {"name": "msgType", "label": "Msg Type", "type": "uint", "width": 4,
    "enum": {"1": "Telemetry", "2": "Config", "3": "Event"}},
   {"name": "seqNum", "label": "Seq", "type": "uint8"},
   {"name": "payloadLen", "label": "Payload Len", "type": "uint16"},
   {"name": "payload", "label": "Payload", "type": "switch", "on": "msgType", "cases": {
      "1": [{"name": "count", "label": "Count", "type": "uint8"},
            {"name": "sensors", "label": "Sensor", "type": "array", "count_from": "count",
             "element": [{"name": "sid", "label": "ID", "type": "uint16", "display": "hex"},
                          {"name": "flags", "label": "Flags", "type": "uint", "width": 3},
                          {"name": "value", "label": "Value", "type": "int16"}]}],
      "2": [{"name": "interval", "label": "Interval", "type": "uint32"}],
      "default": [{"name": "raw", "label": "Raw", "type": "bytes", "length_from": "payloadLen"}]}},
   {"name": "crc", "label": "CRC-16", "type": "uint16", "display": "hex", "crc16": "ccitt_false"}]}
"""


def build_user_prompt(description: str, samples: str = "") -> str:
    desc = description.strip()[:MAX_DESC_CHARS]
    out = f"Protocol description:\n{desc}\n"
    if samples:
        samp = samples.strip()[:MAX_SAMPLE_CHARS]
        out += (f"\nHex sample frame(s) (for layout hints; bytes may be little- or "
                f"big-endian, judge from the description):\n{samp}\n")
    out += "\nNow output the ProtoForge JSON definition only."
    return out


REPAIR_INSTRUCTION = (
    "Your previous JSON failed ProtoForge validation. Fix ALL issues and output the "
    "complete corrected JSON object only (no prose, no fences).\nValidation errors:\n"
)


# ---------------- LLM 调用 ----------------
def _endpoint_url(endpoint: str) -> str:
    ep = endpoint.rstrip("/")
    return ep if ep.endswith("/chat/completions") else ep + "/chat/completions"


def call_chat(cfg: AiConfig, messages: list) -> str:
    """调 OpenAI 兼容 /chat/completions，返回首个 choice 的文本内容。"""
    body = json.dumps({
        "model": cfg.model,
        "messages": messages,
        "temperature": cfg.temperature,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    req = urllib.request.Request(_endpoint_url(cfg.endpoint), data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        excerpt = ""
        try:
            excerpt = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise AiError(f"接口返回 HTTP {e.code}：{excerpt or e.reason}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise AiError(f"无法连接 AI 端点 {cfg.endpoint}：{e}") from e
    except json.JSONDecodeError as e:
        raise AiError(f"接口响应不是 JSON：{e}") from e
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise AiError(f"接口响应缺少 choices[0].message.content：{data!r:.300}") from e
    if not isinstance(content, str) or not content.strip():
        raise AiError("接口返回了空内容")
    return content


# ---------------- 输出解析与自修复循环 ----------------
def extract_json(text: str) -> Optional[dict]:
    """从 LLM 输出中提取第一个可解析的 JSON 对象（容忍 ```json 围栏与前后闲话）。"""
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = []
    if m:
        candidates.append(m.group(1))
    start = text.find("{")
    if start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start:i + 1])
                    break
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def generate_with_repair(description: str, samples: str = "", cfg: Optional[AiConfig] = None,
                         max_rounds: int = 3, call_fn: Optional[Callable] = None,
                         log: Optional[Callable[[str], None]] = None) -> AiResult:
    """生成协议定义；validate 报错回喂 LLM 重试。call_fn(messages)->str 供测试注入。"""
    cfg = cfg or load_settings()
    say = log or (lambda s: None)
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(description, samples)}]
    result = AiResult(ok=False)

    for rnd in range(1, max_rounds + 1):
        result.rounds = rnd
        say(f"第 {rnd}/{max_rounds} 轮：请求 {cfg.model} @ {cfg.endpoint} …")
        try:
            content = (call_fn or call_chat)(cfg, messages)
        except AiError as e:
            result.error = str(e)
            say(f"[失败] {e}")
            return result
        obj = extract_json(content)
        if obj is None:
            result.error = "输出中找不到 JSON 对象（小模型上下文过短可能截断输出，可换更大上下文的模型）"
            say(f"[失败] {result.error}")
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": REPAIR_INSTRUCTION + "- 输出必须是单个 JSON 对象"})
            continue
        try:
            p = load_protocol_dict(obj)
        except Exception as e:  # LLM 给出的结构无法映射（缺 meta/fields 等）
            result.error = f"JSON 结构不符合 schema：{type(e).__name__}: {e}"
            say(f"[失败] {result.error}")
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": REPAIR_INSTRUCTION + f"- {result.error}"})
            continue
        errs = validate(p)
        if not errs:
            result.ok = True
            result.protocol = p
            say(f"[OK] 第 {rnd} 轮通过校验：{p.name}（{len(p.fields)} 个顶层字段）")
            return result
        result.error = "；".join(errs)
        say(f"[重试] 第 {rnd} 轮 {len(errs)} 个校验错误：{errs[0]}{'…' if len(errs) > 1 else ''}")
        messages.append({"role": "assistant", "content": content})
        messages.append({"role": "user",
                         "content": REPAIR_INSTRUCTION + "\n".join(f"- {e}" for e in errs)})
    say("[失败] 已达最大轮数仍校验不过")
    return result
