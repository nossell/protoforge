# -*- coding: utf-8 -*-
"""共享测试夹具：SMSP 示例协议 + 测试帧构造。"""
import struct
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protoforge.core.jsonio import load_protocol

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


@pytest.fixture
def smsp() -> "Protocol":
    return load_protocol(os.path.join(EXAMPLES, "smsp.json"))


# ---------- SMSP 测试帧构造（与 examples/smsp.json 严格对应） ----------
def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


def smsp_frame(version, msg_type, seq, payload: bytes) -> bytes:
    head = struct.pack(">HBBH", 0x5A5A, (version << 4) | msg_type, seq, len(payload))
    body = head + payload
    return body + struct.pack(">H", crc16_ccitt_false(body))


def telemetry_payload(sensors):
    b = struct.pack(">B", len(sensors))
    for sid, online, batlow, cal, value, quality in sensors:
        flags = (online << 7) | (batlow << 6) | (cal << 5)
        b += struct.pack(">HBhB", sid, flags, value, quality)
    return b


@pytest.fixture(scope="session")
def smsp_frames() -> dict:
    good = smsp_frame(1, 1, 1, telemetry_payload([
        (0x0102, 1, 1, 0, -125, 2),
        (0x0304, 1, 0, 1, 4200, 3),
    ]))
    corrupt = bytearray(good)
    corrupt[-1] ^= 0xFF
    return {
        "telemetry": good,
        "config": smsp_frame(1, 2, 2, struct.pack(">BH3h", 7, 5000, 100, -50, 75)),
        "event": smsp_frame(1, 3, 3, struct.pack(">BI", 3, 1770000000)),
        "bad_crc": bytes(corrupt),
    }
