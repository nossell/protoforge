#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成示例抓包 demo.pcap（4 帧 SMSP：Telemetry/Config/Event/损坏CRC）。

用法：python examples/make_demo.py
输出：examples/demo.pcap（供 GUI 测试台、CLI verify --pcap、tshark E2E 使用）
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protoforge.core.pcapio import build_udp_packet as wrap_udp  # noqa: E402
from tests.conftest import crc16_ccitt_false, smsp_frame, telemetry_payload  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.pcap")


def main():
    good = smsp_frame(1, 1, 1, telemetry_payload([
        (0x0102, 1, 1, 0, -125, 2),
        (0x0304, 1, 0, 1, 4200, 3),
    ]))
    corrupt = bytearray(good)
    corrupt[-1] ^= 0xFF
    frames = [
        good,
        smsp_frame(1, 2, 2, struct.pack(">BH3h", 7, 5000, 100, -50, 75)),
        smsp_frame(1, 3, 3, struct.pack(">BI", 3, 1770000000)),
        bytes(corrupt),
    ]
    with open(OUT, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            pkt = wrap_udp(f, 40000 + i, 5566)
            fh.write(struct.pack("<IIII", 1770000000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)
    print(f"[OK] {OUT} ({len(frames)} 帧)")


if __name__ == "__main__":
    main()
