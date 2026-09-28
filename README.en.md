# ProtoForge

**A generator that turns declarative protocol definitions into complete Wireshark Lua dissectors.**

English (this file) | [简体中文](README.md)

[![CI](https://github.com/nossell/protoforge/actions/workflows/ci.yml/badge.svg)](https://github.com/nossell/protoforge/actions/workflows/ci.yml)

![Main window](docs/screenshots/main_window.png)

Describe your private binary protocol once (GUI table / JSON / CSV), and get a full
Wireshark Lua dissector: bitfields, enums, conditional switch payloads, variable-length
arrays, CRC-16 validation with Expert Info, defensive length checks, and port registration —
plus a built-in test bench that executes the generated Lua *without installing Wireshark*.

```
protocol definition ──▶ validate ──▶ generate Lua ──▶ test bench ──▶ one-click deploy
```

## Quick start

```bash
pip install -r requirements.txt
python -m protoforge selftest        # end-to-end sanity check
python -m protoforge generate examples/smsp.json -o examples/smsp.lua
python -m protoforge verify examples/smsp.lua --pcap examples/demo.pcap --port 5566
python -m protoforge.app.main_window # GUI (PySide6)
```

A worked example lives in `examples/` (SMSP: a fictional smart-agriculture sensor protocol
with bitfields, per-message-type payloads, variable-length arrays and CRC-16), including
`demo.pcap` you can open in Wireshark right after deploying the generated dissector.

## Why

Hand-writing Lua dissectors is the known chore of anyone working with private binary
protocols (IoT, automotive, industrial, telecom). The APIs have version traps, bitfield
masks are easy to get wrong, and every new protocol means doing it again. ProtoForge makes
that a five-minute table-filling exercise and keeps a mock Wireshark engine inside so the
result is verified before it ever touches a real capture.

## Features

- AI-assisted authoring: describe the protocol in plain language (+ optional hex samples),
  get a validated definition JSON — validation errors are fed back to the LLM for
  self-repair. Works with any OpenAI-compatible endpoint (local Ollama, GLM, DeepSeek, ...);
  keys stay on your machine
- Types: uint8-32 / int8-32 / fixed-length and variable-length string / bytes / packed
  bitfields (MSB-first) / enums / big or little endian (protocol default + per-field override)
- Structures: switch payloads (nested, with default branch), fixed-count / count-from /
  region-length arrays, NUL-terminated strings
- Checks: checksum family (CRC-16 CCITT-FALSE / MODBUS / XMODEM / SUM8 / SUM16) with Expert
  Info, magic constants, payload length semantics, short-packet and trailing-byte guards
- Test bench: hex / pcap / pcapng input, real Lua execution via lupa, tree + byte-highlight
  linkage; heuristic registration for protocols without a fixed port
- Deploy: cross-platform plugin directory discovery, install/uninstall, tshark detection
- CLI: `generate / verify / deploy / ai / selftest` (CI-friendly exit codes)

## Compatibility & licensing

- Generated Lua targets Wireshark 4.4+ (Lua 5.3/5.4 with native bitwise ops)
- Generated dissectors are distributed under GPLv2+ per the official Wireshark wiki
  ("Beware the GPL") — the notice is embedded in each generated file's header
- ProtoForge itself is MIT-licensed and does not link Wireshark
- This is an **unofficial project, not affiliated with the Wireshark Foundation**

## Status

v0.15.0 — AI-assisted definition generation (description → validated JSON with a
self-repair loop). Earlier rounds added big/little endian (protocol and field level),
variable-length fields/arrays (`length_from`), a checksum family (CRC-16 CCITT-FALSE /
MODBUS / XMODEM, SUM8/16), NUL-terminated strings, nested switches with a default branch,
pcapng input, multiple udp+tcp bindings, and heuristic registration. 180 tests (unit /
integration / GUI offscreen / real-tshark E2E, including a dedicated suite that drives
every feature round through real tshark). Roadmap and known limitations: see
`docs/USER_MANUAL.md` (section 14).

## Commercial & support

- Issues and PRs are welcome — protocol-definition problems are best reported with a
  minimal JSON snippet and a sample frame (hex).
- If this saves you time at work, starring the repo is the best support.
- Commercial licensing, custom protocol packs (e.g. automotive SOME/IP templates) and
  priority support: open a discussion or reach out via the contact in this section
  <!-- TODO(owner): add sponsor link (afdian/Ko-fi) or contact email before going public -->
