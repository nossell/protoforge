# ProtoForge v0.9.0

First public release.

## Highlights

- Declarative protocol definitions (JSON / CSV / GUI) → complete Wireshark Lua dissectors
- Bitfield packing (MSB-first), enums, hex/dec display, magic-constant checks
- Conditional payloads (switch), fixed and variable-length arrays
- CRC-16/CCITT-FALSE validation integrated with Wireshark Expert Info
- Defensive checks: short packets, trailing bytes, payload-length semantics
- Built-in test bench: a lupa-based mock Wireshark engine executes the generated Lua
  without installing Wireshark (hex or pcap input, parse tree + byte highlight)
- One-click deploy to the per-user Wireshark plugin directory
- CLI: `generate` / `verify` / `deploy` / `selftest`

## Quality

- 103 tests: unit, integration, GUI offscreen, and E2E against real tshark 4.6.8
  (E2E builds its own capture with a unique protocol name to avoid plugin conflicts)
- Free-text fields (labels, long names, enum values) are Lua-escaped; generation is
  safe against malformed or hostile definitions
- Reference fields (`switch.on`, `count_from`, `length_check`) are scope- and
  type-checked at definition time

## Compatibility & licensing

- Generated code targets Wireshark 4.4+ (Lua 5.3/5.4, native bitwise ops)
- Generated dissectors are distributed under GPLv2+ (Wireshark wiki "Beware the GPL");
  the notice is embedded in every generated file's header
- ProtoForge itself is MIT-licensed and does not link Wireshark
- Unofficial project; not affiliated with the Wireshark Foundation

## Known limitations (v1)

- Big-endian parsing only; no `length_from` variable elements; classic pcap only in the
  test bench; one top-level switch per protocol. See `docs/USER_MANUAL.md` section 13.
