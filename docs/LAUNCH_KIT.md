# Launch Kit（发布物料包）

> 所有草稿可直接粘贴；仓库地址 `https://github.com/nossell/protoforge` 已上线，链接可直接使用。
> 发布顺序建议：仓库已公开（v0.9.0）→ 本次 Release v0.14.0 → 3 天后 r/wireshark → 1 周后 Show HN / V2EX → 持续答题。

## 0. 仓库元信息（创建时填）

- **Name**: `protoforge`
- **Description** (≤350 chars): `Generate complete Wireshark Lua dissectors from declarative protocol definitions — bitfields, conditional payloads, variable arrays, CRC-16, built-in test bench. GUI + CLI.`
- **Topics**: `wireshark` `lua` `dissector` `packet-analyzer` `protocol` `code-generation` `pyside6` `networking` `iot` `automotive`
- **Website**: 留空或 landing 页地址

## 1. GitHub Release v0.9.0 notes（EN）

```
First public release.

Highlights
- Declarative protocol definitions (JSON/CSV/GUI) → complete Wireshark Lua dissectors
- Bitfield packing (MSB-first), enums, hex/dec display, magic-constant checks
- Conditional payloads (switch), fixed and variable-length arrays
- CRC-16/CCITT-FALSE validation with Wireshark Expert Info integration
- Defensive checks: short packets, trailing bytes, length semantics
- Built-in test bench: lupa-based engine executes the generated Lua without Wireshark
  (hex or pcap input, parse tree + byte-highlight)
- One-click deploy to the per-user Wireshark plugin directory
- CLI: generate / verify / deploy / selftest

Quality
- 75 tests: unit, integration, GUI offscreen, and E2E against real tshark 4.6.8
- Generated output targets Wireshark 4.4+ (Lua 5.3/5.4)

Known limitations (v1)
- Big-endian parsing only; no length_from variable elements; classic pcap only in the
  test bench. See docs/USER_MANUAL.md §13 for the roadmap.
```

## 2. r/wireshark 帖子（EN）

**Title**: `I built a free tool that generates Lua dissectors from a protocol definition (bitfields/switch/arrays/CRC) — looking for feedback`

```
Like many of you I have to write Lua dissectors for private binary protocols, and I kept
making the same mistakes: bitfield masks, offset tracking in loops, and the odd API trap
(ByteArray:get_index vs get, tree:add refusing string values...).

So over the last weeks I built ProtoForge, an open-source (MIT) generator: you describe
your protocol once in JSON (or a small GUI), and it emits a complete dissector — nested
trees, conditional switch payloads, variable-length arrays, CRC-16 with Expert Info,
length guards, Info column, port registration. There's also a built-in test bench that
runs the generated Lua in a mock Wireshark engine, so you can check the parse tree from
a hex string without touching a real capture.

It targets Wireshark 4.4+ and comes with a worked example (JSON → dissector → demo.pcap)
plus a full test suite including real-tshark E2E.

Repo: https://github.com/nossell/protoforge
Docs: https://github.com/nossell/protoforge/blob/main/docs/USER_MANUAL.md

It's early (v0.9), so I'd love feedback on the definition format — especially from folks
who dissect automotive or IoT protocols: what's missing that would make you actually use
it instead of hand-writing?
```

## 3. Show HN（EN）

**Title**: `Show HN: ProtoForge – Generate Wireshark dissectors from a protocol definition`

```
Hi HN! Wireshark ships dissectors for thousands of standard protocols, but if you work
with private binary protocols (IoT firmware, automotive, industrial), your traffic shows
up as opaque hex until someone hand-writes a Lua dissector — a fiddly ~200-line script
full of bitfield masks, offset bookkeeping and version-specific API traps.

ProtoForge (MIT) turns a declarative definition (JSON/CSV/GUI table) into that complete
script: nested fields, conditional payloads, variable-length arrays, CRC-16 validation
wired into Wireshark's expert system. It also embeds a mock Wireshark engine (lupa) that
really executes the generated Lua, so you verify the parse tree from a hex string without
installing anything, and a CLI for CI.

An end-to-end example is in the repo: a fictional sensor protocol, its definition, the
generated dissector, and a pcap you can dissect after a one-command install.
Repo: https://github.com/nossell/protoforge  |  Docs: https://github.com/nossell/protoforge/blob/main/docs/USER_MANUAL.md

Happy to answer questions about the generator design and the mock-engine approach.
```

## 4. V2EX / 知乎（中文，二选一改写）

**标题**: `开源了个小工具：把私有二进制协议的 Wireshark 解析器从手写 200 行 Lua 变成填一张表`

```
做 IoT/车载/工业的兄弟应该都干过这个活：设备间的私有协议抓包后全是 hex，想让 Wireshark
认出来就得手写 Lua dissector——位域掩码、偏移推进、CRC 计算加 expert 告警，一两百行，
换个协议再来一遍。

写了个开源工具 ProtoForge（MIT）：协议定义填成 JSON（或用 GUI 填表），一键生成完整
dissector，位域/枚举/条件分支/变长数组/CRC 全支持，还内置了一个不用装 Wireshark 的
测试引擎（lupa），粘段 hex 就能看解析树。带 CLI，CI 里也能跑。

仓库：https://github.com/nossell/protoforge
示例协议 + demo.pcap 在 examples/ 下，装完用 Wireshark 打开就能看效果。

求反馈，尤其想听车载 SOME/IP / DoIP 方向的意见：定义格式还缺什么？
```

## 5. ask.wireshark.org / StackOverflow 答题模板（持续使用）

在搜"how to write dissector / lua dissector for custom protocol"的老问题下答题：
先正常、具体地回答问题（这段必须真答，不能纯广告），结尾一句：
`If you do this often, I maintain an open-source generator that covers this pattern
(bitfields/switch/arrays/CRC): https://github.com/nossell/protoforge`

## 6. 发布后 30 天节奏

- [ ] 第 1 周：盯 issue，48h 内首响（口碑关键）
- [ ] 每篇社区帖发出后 72h 查 star/clone 曲线（GitHub Insights → Traffic）
- [ ] 收集"定义格式缺什么"的反馈 → 进 roadmap，做 v0.9.x 小版本保持活跃
- [ ] 若某类协议被反复提到（预期：SOME/IP）→ 做"协议模板包"作为 Pro 意向的钩子

## 7. README 赞助区模板（拿到收款码图片后启用）

图片放 `docs/assets/donate_alipay.png`（建议用支付宝"赞赏码"而非"收款码"：
赞赏码显示昵称+可选金额，收款码会露出真实姓名），然后把下面这段替换进
README.md 与 README.en.md 的「商业与支持」节：

```markdown
## 支持作者 / Support

如果 ProtoForge 帮你省了时间，欢迎请作者喝杯咖啡 ☕

<div align="center">
  <img src="docs/assets/donate_alipay.png" alt="支付宝赞赏 / Alipay" width="220">
</div>

国际用户 / International: [Ko-fi or afdian link]   <!-- 二选一或都留 -->
```

注意：二维码是唯一无法被隐私扫描工具发现的个人信息，发布前务必确认
图中只暴露"赞赏昵称"，不暴露真名和手机号。
