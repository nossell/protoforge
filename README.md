# ProtoForge

**Wireshark Lua 解析器（dissector）生成器** —— 声明式定义私有二进制协议，一键生成完整 Lua、
一键部署进 Wireshark、内置测试台免抓包验证。

[English](README.en.md) | 简体中文（本文件）

[![CI](https://github.com/nossell/protoforge/actions/workflows/ci.yml/badge.svg)](https://github.com/nossell/protoforge/actions/workflows/ci.yml)

![主界面](docs/screenshots/main_window.png)

```
协议定义（GUI / JSON / CSV）──▶ 校验 ──▶ 生成 Lua ──▶ 测试台验证 ──▶ 一键部署
```

## 快速开始

```bash
pip install -r requirements.txt
ProtoForge.bat                  # 启动 GUI（或 python -m protoforge.app.main_window）
python -m protoforge selftest   # 自检
run_tests.bat                   # 全量测试（含真实 tshark E2E）
```

五分钟上手流程见 [docs/USER_MANUAL.md](docs/USER_MANUAL.md) 第 3 节（示例协议 + demo.pcap 全套在 `examples/`）。

## 功能

- **AI 辅助生成**：自然语言描述（+ 可选 hex 样本）→ 协议定义 JSON，校验错误自动回喂 LLM
  自修复；OpenAI 兼容端点（本地 Ollama / GLM / DeepSeek…），key 只存本机
- **类型系统**：uint8-32 / int8-32 / 定长与变长 string / bytes / 连续位域自动打包（MSB 分配）/ 枚举 / hex·dec 显示
- **字节序**：协议级默认 + 字段级覆盖（大端 / 小端，小端生成 `add_le`）
- **变长能力**：`length_from` 变长 string/bytes/数组（带越界钳制与告警）；终止符字符串（如 0x00 结尾）
- **结构**：switch 条件分支（含 default 兜底、嵌套 switch）、定长/按字段计数/按字节长度数组
- **校验和**：CRC-16/CCITT-FALSE、MODBUS、XMODEM、SUM8、SUM16，自动计算并与 Wireshark Expert Info 联动
- **防御检查**：幻数检查、payloadLen 语义检查、过短包/尾随字节防御
- **测试台**：hex / pcap / pcapng 输入 → 内置 lupa 引擎**真实执行生成的 Lua** → 解析树 + 字节高亮联动
- **部署**：跨平台插件目录发现、安装/卸载、tshark 版本检测、UDP/TCP 启发式注册
- **CLI**：`generate / verify / deploy / ai / selftest`（CI 友好，退出码规范，多端口提取）

## 目录

```
protoforge/            Python 包
  core/                纯逻辑层（model/generator/jsonio/csvimport/luaengine/pcapio/deploy/aigen）
  app/                 PySide6 GUI
  cli.py               命令行入口
tests/                 180 用例：单元 / 集成 / GUI offscreen / 真实 tshark E2E
examples/              SMSP 与车载 SADP 示例（json/csv/pcap/构造脚本）
docs/                  DESIGN.md / PLAN.md / USER_MANUAL.md / PROTOCOL_SCHEMA.md / screenshots/
tools/make_screens.py  手册截图生成
```

## 兼容性与授权

- 生成的 Lua 面向 **Wireshark 4.4+**（Lua 5.3/5.4 原生位运算；4.4.0 起移除 5.1/5.2）
- 生成物按官方口径以 **GPLv2+** 分发；本工具不链接 Wireshark，可独立/闭源分发
- 产品命名不含 "Wireshark"；**本项目为非官方项目，与 Wireshark 基金会无关联**
  （商标规避与许可依据详见 `docs/USER_MANUAL.md` 第 12 节）

## 状态

v0.15.0（2026-09-29）——新增 **AI 辅助生成**（描述→定义 JSON，自修复校验循环）。此前五轮迭代：
字节序、变长字段、校验和家族、终止符字符串、嵌套 switch/default、pcapng、多绑定、启发式注册。
路线图见手册第 14 节。

## 商业与支持

- 欢迎提 issue/PR；反馈协议定义问题时请附最小 JSON 片段和示例帧 hex
- 如果它帮你省了时间，给个 star 就是最好的支持
- 商业授权、定制协议模板包（如车载 SOME/IP）、优先支持：通过本仓库 Issues 联系
  （赞赏/赞助入口将在二维码就绪后加入本节）
- 发布物料（Release notes / 社区帖 / 答题模板）见 `docs/LAUNCH_KIT.md`
