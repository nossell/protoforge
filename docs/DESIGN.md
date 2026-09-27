# ProtoForge 设计说明书（Design Spec）

> 版本 v0.9.0 ｜ 2026-09-27 ｜ 由 spike（一次性可行性原型，已归档）升级为完整产品
> 背景：市场调研报告《Wireshark 解析器生成器-可行性与市场分析》（随项目归档）

## 1. 产品定位

ProtoForge 是一个** Wireshark Lua 解析器（dissector）生成器**：用声明式定义（GUI 表格编辑 /
JSON / CSV）描述私有二进制协议，一键生成完整、正确、带防御性检查的 Lua dissector，
一键部署到 Wireshark 插件目录，并内置测试台（无需抓包即可验证解析效果）。

- **目标用户**：与私有二进制协议打道的工程师（IoT/车载/工业/电信）
- **差异化**（对竞品 shark-dgen/wsgd）：GUI 易用 + 嵌套/条件/数组/bitfield/CRC 全覆盖 +
  内置 mock 测试引擎 + 一键部署
- **运行形态**：桌面 GUI（PySide6）+ CLI（无头/CI）共用 core

## 2. 技术栈与全局约束

| 项 | 决策 | 理由 |
|---|---|---|
| 语言 | Python 3.10+ | 用户舒适区；spike 已验证 |
| GUI | PySide6（LGPL，可闭源分发） | Qt 成熟；offscreen 可自动化测试 |
| core 依赖 | 纯标准库 | core 可独立交付/移植 |
| 测试引擎 | lupa（lua54） | 无 Wireshark 环境下真实执行生成的 Lua |
| 测试 | pytest | 标准 |
| Lua 基线 | Wireshark 4.4+（Lua 5.3/5.4 原生位运算） | 4.4 起移除 5.1/5.2（调研确认） |
| 产品命名 | ProtoForge，**不含 "Wireshark" 字样** | 商标风险（调研法务节） |
| GPL 边界 | 生成物 .lua 头部声明 GPLv2+；生成器/工具本体不链接 Wireshark 可闭源 | 官方 wiki「Beware the GPL」口径 |

## 3. 架构

```
┌────────────────────────────────────────────┐
│ app/ (PySide6 GUI)      cli.py (argparse)  │
│   MainWindow / FieldEditor / PropertyPanel │
│   TestBench / DeployDialog                 │
├────────────────────────────────────────────┤
│ core/（无 GUI 依赖，纯标准库 + lupa）       │
│   model      协议数据模型 + 校验            │
│   jsonio     JSON ↔ model（兼容 spike 格式）│
│   csvimport  CSV ↔ model（平铺子集）        │
│   generator  model → Lua 代码生成           │
│   luaengine  lupa mock Wireshark API 执行器 │
│   pcapio     最小 pcap 读取（Eth/IP/UDP/TCP）│
│   deploy     插件目录发现/安装/卸载/tshark  │
├────────────────────────────────────────────┤
│ tests/  unit + integration + e2e(tshark) +  │
│         GUI offscreen smoke                 │
└────────────────────────────────────────────┘
```

数据流：`定义(GUI/JSON/CSV) → model.validate → generator.generate → .lua 文本
→ { luaengine.dissect（测试台/CI） | deploy.install（真实 Wireshark） }`

## 4. v1.0 功能范围

### 4.1 Must（本次交付）
1. **类型系统**：uint8/16/24/32、int8/16/32、定长 string、定长 bytes、连续 bitfield 自动打包
   （8/16/24/32 bit 边界）、enum（值→名）、display dec/hex、const 幻数校验
2. **结构**：switch（按字段值条件分支，多 case）、array（定长 count / 变长 count_from）、
   任意嵌套（case 内可再嵌 array/子结构）
3. **校验**：CRC-16/CCITT-FALSE（自动计算+比对+expert 报错）、payloadLen 语义检查、
   过短包/尾随字节防御、幻数错误告警
4. **绑定**：udp.port / tcp.port，多端口、多表
5. **IO**：JSON 加载/保存（兼容 spike smsp.json）；CSV 导入/导出（平铺字段子集，enum 用
   `1=A;2=B` 语法）；Lua 导出
6. **测试台**：hex 粘贴 / pcap 文件（自动按端口提取载荷）→ lupa 真实执行生成的 Lua →
   解析树 + hex 高亮联动
7. **部署**：跨平台插件目录发现、安装/卸载、打开插件目录、tshark 版本检测
8. **CLI**：`generate` / `verify`（--hex/--pcap）/ `deploy` / `selftest`
9. **测试**：全层测试用例（见 §6）
10. **文档**：详尽中文使用手册 + 协议定义 Schema 参考 + README

### 4.2 Won't（明确不做，手册声明）
AI 辅助生成、Kaitai .ksy 导入、变长元素数组（length_from）、heuristic 解绑、协议样例库、
大版本升级管理。理由：YAGNI，v1 先验证核心价值闭环。

## 5. 关键设计决策记录

| # | 决策 | 备选与取舍 |
|---|---|---|
| D1 | GUI 用 PySide6 而非 Tauri | 免 Rust 工具链；Python 是用户舒适区；offscreen 测试成熟 |
| D2 | bitfield 只支持连续打包到字节边界 | Wireshark mask 语义天然如此；跨边界拆组留给 v2 |
| D3 | crc 字段约定必须是最后一个字段 | 覆盖域明确（帧首到此字段前）；spike 已验证该模型 |
| D4 | switch.on 的字段必须在 switch 之前声明 | 生成器用 captured local 保证正确性；模型校验强制 |
| D5 | CSV 只支持平铺字段 | 嵌套结构 CSV 表达力不足；复杂协议用 JSON（手册引导） |
| D6 | mock 引擎做进产品而非仅测试工具 | 「无 Wireshark 也能验证」是卖点；CI 可跑 |
| D7 | pcap 只读 classic pcap linktype 1 | 覆盖 demo/导出场景；pcapng 留 v2 |
| D8 | Lua 生成物头部强制 GPLv2+ 声明 | 法务调研结论 |

## 6. 测试策略

| 层 | 文件 | 覆盖 |
|---|---|---|
| 单元 | test_model.py | 校验规则全部错误分支（重名/位域不成界/on 引用缺失/count_from 引用/crc 位置/非法类型/非法标识符） |
| 单元 | test_generator.py | 每种类型的生成代码关键行断言；位域掩码；多绑定；string/bytes；错误抛出 |
| 单元 | test_csvimport.py | 往返、enum 语法、不支持结构的拒绝、注释/空行 |
| 单元 | test_pcapio.py | 自产自读（构造 pcap→读回断言字段）、端口过滤、坏文件 |
| 单元 | test_deploy.py | 安装/卸载（tmp_path）、目录发现（monkeypatch env）、tshark 检测 |
| 集成 | test_luaengine.py | JSON→Lua→mock 执行→树断言（spike 4 场景全部进用例 + string/bytes + tcp + 过短包 + 尾随字节 + 幻数错误） |
| 集成 | test_cli.py | generate/verify/deploy/selftest 子命令（tmp 目录） |
| E2E | test_e2e_tshark.py | tshark 存在则：生成→pcap→tshark -V 输出含关键字（CRC correct/incorrect、bitfield 行） |
| GUI | test_gui_smoke.py | offscreen：加载示例、树节点数、生成按钮、测试台运行、属性面板联动 |

## 7. 交付物清单

产品仓库 `protoforge/`：源码（protoforge 包）、tests、examples（SMSP json+csv+pcap
+ 构造脚本）、docs（DESIGN/PLAN/USER_MANUAL/PROTOCOL_SCHEMA）、README、启动器 .bat（CRLF）。
