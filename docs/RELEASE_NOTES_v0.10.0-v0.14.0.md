# ProtoForge v0.10.0 – v0.14.0 五轮功能迭代合并说明

> 每轮独立提交、独立全量回归（145 个测试）。合并发布前供审查。

## v0.10.0 — 字节序与变长字段

- 协议级默认字节序（`meta.byte_order`: big/little）+ 字段级覆盖（`byte_order`）
- 小端数值字段生成 `add_le`（与 Wireshark 惯用法一致）；int16 等有符号同样支持
- `length_from`：string/bytes 按引用字段值动态定长（越界自动钳制并挂 expert 告警）
- 数组 `length_from`：按区域字节长度整除元素尺寸计数（同样带钳制）
- 校验：byte_order/length_from 的类型与作用域检查；size/length_from 互斥
- GUI：字节序下拉、长度来源字段下拉

## v0.11.0 — 校验和家族与终止符字符串

- 校验和字段从单一 CCITT-FALSE 扩展为 5 种：`ccitt_false` / `modbus`（低字节在前）/
  `xmodem` / `sum8`（uint8）/ `sum16`（uint16）；算法与字段类型强校验
- 字符串 `terminated_by`（如 0x00 结尾）：自动扫描终止符，内容显示不含终止符，
  未找到时标注 `(unterminated)`；与 size/length_from 三选一
- GUI：校验和下拉、终止符启用+字节值控件

## v0.12.0 — 嵌套 switch 与 default 分支

- case 内可嵌套 switch（作为该 case 的最后一项，校验强制），两级/三级条件分支正确生成与解析
- `cases` 新增 `"default"` 键：未命中任何 case 时解析兜底字段列表（不再只是标注 unknown）
- default 分支内的引用受同一作用域校验覆盖；JSON 完整往返；GUI 增加 "case default" 节点与创建入口

## v0.13.0 — pcapng、多绑定与多端口

- pcapio 支持 **pcapng**（SHB 字节序自动识别、IDB linktype 校验、EPB 包提取、截断守卫）；
  classic pcap 路径不变
- GUI：绑定表替代单绑定行——同一协议可同时绑定 udp+tcp 多行，增删实时生效
- CLI：`verify --port` 支持逗号分隔多端口（如 `--port 5566,5567`）

## v0.14.0 — 启发式注册与车载示例

- `meta.heuristic` = udp/tcp 时生成启发式解析器：以首字段 const 快速判别，命中才接管报文
  （校验强制：首字段须带 const 且存在对应端口绑定；mock 引擎可验证注册与判别行为）
- 新示例 `examples/automotive_sadp.json`：车载诊断风格协议（虚构教学用），
  覆盖嵌套 default 分支、终止符字符串、MODBUS 校验和的完整用法

## 质量与文档

- 测试 103 → **145 个**（每轮新增回归：字节序/变长 12、校验和/终止符 15、嵌套/default 8、
  pcapng/多绑定 6、启发式/车载 6 等）
- `docs/PROTOCOL_SCHEMA.md` 同步全部新键与校验规则；`docs/USER_MANUAL.md` §13 更新
- 已知限制（未做）：length_from 变长元素数组、case 元素内 switch、pcapng 写入、
  Kaitai 导入、AI 辅助生成
