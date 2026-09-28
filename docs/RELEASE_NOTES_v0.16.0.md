# ProtoForge v0.16.0 — TLV 变长元素数组、TCP 解段、抓包导出（schema v1.1）

> 发布日期：2026-09-29 ｜ 上一个版本：v0.15.0

## TLV 变长元素数组（schema v1.1）

真实二进制协议里最普遍的形态就是 TLV（`type/length/value`），此前无法表达，本次解锁：

- `count` / `count_from` 数组的**元素内允许变长字段与 switch/array**：
  `element = [type(uint8+enum), len(uint8), value(switch on type，各 case 用 length_from=len)]`
- 元素局部作用域：元素内字段可引用元素内更早声明的字段（也可引用外层），作用域校验递归覆盖
- 元素内 switch 同样必须为末项；元素内可再嵌 count 数组（二级 TLV）
- 变长元素的解析树容器用零长节点 + `TreeItem:set_len` 回设实际范围（真机验证）
- **顶层裸 TLV 链**：运行时边界从 switch 推广到 count/count_from 数组——
  `头部字段 + TLV 数组 + CRC` 直接表达，无需再包一层假 switch；边界后仅允许 crc 收尾
- `length_from` 数组语义不变（区域字节 ÷ 元素尺寸），仍要求全定长元素（TLV 请用 count_from）

## TCP 解段（desegment）

- `meta.desegment: true`（要求 tcp.port 绑定 + `length_check` + 长度字段前可静态定位）：
  生成的 dissector 在帧不完整时按长度字段请求 Wireshark 重组
- 真机验证：单 PDU 跨两个 TCP 分段自动拼装并正确解析（`[2 Reassembled TCP Segments]`），
  为 SOME/IP 等跑在 TCP 上的协议铺路
- 测试台/CLI：绑定 tcp.port 的协议按流重组提取载荷（同向分段按序号拼接，反向独立）
- 实现备注：真机 Lua Pinfo 无法区分传输层（`pinfo.ip` 不存在），采用官方惯例无条件请求，
  UDP 侧会忽略 desegment 请求（截断的 UDP 样本显示为 Data）

## 抓包写出（复现链路闭环）

- `pcapio.write_capture`：classic pcap 与 pcapng（小端）写出，统一封装 Ethernet+IPv4+UDP
- CLI `verify --export repro.pcap`（按扩展名定格式）：把测试帧写成抓包文件，直接附 issue
  ——与 issue 模板"必附样本帧"呼应

## 质量与文档

- 测试 180 → **194 个**：新增 `tests/test_v16_tlv_tcp.py`（TLV 校验/生成/mock 解析、
  解段规则与请求语义、写读往返、流重组、CLI 导出）；
  真机 E2E 高级套件扩至 TLV 与分段重组（`[2 Reassembled TCP Segments]` 断言）
- 新示例 `examples/tlv_demo.json`（TLV 三形态：u32 / 定长字符串 / default raw）
- AI 提示词同步 v1.1（TLV 形态与 desegment 键，AI 可直接起草 TLV 协议定义）
- 文档：PROTOCOL_SCHEMA v1.1、手册路线图、DESIGN §4.5
- 审查注记：`static_size()` 对变长字段按 0 宽容计算，不能用于定长判定——新增
  `is_fixed_layout()`，该误判（容器范围错 → 真机 hex 高亮错位）在合并前被单测逮住

## 升级

无破坏性变更；v0.15 及之前的定义文件完全兼容。无新增依赖。
（仍暂缓：Kaitai .ksy 导入、位序自定义——等真实用户反馈。）
