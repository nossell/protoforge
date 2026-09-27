# ProtoForge 协议定义 Schema 参考

> 适用版本 v0.9.0。定义文件是 JSON（`.json`）或 CSV（平铺子集，见手册第 7 节）。
> 本文档是权威格式说明；示例见 `examples/smsp.json`。

## 顶层结构

```json
{
  "meta":     { ... },      // 协议元信息
  "bindings": [ { ... } ],  // 端口绑定（至少 1 个）
  "fields":   [ { ... } ]   // 顶层字段序列（有序）
}
```

## meta

| 键 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `name` | string | ✓ | 协议短名：Lua `Proto` 名与过滤器前缀；`[A-Za-z_][A-Za-z0-9_]*` |
| `long_name` | string | — | 显示名；缺省 = name 大写 |
| `desc` | string | — | 备注（不参与生成） |
| `length_check` | object | — | `{ "field": "<长度字段名>", "region": "payload" }`：长度字段值 ≠ 帧长−头−尾 时挂 WARN |

## bindings[]

| 键 | 类型 | 说明 |
|---|---|---|
| `table` | string | `udp.port` 或 `tcp.port` |
| `ports` | int[] | 1-65535，可多个；多绑定（同时 udp+tcp）由数组多个元素表达，CLI/生成器支持，GUI 编辑仅第一个 |

## fields[]（Field 对象）

所有字段共有的键：

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `name` | string | 必填 | 全树唯一标识符 |
| `label` | string | =name | 解析树显示名（可中文） |
| `type` | string | `uint8` | 见类型表 |
| `display` | string | `dec` | `dec` / `hex` |
| `enum` | object | — | `{ "1": "Telemetry", ... }`，键为整数字符串；显示为 `1 (Telemetry)` |
| `const` | string | — | 幻数校验，如 `"0x5A5A"`；不匹配挂 WARN expert |

按类型附加的键：

| type | 附加键 | 约束 |
|---|---|---|
| `uint8/16/24/32`, `int8/16/32` | — | 大端 |
| `uint`（位域） | `width`: 1-7 | 连续位域自动打包；每组总和必须 = 8/16/24/32 |
| `string` | `size`: ≥1 | 定长 |
| `bytes` | `size`: ≥1 | 定长，hex 显示 |
| `switch` | `on`: 字段名；`cases`: `{"1": [Field...], ...}` | `on` 字段须在 switch 之前声明；case 键为整数字符串；未匹配值显示 unknown |
| `array` | `count`: int 或 `count_from`: 字段名（二选一）；`element`: [Field...] | 元素须全为定长字段；`count_from` 字段须在 array 之前声明 |
| `uint16` + | `crc16`: `"ccitt_false"` | 必须是**最后一个顶层字段**；覆盖帧首至该字段前 |

## 校验规则清单（validate）

1. 协议名匹配 `^[A-Za-z_][A-Za-z0-9_]*$` 且**至少 2 个字符**（Wireshark 过滤名下限）；字段名同规则
2. 字段名全树唯一
3. `type` 合法；位域 `width` 1-7；string/bytes `size`≥1
4. 连续位域组总和 ∈ {8,16,24,32}
5. **引用规则**（作用域感知）：
   - `switch.on` / `array.count_from` 引用的字段必须**在可见作用域内声明在前**（顶层或同一 case 内；跨 case 不可见），且必须是数值/位域类型
   - `meta.length_check.field` 必须是**顶层数值**字段
6. **switch 必须是所在字段列表的最后一项**（switch 长度运行时可变，其后字段无法定位）；
   顶层例外：switch 之后仅允许 `crc16` 收尾
7. 顶层最多一个 switch；顶层不允许 array（数组请放入 case 内）
8. `crc16` 字段必须位于顶层末尾且为 `uint16`；case 内不允许 crc16
9. `array.count` 必须是 0-65535 的整数，且与 `count_from` 二选一；元素内不允许嵌套 switch/array
10. `const` 仅支持数值/位域字段且不能为负数（无符号字段）
11. 至少一个绑定；端口 1-65535；表名仅 `udp.port`/`tcp.port`
12. switch 至少一个 case；array 必须提供 element

> 说明：label / long_name / enum 值为自由文本，生成时自动做 Lua 字符串转义与块注释消毒，
> 可安全包含引号、反斜杠、换行与任意 Unicode。

## 生成语义（简）

- 读取顺序 = 声明顺序（大端）
- 被引用字段（switch.on / count_from / length_check / const）自动生成 `local v_<name>` 运行时值
- Info 列自动填充：switch 依据字段的枚举名 + `Seq=N`（若存在名为 `seqNum` 的字段）
- 防御检查（自动包含）：过短包 / 尾随字节 / 幻数 / 长度语义 / CRC
