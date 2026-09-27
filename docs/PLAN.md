# ProtoForge v0.9 实现计划

> **For agentic workers:** 本计划按任务推进，接口签名即契约。执行模式：本会话 inline TDD。
> Spec: docs/DESIGN.md（本文件从 spec 论证，执行者需两份同读）

**Goal:** 把 spike 生成内核升级为完整产品：core + CLI + PySide6 GUI + 全层测试 + 中文手册。

**Architecture:** 三层——纯标准库 core（model/generator/io/engine）、CLI 与 GUI 两个消费者、
pytest 全层测试。数据流：定义 → model.validate → generator → Lua 文本 → luaengine 执行或
deploy 安装。

**Tech Stack:** Python 3.10+、PySide6、lupa(lua54)、pytest。core 除 lupa 外零第三方依赖。

## Global Constraints（每个任务隐含遵守）

- 产品/代码内命名只用 ProtoForge，不得出现 "Wireshark XXX" 式产品名（"for Wireshark" 描述可用）
- 生成的 .lua 头部必须含 GPLv2+ 声明行
- Lua 代码仅用 5.3+ 语法（原生 `~ & | <<` 位运算、整数除法）
- core/ 目录不得 import PySide6；tests 除 GUI 冒烟外不得依赖 GUI
- 所有文件 UTF-8；.bat 输出必须 CRLF（od 验证 0d0a）
- 版本号统一 `__version__ = "0.9.0"`

## 接口契约（跨任务引用以此为准）

```python
# core/model.py
class ValidationError(ValueError): ...
@dataclass
class Field:  # name,label,type,width,display,enum,const,size,on,cases,count,count_from,element,crc16
@dataclass
class Binding:  # table:str, ports:list[int]
@dataclass
class Protocol:  # name,long_name,desc,bindings,fields,length_check
def walk(fields: list[Field]) -> Iterator[Field]
def is_bitfield(f: Field) -> bool          # type=="uint" 且 1<=width<8
def field_size(f: Field) -> int | None
def static_size(fields: list[Field]) -> int          # 抛 ValidationError
def bitfield_groups(fields) -> list[list[Field]]     # 打包组（含嵌套容器内）
def validate(p: Protocol) -> list[str]               # 错误字符串列表，空=合法

# core/jsonio.py
def load_protocol(src: str | Path) -> Protocol       # 路径或 JSON 文本
def protocol_to_dict(p: Protocol) -> dict
def save_protocol(p: Protocol, path: Path) -> None

# core/csvimport.py
def import_csv(src: str | Path) -> Protocol
def export_csv(p: Protocol, path: Path) -> None      # 含 switch/array 时抛 CsvUnsupported

# core/generator.py
def generate_lua(p: Protocol) -> str                 # 抛 ValidationError
class SpecError(Exception)  # 兼容 spike 消息

# core/luaengine.py
@dataclass class TreeNode: label,value,offset,length,expert,expert_tag,children
@dataclass class DissectResult: ok,error,info,protocol,consumed,tree
class LuaError(RuntimeError): ...
class LuaEngine:
    def load(self, lua_code: str) -> None            # 抛 LuaError
    def dissect(self, frame: bytes) -> DissectResult

# core/pcapio.py
@dataclass class Packet: index,ts,src,dst,sport,dport,proto,payload
def read_pcap(path) -> list[Packet]                  # 仅 classic pcap / linktype 1
def extract_frames(packets, ports: set[int]) -> list[bytes]

# core/deploy.py
def plugin_dirs() -> list[Path]
def default_plugin_dir() -> Path | None
def install(lua_text: str, name: str, target: Path) -> Path
def uninstall(name: str, target: Path) -> bool
def find_tshark() -> str | None
def tshark_version(exe: str) -> str | None

# cli.py
def main(argv: list[str] | None = None) -> int       # 0 成功

# app/main_window.py
class MainWindow(QMainWindow):
    def load_protocol(self, path: str) -> None
    def current_lua(self) -> str                      # 触发生成，错误时弹窗并返回 ""
```

---

### Task 1: core/model.py（数据模型+校验）
Files: protoforge/core/model.py; tests/test_model.py
用例：重名/位域不成字节边界/switch.on 引用不存在或位置在后/count_from 同理/crc16 非末尾/
非法 type/非法 name 标识符/enum 键非整数→错误；合法 SMSP 协议→[]。
步骤：写失败测试→实现 dataclass+validate→绿。

### Task 2: core/jsonio.py（JSON IO）
Files: core/jsonio.py; tests/test_jsonio.py
用例：加载 spike 的 smsp.json（examples/ 拷贝）→字段数/绑定正确；dict↔model 往返等价；
坏 JSON→异常。

### Task 3: core/generator.py（生成器升级）
Files: core/generator.py; tests/test_generator.py
基于 spike generator.py 重构：接收 Protocol 而非 dict；新增 string/bytes 类型、多绑定、
GPL 头不变。用例：SMSP 生成含关键行（0xF0 掩码/bitfield(4, 4)/get_index/append_text/
udp.table）；string 生成 ProtoField.string；tcp.port 绑定生成 DissectorTable.get("tcp.port")；
校验错误→抛 ValidationError。

### Task 4: core/luaengine.py（mock 执行引擎）
Files: core/luaengine.py; tests/test_luaengine.py
从 spike verify_lupa.py 提取为可复用引擎：TreeNode 带 offset/length（供 GUI hex 高亮）、
expert 标记、bindings 记录。用例：SMSP 4 帧（含坏 CRC）树断言（复用 spike 场景）+
string/bytes 帧 + 过短包（ok=False 或 expert）+ 尾随字节 expert + 幻数错误 expert +
Lua 语法错误→LuaError。

### Task 5: core/csvimport.py（CSV IO）
Files: core/csvimport.py; tests/test_csvimport.py
列：name,label,type,width,display,enum,const,size；enum 语法 `1=A;2=B`；# 注释、空行跳过。
用例：导入平铺→字段断言；往返；export 含 switch→CsvUnsupported。

### Task 6: core/pcapio.py（pcap 读取）
Files: core/pcapio.py; tests/test_pcapio.py
用例：make_demo.py 产出的 demo.pcap 读回 4 包（地址/端口/载荷长度断言）；端口过滤；
非 pcap 头→ValueError。

### Task 7: core/deploy.py（部署）
Files: core/deploy.py; tests/test_deploy.py
用例：install 写文件返回路径、内容一致；uninstall；find_tshark 在本机返回 4.6.x；
plugin_dirs 在 Windows 含 %APPDATA% 候选（monkeypatch 临时 APPDATA 指向 tmp）。

### Task 8: cli.py + __main__.py
Files: protoforge/cli.py, protoforge/__main__.py, protoforge/__init__.py; tests/test_cli.py
子命令：generate spec -o out；verify spec --hex/--pcap --port；deploy out.lua --name --dir；
selftest（跑内置 SMSP 全链路并打印 PASS/FAIL）。用例：generate 产物可被 LuaEngine 执行；
verify --hex 返回 0 且输出含 "Magic"；deploy 到 tmp；坏参数返回非 0。

### Task 9: app/ GUI
Files: app/{__init__,main_window,field_editor,property_panel,testbench,deploy_dialog}.py;
tests/test_gui_smoke.py（QT_QPA_PLATFORM=offscreen）
MainWindow：左 FieldEditor（QTreeWidget：名称/类型/宽度/备注 + 增删上移下移 + case/element
子层）+ 右上 PropertyPanel + 右下 Tab（生成 Lua 预览/测试台）。菜单：文件(新建/打开json/
保存json/导入csv/导出lua)、部署(安装到 Wireshark/卸载/打开插件目录/检测 tshark)、帮助(手册)。
冒烟用例：load examples/smsp.json→树顶层节点数=8；current_lua() 含 "ProtoField.uint8"；
测试台喂 spike 帧 hex→树含 "Magic: 0x5a5a" 与 "incorrect"；属性面板改 label→生成代码同步。

### Task 10: E2E tshark 自动化
Files: tests/test_e2e_tshark.py
skipif 无 tshark。流程：examples/smsp.json→generate→tmp.lua；make_demo 产 pcap；
tshark -r -X lua_script -V 断言输出含 "Message Type: 1"、" [correct]"、" [incorrect"。

### Task 11: examples + 启动器
Files: examples/{smsp.json,smsp.csv,make_demo.py}（demo.pcap 由 make_demo 生成）；
ProtoForge.bat（CRLF+od 验证）；run_tests.bat。
make_demo.py 复用 spike packets 逻辑（重写，净室）。

### Task 12: 文档
Files: docs/USER_MANUAL.md（详尽：安装/5分钟上手/界面截图/类型系统/JSON schema/CSV/
测试台/CLI/部署与版本/FAQ/授权）；docs/PROTOCOL_SCHEMA.md；README.md；docs/screenshots/
（offscreen grab 保存）。

### Task 13: 全量验证与收尾
pytest 全绿；od 验证 .bat；清理 __pycache__；交付清单核对；busy flag 删除。

## Self-Review 记录
- 覆盖检查：DESIGN §4.1 十项 → Task 1-12 全映射（GUI=9、CLI=8、测试=各任务+E2E=10、手册=12）✓
- 占位符扫描：无 TBD/“稍后实现” ✓
- 类型一致性：接口契约块为唯一权威，各任务引用同签名 ✓
