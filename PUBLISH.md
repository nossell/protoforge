# 发布前检查清单（PUBLISH.md）

ProtoForge 达到"可对外发布"状态的操作清单。执行前逐项打勾。

## 1. 隐私与合规扫描（每次发布前必跑）

- [ ] 全仓扫描个人特征词零命中：盘符路径（`F:` `D:` 等）、用户目录（`C:\Users`）、设备名/NAS 名、邮箱、账号名（搜索模式按需维护，勿把真实特征词写进本清单）
- [ ] docs/screenshots/ 四张截图目检：无本机路径、无真实账号名
- [ ] examples/demo.pcap 里的 IP（192.168.10.x 为 RFC1918 演示地址，可保留）
- [ ] git log 无敏感信息（本仓库首次提交前已完成扫描）

## 2. 质量门禁

- [ ] `run_tests.bat`（或 `python -m pytest tests -q`）全绿（当前 162 例，含真实 tshark E2E）
- [ ] `python -m protoforge selftest` 输出 PASS
- [ ] 双击 ProtoForge.bat 走一遍：打开示例 → 生成 → 测试台 pcap → 部署对话框
- [ ] docs/USER_MANUAL.html 目录锚点可跳转、无裸 md

## 3. 发布形态二选一

### A. GitHub 开源（建议默认）
- [ ] 仓库命名 `protoforge`（或 disectorforge 类备选），描述一行 + topics：wireshark, lua, dissector, protocol, generator
- [ ] 首屏 README 已含截图与五分钟上手（已就绪）
- [ ] LICENSE（MIT，生成物 GPLv2+ 说明已写入 LICENSE 附录）✅ 已就绪
- [ ] 建议补一个 30 秒 GIF 演示（GUI 操作录屏，tools/make_screens.py 可改造）

### B. 试水推广（挂 landing + 免费收集意向）
- [ ] preview/index.html 即 landing（当前含真实交互仿真）
- [ ] 可加「加入等待名单」表单（表单服务自选），先测需求再决定收费
- [ ] 目标社区：r/wireshark、ask.wireshark.org（答题带链接，守社区礼节）、车载以太网社群

## 4. 商标纪律（长期有效）

- [ ] 产品名与文案不出现 "Wireshark XXX" 式命名；用 "for Wireshark" 兼容性描述
- [ ] 页面注明：非官方，与 Wireshark 基金会无关

## 5. 版本发布

- [ ] `protoforge/__init__.py` 版本号递增
- [ ] git tag v0.9.x + GitHub Release（附 CHANGELOG：改了什么/修了什么）
