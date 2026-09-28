# ProtoForge v0.15.0 — AI 辅助生成协议定义

> 发布日期：2026-09-29 ｜ 上一个版本：v0.14.0

## 新功能：AI 辅助生成（自然语言 → 协议定义）

把一段自然语言协议描述（中英皆可，可选附十六进制样本帧）交给大模型，生成 ProtoForge
JSON 定义。**校验不过的错误会自动回喂给模型修复，直到通过校验或达到轮数上限。**

核心理念：**AI 负责"填表"，工具负责"表合法"**。AI 产出的是协议定义而不是最终 Lua——
它必须通过与手写定义完全相同的全量校验，再走常规的生成/测试台/部署流程，正确性由工具链
保证，不靠模型自觉。这也是对"为什么不直接让 ChatGPT 写 dissector"的回答。

### 入口

- **GUI**：菜单 文件 → AI 生成协议定义…（QThread 异步生成，日志逐行回显，成功自动载入主窗口）
- **CLI**：

```bash
python -m protoforge ai --describe-file desc.txt --hex "5a5a1101..." -o myproto.json
python -m protoforge generate myproto.json -o myproto.lua
```

### 端点与隐私

- 任何 OpenAI 兼容 `/chat/completions` 端点：本地 Ollama（默认，`http://127.0.0.1:11434/v1`，
  key 留空）或 GLM / DeepSeek / OpenAI 等云服务
- 配置优先级：界面填写 > 环境变量（`PROTOFORGE_AI_ENDPOINT/_MODEL/_API_KEY`）>
  `~/.protoforge/ai.json`（GUI 成功后自动保存；key 明文本机保存）
- 隐私边界：请求只发往你自己配置的端点；提示词只包含你粘贴的描述与样本；工具无遥测

### 实测预期（写进手册的诚实预期）

- 7B 级本地小模型：结构能对（帧头/分支/绑定），细节常丢（位域拆分、长度字段）；
  第 1 轮若"找不到 JSON"多为模型上下文太短截断输出，换更大上下文模型
- 旗舰级模型（27B+/云端）：多数常见协议形态一次或一轮修复后通过
- 生成结果必须人工核对后再生成 Lua

## 仓库配套

- **GitHub Actions CI**：ubuntu（安装 tshark，跑含真机 E2E 的全量测试）+ windows 双矩阵；
  README 挂 CI 徽章
- **issue 模板**：bug 报告（强制附协议定义 JSON 与样本帧）/ 功能请求（要求描述协议形态）

## 质量

- 测试 163 → **180 个**（新增 `tests/test_aigen.py` 17 例：提示词构建、JSON 提取容错、
  自修复循环、设置读写、CLI 参数校验、GUI 对话框——全部离线，注入假 LLM，不发起网络请求）
- 真实 LLM 端到端验证：本机 Ollama（qwen3:4b）实测自修复循环两轮收敛

## 升级

无破坏性变更；v0.14 的定义文件与生成物完全兼容。新功能不引入任何新依赖（HTTP 走标准库）。
