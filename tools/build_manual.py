#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 docs/USER_MANUAL.md 渲染为 docs/USER_MANUAL.html（与概览页同套设计令牌）。

用法：python tools/build_manual.py
锚点用 GitHub 风格 slug（保留 CJK），保证手册内目录链接可用。
"""
import os
import re
import sys

import markdown

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = [
    ("USER_MANUAL.md", "USER_MANUAL.html", "ProtoForge 使用手册"),
    ("PROTOCOL_SCHEMA.md", "PROTOCOL_SCHEMA.html", "ProtoForge 协议定义 Schema 参考"),
]


def gh_slug(text: str) -> str:
    """GitHub 风格锚点：小写、去标点（保留 CJK/连字符/空格/下划线）、空格转连字符。"""
    t = text.strip().lower()
    t = re.sub(r"[^\w\u4e00-\u9fff\- ]", "", t)
    t = t.replace(" ", "-")
    return t


def slugify_with_counter():
    used = set()

    def _slug(value, separator):
        base = gh_slug(value)
        slug, i = base, 2
        while slug in used:
            slug = f"{base}-{i}"
            i += 1
        used.add(slug)
        return slug
    return _slug


CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
:root{
  --text:#161616; --text-2:#525252; --text-3:#6f6f6f;
  --bg:#ffffff; --surface:#f4f4f4;
  --border:#e0e0e0; --border-strong:#c6c6c6;
  --accent:#0f62fe; --accent-hover:#0043ce; --tint:#edf5ff; --tint-2:#d0e2ff;
  --sans:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.7;
  -webkit-font-smoothing:antialiased}
.topbar{position:sticky;top:0;z-index:5;background:#fff;border-bottom:1px solid var(--border)}
.topbar .in{max-width:880px;margin:0 auto;padding:0 24px;height:48px;display:flex;align-items:center;gap:14px}
.topbar a{font-size:13px;color:var(--text-2);text-decoration:none}
.topbar a:hover{color:var(--accent)}
.topbar .brand{font-size:14px;font-weight:600;color:var(--text)}
.topbar .crumb{border-left:1px solid var(--border-strong);padding-left:14px}
main{max-width:880px;margin:0 auto;padding:40px 24px 96px}
h1{font-size:34px;font-weight:300;letter-spacing:-.7px;line-height:1.2;margin:20px 0 8px}
h2{font-size:24px;font-weight:400;letter-spacing:-.2px;margin:56px 0 12px;padding-top:12px;border-top:1px solid var(--border)}
h3{font-size:17px;font-weight:600;margin:32px 0 8px}
p{margin:10px 0;color:var(--text);max-width:76ch}
li{margin:6px 0;color:var(--text)}
ul,ol{padding-left:24px;margin:10px 0}
blockquote{border-left:3px solid var(--accent);background:var(--surface);padding:12px 18px;margin:16px 0;
  color:var(--text-2);font-size:14px}
blockquote p{margin:4px 0;color:var(--text-2)}
code{font-family:var(--mono);font-size:13px;background:var(--surface);border:1px solid var(--border);
  padding:1px 6px;border-radius:2px}
pre{background:var(--surface);border:1px solid var(--border);border-radius:2px;padding:14px 16px;
  overflow:auto;margin:14px 0;line-height:1.6}
pre code{background:none;border:none;padding:0;font-size:12.5px}
table{border-collapse:collapse;width:100%;margin:16px 0;font-size:13.5px}
th{text-align:left;font-weight:600;font-size:12.5px;color:var(--text-2);background:#fafafa;
  border-bottom:1px solid var(--border-strong);padding:7px 10px}
td{padding:7px 10px;border-bottom:1px solid #ececec;vertical-align:top}
tr:hover td{background:var(--surface)}
hr{border:none;border-top:1px solid var(--border);margin:40px 0}
a{color:var(--accent)}
.toc{background:var(--surface);border:1px solid var(--border);border-radius:2px;padding:22px 26px;margin:24px 0 8px}
.toc > ul{list-style:none;padding-left:0;margin:0;display:grid;grid-template-columns:1fr 1fr;gap:6px 44px}
.toc > ul > li{break-inside:avoid;margin:0 0 14px;font-weight:600;font-size:14px}
.toc > ul > li > a{color:var(--text)}
.toc > ul > li > a:hover{color:var(--accent);text-decoration:underline}
.toc ul ul{list-style:none;padding-left:0;margin:8px 0 0}
.toc ul ul li{margin:4px 0;font-weight:400;font-size:13px}
.toc ul ul a{color:var(--text-2);text-decoration:none}
.toc ul ul a:hover{color:var(--accent);text-decoration:underline}
@media (max-width:720px){.toc > ul{grid-template-columns:1fr}}
.meta{font-size:13px;color:var(--text-3)}
@media print{.topbar{display:none}main{max-width:none}}
"""


def build(src_name: str, dst_name: str, title: str) -> None:
    src = os.path.join(REPO, "docs", src_name)
    dst = os.path.join(REPO, "docs", dst_name)
    with open(src, "r", encoding="utf-8") as fh:
        md_text = fh.read()

    # 去掉 md 里手写的目录段，用 toc 扩展自动生成（锚点风格统一）
    md_text = re.sub(r"## 目录\n\n[\s\S]*?\n---\n", "[TOC]\n\n---\n", md_text, count=1)

    body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "toc", "nl2br"],
        extension_configs={
            "toc": {
                "slugify": slugify_with_counter(),
                "permalink": False,
                "toc_depth": "2-3",   # 目录只收录 h2/h3，排除 h1
            },
        },
    )
    # 文档间互链改写为 .html：浏览器直接点开 .md 会显示裸 Markdown（用户已报过一次）
    body = re.sub(r'href="([A-Za-z0-9_./-]+)\.md(#[^"]*)?"', r'href="\1.html\2"', body)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>{CSS}</style>
</head>
<body>
<div class="topbar"><div class="in">
  <span class="brand">ProtoForge</span>
  <a class="crumb" href="/preview/index.html">返回概览</a>
  <a href="/docs/USER_MANUAL.html">使用手册</a>
  <a href="/docs/PROTOCOL_SCHEMA.html">Schema 参考</a>
</div></div>
<main>
{body}
</main>
</body>
</html>"""
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(html)
    print(f"[OK] {dst} ({len(html.splitlines())} 行)")


def main():
    for src, dst, title in DOCS:
        build(src, dst, title)


if __name__ == "__main__":
    sys.exit(main())
