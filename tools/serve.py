#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ProtoForge 本地预览服务（替代 python -m http.server）。

增强：
- HTML 响应带 no-store，避免浏览器缓存旧页面
- 访问 docs/*.md 时 302 跳转到同名 .html（渲染版），旧链接/旧缓存页也能落到正确内容

用法：python tools/serve.py [端口，默认 18472]
"""
import http.server
import os
import sys
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=REPO, **kwargs)

    def end_headers(self):
        if (self.path.endswith(".html") or self.path.endswith("/") or
                "index.html" in self.path):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.endswith(".md"):
            target = path[:-3] + ".html"
            if os.path.exists(os.path.join(REPO, target.lstrip("/"))):
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
                return
        super().do_GET()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18472
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[OK] ProtoForge preview server on http://127.0.0.1:{port}/preview/index.html")
    server.serve_forever()


if __name__ == "__main__":
    main()
