#!/usr/bin/env python3
"""apk-audit: dependency-free Android APK static security auditor.

Usage:
    python3 cli.py <apk> [<apk> ...] [--json] [--no-color] [--output DIR]
"""

from __future__ import annotations

import argparse
import os
import sys

# Allow running both as a module (`python -m apk_auditor.cli`) and directly
# as a script (`python3 cli.py path/to.apk`) without installation.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apk_auditor.audit import audit_apk
from apk_auditor.report import render_json, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apk-audit",
        description=(
            "Android APK 静态安全审计：直接解析二进制 AXML，不依赖 aapt；"
            "审计导出组件、权限、明文流量、网络安全配置与 v1-v3 签名。"
        ),
    )
    parser.add_argument("apks", nargs="+", help="待审计的 APK 文件路径（可多个）")
    parser.add_argument(
        "--json", action="store_true", help="输出机器可读 JSON 而非中文文本报告"
    )
    parser.add_argument("--no-color", action="store_true", help="关闭终端颜色")
    parser.add_argument(
        "--output", "-o", metavar="DIR", help="把每个 APK 的报告写入该目录"
    )
    args = parser.parse_args(argv)

    if args.output:
        os.makedirs(args.output, exist_ok=True)

    worst_seen = 0
    level_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
    for path in args.apks:
        if not os.path.isfile(path):
            print(f"[错误] 文件不存在: {path}", file=sys.stderr)
            return 2
        try:
            result = audit_apk(path)
        except ValueError as exc:
            print(f"[错误] {path}: {exc}", file=sys.stderr)
            return 2

        if args.json:
            rendered = render_json(result)
        else:
            rendered = render_text(result, color=not args.no_color)
        print(rendered)
        if len(args.apks) > 1:
            print("\n")

        if args.output:
            base = os.path.splitext(os.path.basename(path))[0]
            ext = "json" if args.json else "txt"
            out_path = os.path.join(args.output, f"{base}-audit.{ext}")
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(rendered)
                fh.write("\n")
            print(f"[i] 报告已写入 {out_path}", file=sys.stderr)

        for f in result.findings:
            worst_seen = max(worst_seen, level_weight.get(f.level, 0))

    # Exit code reflects the worst finding for CI pipelines:
    # 0 clean/info-only, 1 medium+, 2 usage/file errors (above).
    if worst_seen >= 3:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
