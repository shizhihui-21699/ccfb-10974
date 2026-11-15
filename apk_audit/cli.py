"""命令行入口：python -m apk_audit <apk|目录> [选项]"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .auditor import audit_apk
from .report import Renderer
from .rules import SEVERITY_ORDER


def _collect_apks(targets: list[str]) -> list[str]:
    out = []
    for t in targets:
        if os.path.isdir(t):
            for root, _dirs, files in os.walk(t):
                for name in files:
                    if name.lower().endswith(".apk"):
                        out.append(os.path.join(root, name))
        else:
            out.append(t)
    return sorted(set(out))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apk_audit",
        description="纯 Python APK 静态审计：AXML 解析 / 导出组件 / 网络配置 / v1-v3 签名",
    )
    parser.add_argument("targets", nargs="+", help="APK 文件或包含 APK 的目录")
    parser.add_argument("--json", dest="json_out", metavar="PATH",
                        help="把结构化结果写入 JSON 文件（- 表示 stdout）")
    parser.add_argument("--no-color", action="store_true", help="关闭终端颜色")
    parser.add_argument("--fail-on", choices=("CRITICAL", "HIGH", "MEDIUM", "LOW"),
                        help="达到该严重级别即以非零码退出（便于 CI 卡点）")
    args = parser.parse_args(argv)

    apks = _collect_apks(args.targets)
    if not apks:
        print("没有找到任何 .apk 文件", file=sys.stderr)
        return 2

    renderer = Renderer(color=not args.no_color and sys.stdout.isatty())
    all_results = []
    worst = -1

    for path in apks:
        result = audit_apk(path)
        all_results.append(result)
        print(renderer.render(result))
        print()
        if result.ok:
            for f in result.findings:
                worst = max(worst, SEVERITY_ORDER[f.severity])

    if args.json_out:
        payload = json.dumps(
            [r.to_dict() for r in all_results], ensure_ascii=False, indent=2,
            default=str,
        )
        if args.json_out == "-":
            print(payload)
        else:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                fh.write(payload)
            print(f"JSON 报告已写入 {args.json_out}")

    if args.fail_on and worst >= SEVERITY_ORDER[args.fail_on]:
        return 1
    # 审计本身失败（文件损坏等）也返回非零
    if any(not r.ok for r in all_results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
