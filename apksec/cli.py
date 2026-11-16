"""Command-line interface: ``python -m apksec <command>``."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import __version__, apkfile, binxml, report, signature
from .audit import AuditError, audit_apk


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="报告格式（默认 text）",
    )
    p.add_argument("-o", "--output", help="写入文件而不是标准输出")
    p.add_argument("--no-color", action="store_true", help="禁用彩色输出")


def _emit(text: str, args) -> None:
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def cmd_audit(args) -> int:
    rc = 0
    results = []
    paths = args.apk
    for path in paths:
        try:
            results.append(audit_apk(path))
        except (AuditError, apkfile.ApkFormatError, OSError) as exc:
            sys.stderr.write(f"apksec: {path}: {exc}\n")
            rc = 2
    if not results:
        return rc
    color = (
        args.format == "text"
        and not args.no_color
        and not args.output
        and sys.stdout.isatty()
    )
    if args.format == "json":
        payload = [r.to_dict() for r in results]
        text = json.dumps(payload[0] if len(payload) == 1 else payload, ensure_ascii=False, indent=2)
    elif args.format == "markdown":
        text = "\n\n---\n\n".join(report.render_markdown(r) for r in results)
    else:
        text = "\n".join(report.render_text(r, color=color) for r in results)
    _emit(text, args)

    if args.fail_on:
        thresholds = [s.strip() for s in args.fail_on.split(",") if s.strip()]
        bad = False
        for r in results:
            for f in r.findings:
                if f.severity in thresholds:
                    bad = True
        if bad:
            return 1
    return rc


def cmd_dump(args) -> int:
    rc = 0
    for path in args.apk:
        try:
            with apkfile.ApkFile(path) as apk:
                name = args.entry or "AndroidManifest.xml"
                data = apk.read_entry_safe(name, max_size=64 * 1024 * 1024)
                if data is None:
                    sys.stderr.write(f"apksec: {path}: {name} not found\n")
                    rc = 2
                    continue
                if data[:2] != b"\x03\x00":
                    sys.stderr.write(
                        f"apksec: {name} is not binary XML "
                        f"(starts with {data[:4].hex()})\n"
                    )
                    rc = 2
                    continue
                doc = binxml.parse_axml(data)
                if args.raw_strings:
                    sys.stdout.write("\n".join(doc.strings) + "\n")
                else:
                    sys.stdout.write(doc.dump() + "\n")
        except (binxml.BinXmlError, apkfile.ApkFormatError, OSError) as exc:
            sys.stderr.write(f"apksec: {path}: {exc}\n")
            rc = 2
    return rc


def cmd_sig(args) -> int:
    rc = 0
    for path in args.apk:
        try:
            with apkfile.ApkFile(path) as apk:
                sig_report = signature.analyze_signatures(apk)
                payload = {
                    "file": path,
                    "schemes": [f"v{s}" for s in sig_report.schemes_present()],
                    "v1": report.AuditResult._scheme_dict(sig_report.v1),
                    "v2": report.AuditResult._scheme_dict(sig_report.v2),
                    "v3": report.AuditResult._scheme_dict(sig_report.v3),
                    "v3.1": report.AuditResult._scheme_dict(sig_report.v31),
                    "errors": sig_report.errors,
                }
                sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        except (apkfile.ApkFormatError, OSError) as exc:
            sys.stderr.write(f"apksec: {path}: {exc}\n")
            rc = 2
    return rc


def cmd_fixtures(args) -> int:
    try:
        from tools.apkbuild.fixtures import build_all
    except ImportError:
        sys.stderr.write(
            "apksec: fixture builder not found (tools/apkbuild); "
            "run from a source checkout\n"
        )
        return 2
    built = build_all(args.out_dir)
    for fixture in built:
        sys.stdout.write(
            f"{fixture.name:<28} {len(fixture.apk):>8} bytes  {fixture.description}\n"
        )
    sys.stdout.write(f"\n{len(built)} 个样本已写入 {args.out_dir}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apksec",
        description="Android APK 静态安全审计（纯 Python，不依赖 aapt/jadx/Java）",
    )
    parser.add_argument("--version", action="version", version=f"apksec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("audit", help="审计一个或多个 APK")
    p.add_argument("apk", nargs="+", help="APK 文件路径")
    p.add_argument(
        "--fail-on",
        help='发现指定级别时以退出码 1 结束，例如 "critical,high"',
    )
    _add_output_args(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("dump", help="以文本形式转储 AndroidManifest.xml / 其他二进制 XML")
    p.add_argument("apk", nargs="+", help="APK 文件路径")
    p.add_argument("--entry", help="APK 内的条目路径（默认 AndroidManifest.xml）")
    p.add_argument("--raw-strings", action="store_true", help="只输出字符串池")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("sig", help="仅检查签名方案并输出 JSON")
    p.add_argument("apk", nargs="+", help="APK 文件路径")
    p.set_defaults(func=cmd_sig)

    p = sub.add_parser(
        "fixtures",
        help="生成测试用 APK 语料（自行打包，含正常与问题样本）",
    )
    p.add_argument(
        "out_dir",
        nargs="?",
        default="fixtures",
        help="输出目录（默认 ./fixtures）",
    )
    p.set_defaults(func=cmd_fixtures)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
