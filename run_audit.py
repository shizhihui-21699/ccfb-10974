#!/usr/bin/env python3
"""隔离模式入口：把工作区注入 sys.path 后转交给 CLI。

可用 `python3 -I run_audit.py ...` 运行，避免 -I 下 PYTHONPATH 被忽略。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apk_audit.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
