"""Unit tests for the AXML parser/writer round-trip and typed values.

Run from the workspace root:  python3 -I -m pytest tests/ -q
(or) python3 -I tests/test_axml.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apk_auditor.axml import (
    AxmlAttribute,
    AxmlNode,
    TYPE_INT_BOOLEAN,
    TYPE_INT_DEC,
    TYPE_REFERENCE,
    TYPE_STRING,
    parse_axml,
)
from apk_auditor.axml_writer import ANDROID_NS, AxmlWriter


def _attr(name: str, value, rid: int | None = None) -> AxmlAttribute:
    if isinstance(value, bool):
        dtype = TYPE_INT_BOOLEAN
        raw = None
    elif isinstance(value, int):
        dtype = TYPE_INT_DEC
        raw = None
    else:
        dtype = TYPE_STRING
        raw = str(value)
    return AxmlAttribute(
        namespace=ANDROID_NS,
        name=name,
        raw_name=name,
        value=value,
        raw_value=raw,
        type=dtype,
        type_name="",
        resource_id=rid,
    )


def _node(tag: str, attrs: dict | None = None, children: list | None = None,
          text: str | None = None) -> AxmlNode:
    n = AxmlNode(tag, None)
    for k, v in (attrs or {}).items():
        n.attributes[k] = _attr(k, v)
    n.children = children or []
    n.text = text
    return n


class AxmlRoundTripTests(unittest.TestCase):
    def test_basic_types_round_trip(self) -> None:
        root = _node(
            "manifest",
            {"package": "com.test.app", "versionCode": 42},
            [
                _node(
                    "application",
                    {
                        "debuggable": True,
                        "allowBackup": False,
                        "networkSecurityConfig": "@0x7f120001",
                    },
                )
            ],
        )
        blob = AxmlWriter().write(root)
        parsed = parse_axml(blob)

        self.assertEqual(parsed.name, "manifest")
        self.assertEqual(parsed.get("package"), "com.test.app")
        self.assertEqual(parsed.get("versionCode"), 42)
        app = parsed.find("application")
        self.assertIs(app.get("debuggable"), True)
        self.assertIs(app.get("allowBackup"), False)
        # Reference must decode back to the @0x form, not a bare integer.
        self.assertEqual(app.get("networkSecurityConfig"), "@0x7f120001")

    def test_nested_tree_and_cdata(self) -> None:
        root = _node(
            "network-security-config",
            {},
            [
                _node(
                    "domain-config",
                    {"cleartextTrafficPermitted": False},
                    [
                        _node("domain", {"includeSubdomains": True},
                              text="api.example.com"),
                        _node(
                            "pin-set",
                            {},
                            [_node("pin", {"digest": "SHA-256"}, text="abc=")],
                        ),
                    ],
                )
            ],
        )
        parsed = parse_axml(AxmlWriter().write(root))
        dc = parsed.find("domain-config")
        self.assertIs(dc.get("cleartextTrafficPermitted"), False)
        domain = dc.find("domain")
        self.assertEqual(domain.text, "api.example.com")
        pin = dc.find("pin-set").find("pin")
        self.assertEqual(pin.text, "abc=")
        self.assertEqual(pin.get("digest"), "SHA-256")

    def test_many_strings_keep_offsets_aligned(self) -> None:
        # Long pools exercise the UTF-8 two-byte length and offset tables.
        children = [
            _node("activity", {"name": f"com.test.Activity{i:03d}"})
            for i in range(60)
        ]
        root = _node("application", {}, children)
        parsed = parse_axml(AxmlWriter().write(root))
        names = [c.get("name") for c in parsed.findall("activity")]
        self.assertEqual(len(names), 60)
        self.assertEqual(names[0], "com.test.Activity000")
        self.assertEqual(names[59], "com.test.Activity059")

    def test_rejects_non_axml(self) -> None:
        with self.assertRaises(ValueError):
            parse_axml(b"not an axml file at all")


if __name__ == "__main__":
    unittest.main()
