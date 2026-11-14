"""apk_auditor: dependency-free static security auditor for Android APKs.

Parses binary AndroidManifest (AXML) directly, audits network security config
and APK signature schemes v1-v3, and grades exported-component exposure.
"""

from .axml import AxmlNode, AxmlParser, parse_axml
from .manifest_analysis import (
    CRITICAL,
    HIGH,
    MEDIUM,
    INFO,
    Finding,
    ManifestInfo,
    analyze_risks,
    analyze_network_security,
    overall_level,
    parse_manifest,
    rating,
    score,
)

__version__ = "1.0.0"

__all__ = [
    "AxmlNode",
    "AxmlParser",
    "parse_axml",
    "Finding",
    "ManifestInfo",
    "analyze_risks",
    "analyze_network_security",
    "overall_level",
    "parse_manifest",
    "rating",
    "score",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "INFO",
]
