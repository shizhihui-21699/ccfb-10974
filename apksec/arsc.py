"""Parser for Android's compiled resource table (resources.arsc).

Used to resolve ``@0x7f...`` attribute values such as
``android:networkSecurityConfig="@xml/network_security_config"`` back to the
resource name, and to read the referenced compiled XML file.  Only what a
manifest audit needs is implemented: packages, type specs, types, entries and
simple (non-complex) values, including the modern compact / sparse / 16-bit
offset encodings.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from . import binxml

RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

FLAG_COMPLEX = 0x0001
FLAG_PUBLIC = 0x0002
FLAG_WEAK = 0x0004
FLAG_COMPACT = 0x0008

NO_ENTRY = 0xFFFFFFFF
FLAG_SPARSE = 0x01
FLAG_OFFSET16 = 0x02

MAX_TYPES = 512
MAX_ENTRIES = 200_000
MAX_PACKAGES = 64


class ArscError(ValueError):
    pass


@dataclass
class Config:
    raw: bytes
    size: int
    sdk_version: int = 0
    language: str = ""
    region: str = ""
    density: int = 0

    @property
    def is_default(self) -> bool:
        # A default config has every selector zero/empty.
        return not self.language and not self.region and self.density == 0

    def describe(self) -> str:
        parts = []
        if self.language or self.region:
            parts.append(f"{self.language}-{self.region}".strip("-"))
        if self.density:
            parts.append(f"density={self.density}")
        if self.sdk_version:
            parts.append(f"sdk={self.sdk_version}")
        return " ".join(parts) if parts else "default"

    def score(self) -> tuple[int, int, int]:
        """Heuristic preference: default-ish configs first, then newest sdk."""
        return (
            1 if self.is_default else 0,
            0 if self.density else 1,
            self.sdk_version,
        )


def _parse_config(raw: bytes) -> Config:
    cfg = Config(raw=raw, size=struct.unpack_from("<I", raw, 0)[0] if len(raw) >= 4 else len(raw))
    if len(raw) >= 8:
        lang = raw[8:10]
        if lang not in (b"\x00\x00", b"\x00\x00\x00\x00"):
            cfg.language = lang.rstrip(b"\x00").decode("ascii", errors="replace")
    if len(raw) >= 10:
        region = raw[10:12]
        if region not in (b"\x00\x00",):
            cfg.region = region.rstrip(b"\x00").decode("ascii", errors="replace")
    if len(raw) >= 16:
        cfg.density = struct.unpack_from("<H", raw, 14)[0]
    if len(raw) >= 26:
        cfg.sdk_version = struct.unpack_from("<H", raw, 24)[0]
    return cfg


@dataclass
class Entry:
    key: str
    value_type: int
    data: int
    is_complex: bool
    config: Config


@dataclass
class Package:
    id: int
    name: str
    type_names: list[str] = field(default_factory=list)
    key_names: list[str] = field(default_factory=list)
    # (type_id, entry_index) -> [(config, entry)]
    entries: dict[tuple[int, int], list[Entry]] = field(default_factory=dict)

    def find(self, res_id: int) -> Optional[Entry]:
        if (res_id >> 24) != self.id:
            return None
        type_id = (res_id >> 16) & 0xFF
        index = res_id & 0xFFFF
        candidates = self.entries.get((type_id, index))
        if not candidates:
            return None
        return max(candidates, key=lambda e: e.config.score())


@dataclass
class ResourceTable:
    global_strings: list[str]
    packages: list[Package]

    def lookup(self, res_id: int) -> Optional[tuple[str, Entry]]:
        """Resolve ``0xPPTTEEEE`` to (``type/name``, entry)."""
        for pkg in self.packages:
            entry = pkg.find(res_id)
            if entry is None:
                continue
            type_id = (res_id >> 16) & 0xFF
            type_name = (
                pkg.type_names[type_id - 1]
                if 0 < type_id <= len(pkg.type_names)
                else f"type{type_id}"
            )
            return f"{type_name}/{entry.key}", entry
        return None

    def lookup_name(self, res_id: int) -> Optional[str]:
        hit = self.lookup(res_id)
        return hit[0] if hit else None

    def string_value(self, entry: Entry) -> Optional[str]:
        """Return the string a simple entry points at, if it is one."""
        if entry.value_type == binxml.TYPE_STRING and 0 <= entry.data < len(self.global_strings):
            return self.global_strings[entry.data]
        return None



def _read_u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise ArscError("truncated resource table")
    return struct.unpack_from("<H", data, off)[0]


def _read_u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise ArscError("truncated resource table")
    return struct.unpack_from("<I", data, off)[0]


def parse_arsc(data: bytes) -> ResourceTable:
    typ, header_size, size = struct.unpack_from("<HHI", data, 0)
    if typ != RES_TABLE_TYPE:
        raise ArscError("not a resource table")
    if header_size < 12 or size > len(data):
        raise ArscError("invalid resource table header")
    package_count = _read_u32(data, 8)
    if package_count > MAX_PACKAGES:
        raise ArscError("too many resource packages")

    global_strings: list[str] = []
    packages: list[Package] = []

    off = header_size
    limit = size
    while off + 8 <= limit:
        ctype, chead, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8 or off + csize > limit:
            raise ArscError("invalid chunk in resource table")
        if ctype == binxml.RES_STRING_POOL_TYPE:
            global_strings = binxml.parse_string_pool(data, off)
        elif ctype == RES_TABLE_PACKAGE_TYPE:
            packages.append(_parse_package(data, off, chead, csize))
        off += csize
    return ResourceTable(global_strings=global_strings, packages=packages)


def _parse_package(data: bytes, off: int, header_size: int, size: int) -> Package:
    if header_size < 284:
        raise ArscError("package header too small")
    pkg_id = _read_u32(data, off + 8)
    if pkg_id == 0 or pkg_id > 0xFF:
        raise ArscError("invalid package id")
    name_raw = data[off + 12 : off + 12 + 256]
    name = name_raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    type_strings_off = _read_u32(data, off + 268)
    key_strings_off = _read_u32(data, off + 276)
    # typeIdOffset (API 26+) shifts type ids; most APKs leave it 0.
    type_id_offset = 0
    if header_size >= 288:
        type_id_offset = _read_u32(data, off + 284)
    pkg = Package(id=pkg_id, name=name)
    if type_strings_off:
        pkg.type_names = binxml.parse_string_pool(data, off + type_strings_off)
    if key_strings_off:
        pkg.key_names = binxml.parse_string_pool(data, off + key_strings_off)

    end = off + size
    sub = off + header_size
    while sub + 8 <= end:
        ctype, chead, csize = struct.unpack_from("<HHI", data, sub)
        if csize < 8 or sub + csize > end:
            raise ArscError("invalid chunk inside package")
        if ctype == RES_TABLE_TYPE_TYPE:
            _parse_type_chunk(data, sub, chead, csize, pkg, type_id_offset)
        sub += csize
    return pkg


def _parse_type_chunk(
    data: bytes,
    off: int,
    header_size: int,
    size: int,
    pkg: Package,
    type_id_offset: int,
) -> None:
    if header_size < 20:
        raise ArscError("type chunk header too small")
    type_id = data[off + 8] + type_id_offset
    flags = data[off + 9]
    entry_count = _read_u32(data, off + 12)
    entries_start = _read_u32(data, off + 16)
    if entry_count > MAX_ENTRIES:
        raise ArscError("too many entries in type chunk")
    config_size = _read_u32(data, off + 20) if header_size >= 24 else 0
    if config_size < 4 or 20 + config_size > header_size:
        # Some old tables have a short header; treat as default config.
        config = Config(raw=b"\x00" * 4, size=4)
    else:
        config = _parse_config(data[off + 20 : off + 20 + config_size])
    if entries_start > size:
        raise ArscError("entriesStart out of bounds")
    entry_area = off + entries_start
    end = off + size

    if flags & FLAG_SPARSE:
        # Array of ResTable_sparseTypeEntry { uint16 idx; uint16 off/4 }
        table_bytes = entry_count * 4
        if header_size + table_bytes > size:
            raise ArscError("sparse entry table out of bounds")
        pairs = []
        for i in range(entry_count):
            p = off + header_size + 4 * i
            idx, raw_off = struct.unpack_from("<HH", data, p)
            pairs.append((idx, raw_off * 4 if raw_off != 0xFFFF else NO_ENTRY))
    elif flags & FLAG_OFFSET16:
        table_bytes = entry_count * 2
        if header_size + table_bytes > size:
            raise ArscError("offset16 entry table out of bounds")
        pairs = []
        for i in range(entry_count):
            raw_off = _read_u16(data, off + header_size + 2 * i)
            pairs.append((i, raw_off * 4 if raw_off != 0xFFFF else NO_ENTRY))
    else:
        table_bytes = entry_count * 4
        if header_size + table_bytes > size:
            raise ArscError("entry offset table out of bounds")
        pairs = []
        for i in range(entry_count):
            raw_off = _read_u32(data, off + header_size + 4 * i)
            pairs.append((i, raw_off))

    for index, entry_off in pairs:
        if entry_off == NO_ENTRY:
            continue
        pos = entry_area + entry_off
        if pos + 8 > end:
            raise ArscError("resource entry out of bounds")
        entry_size = _read_u16(data, pos)
        entry_flags = _read_u16(data, pos + 2)
        if entry_size < 8:
            raise ArscError("resource entry too small")
        if entry_flags & FLAG_COMPACT:
            key_index = entry_size  # compact.key overlays the size field
            data_type = (entry_flags >> 8) & 0xFF
            value = _read_u32(data, pos + 4)
            is_complex = False
        else:
            key_index = _read_u32(data, pos + 4)
            is_complex = bool(entry_flags & FLAG_COMPLEX)
            if is_complex:
                value = 0
                data_type = 0
                if entry_size < 16:
                    raise ArscError("complex entry too small")
                # ResTable_map_entry: parent + count, followed by maps. We do
                # not resolve bag values; callers only need scalar attributes.
            else:
                vpos = pos + entry_size
                if vpos + 8 > end:
                    raise ArscError("resource value out of bounds")
                value_size = _read_u16(data, vpos)
                if value_size < 8:
                    raise ArscError("resource value too small")
                data_type = data[vpos + 3]
                value = _read_u32(data, vpos + 4)
        key = (
            pkg.key_names[key_index]
            if 0 <= key_index < len(pkg.key_names)
            else f"key{key_index}"
        )
        pkg.entries.setdefault((type_id, index), []).append(
            Entry(
                key=key,
                value_type=data_type,
                data=value,
                is_complex=is_complex,
                config=config,
            )
        )
