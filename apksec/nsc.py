"""Android Network Security Config parsing and evaluation.

Covers the security-relevant subset: base-config and domain-config cleartext
policy, trust anchors (system / user / bundled), certificate pin sets and
debug-overrides.  Also computes the *effective* defaults when no config is
present, which depend on targetSdkVersion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import binxml, manifest as manifest_mod
from .arsc import ResourceTable

MAX_NSC_BYTES = 4 * 1024 * 1024


@dataclass
class TrustAnchors:
    system: bool = False
    user: bool = False
    bundled: list[str] = field(default_factory=list)


@dataclass
class DomainRule:
    domain: str
    include_subdomains: bool = True
    cleartext: Optional[bool] = None
    trust: Optional[TrustAnchors] = None
    pins: list[str] = field(default_factory=list)
    inherited: bool = True


@dataclass
class NscConfig:
    found: bool = False
    path: Optional[str] = None
    resolved_via: Optional[str] = None
    parse_error: Optional[str] = None
    base_cleartext: Optional[bool] = None
    base_trust: Optional[TrustAnchors] = None
    base_pins: list[str] = field(default_factory=list)
    domains: list[DomainRule] = field(default_factory=list)
    debug_cleartext: Optional[bool] = None
    debug_trust: Optional[TrustAnchors] = None
    has_debug_overrides: bool = False
    warnings: list[str] = field(default_factory=list)

    def domains_allowing_cleartext(self) -> list[DomainRule]:
        return [d for d in self.domains if d.cleartext is True]

    def domains_trusting_user_certs(self) -> list[DomainRule]:
        return [d for d in self.domains if d.trust is not None and d.trust.user]


def _bool_attr(el: binxml.Element, name: str) -> Optional[bool]:
    return el.flag(name)


def _parse_trust_anchors(el: binxml.Element, warnings: list[str]) -> TrustAnchors:
    ta = TrustAnchors()
    for child in el.children:
        if child.name == "certificates":
            src = (child.value("src") or "").strip()
            if src == "system":
                ta.system = True
            elif src == "user":
                ta.user = True
            elif src:
                ta.bundled.append(src)
    if not ta.system and not ta.user and not ta.bundled:
        warnings.append("<trust-anchors> contains no usable <certificates> entry")
    return ta


def _parse_pin_set(el: binxml.Element) -> tuple[list[str], int]:
    pins: list[str] = []
    expiration = 0
    for pin in el.children_named("pin"):
        v = pin.value("digest") or pin.value("value", ns=None)
        if v:
            pins.append(v)
    exp = el.attr("expiration")
    if exp is not None:
        try:
            expiration = int(exp.value or "0")
        except ValueError:
            expiration = 0
    return pins, expiration


def _parse_debug_overrides(el: binxml.Element, cfg: NscConfig) -> None:
    cfg.has_debug_overrides = True
    cfg.debug_cleartext = _bool_attr(el, "cleartextTrafficPermitted")
    for trust_el in el.children_named("trust-anchors"):
        cfg.debug_trust = _parse_trust_anchors(trust_el, cfg.warnings)


def parse_nsc_document(doc: binxml.Document, path: str) -> NscConfig:
    cfg = NscConfig(found=True, path=path)
    root = doc.root
    if root is None or root.name != "network-security-config":
        cfg.parse_error = (
            f"root element is <{root.name if root else 'none'}>, "
            "expected <network-security-config>"
        )
        return cfg
    for child in root.children:
        if child.name == "base-config":
            cfg.base_cleartext = _bool_attr(child, "cleartextTrafficPermitted")
            for trust_el in child.children_named("trust-anchors"):
                cfg.base_trust = _parse_trust_anchors(trust_el, cfg.warnings)
            for pin_el in child.children_named("pin-set"):
                pins, _exp = _parse_pin_set(pin_el)
                cfg.base_pins.extend(pins)
        elif child.name == "domain-config":
            rule = _parse_domain_config(child, cfg, parent=None)
            cfg.domains.extend(rule)
        elif child.name == "debug-overrides":
            _parse_debug_overrides(child, cfg)
    return cfg


def _parse_domain_config(
    el: binxml.Element, cfg: NscConfig, parent: Optional[DomainRule]
) -> list[DomainRule]:
    cleartext = _bool_attr(el, "cleartextTrafficPermitted")
    trust = None
    pins: list[str] = []
    domains: list[DomainRule] = []
    inherit = el.flag("inherit")
    inherited = True if inherit is None else inherit
    if parent is not None and inherited:
        if cleartext is None:
            cleartext = parent.cleartext
        trust = parent.trust
        pins = list(parent.pins)
    for trust_el in el.children_named("trust-anchors"):
        trust = _parse_trust_anchors(trust_el, cfg.warnings)
    for pin_el in el.children_named("pin-set"):
        p, _exp = _parse_pin_set(pin_el)
        pins.extend(p)
    for dom in el.children_named("domain"):
        # The domain name is element text in aapt-compiled configs; a few
        # hand-written variants use an attribute instead.
        name = (dom.text or "").strip() or (dom.value("name") or "").strip()
        if not name:
            cfg.warnings.append("<domain> element without a domain name")
            continue
        inc = dom.flag("includeSubdomains")
        domains.append(
            DomainRule(
                domain=name,
                include_subdomains=True if inc is None else inc,
                cleartext=cleartext,
                trust=trust,
                pins=pins,
                inherited=inherited,
            )
        )
    for nested in el.children_named("domain-config"):
        child_rule_parent = DomainRule(
            domain="<nested>",
            cleartext=cleartext,
            trust=trust,
            pins=pins,
        )
        domains.extend(_parse_domain_config(nested, cfg, child_rule_parent))
    return domains


def _find_nsc_path(apk, res_name: str, arsc_value: Optional[str] = None) -> Optional[str]:
    """Locate the compiled XML file backing the network security config.

    The resource table's value is authoritative: release builds routinely
    obfuscate resource file names (``res/8G.xml``), and resource
    shrinking/optimisation can rename or relocate them.  Only when the table
    gives no usable path do we fall back to the conventional
    ``res/xml/network_security_config.xml`` layout.
    """
    if arsc_value:
        candidate = arsc_value.lstrip("/")
        if not candidate.startswith("res/"):
            candidate = "res/" + candidate
        if apk.get_entry(candidate) is not None:
            return candidate

    type_name, _, key = res_name.partition("/")
    if not type_name or not key:
        return None
    target = f"{key}.xml"
    candidates = []
    for e in apk.iter_entries():
        if e.is_directory:
            continue
        parts = e.name.split("/")
        if len(parts) != 3 or parts[0] != "res":
            continue
        dir_name = parts[1]
        if not (dir_name == type_name or dir_name.startswith(type_name + "-")):
            continue
        if parts[-1] == target:
            candidates.append(e.name)
    if not candidates:
        return None
    candidates.sort(key=len)
    return candidates[0]


def load_nsc(apk, mf: manifest_mod.Manifest, res: Optional[ResourceTable]) -> NscConfig:
    attr = None
    if mf.application is not None:
        attr = mf.application.attr("networkSecurityConfig")
    if attr is None or attr.display in (None, ""):
        return NscConfig(found=False)

    res_name: Optional[str] = None
    referenced_id: Optional[int] = None
    arsc_value: Optional[str] = None
    if attr.value_type in (binxml.TYPE_REFERENCE, binxml.TYPE_DYNAMIC_REFERENCE):
        referenced_id = attr.data
        if res is not None:
            hit = res.lookup(attr.data)
            if hit is not None:
                res_name = hit[0]
                arsc_value = res.string_value(hit[1])
    display = (attr.display or "").strip()
    if display.startswith("@") and not display.startswith("@0x") and not display.startswith("@dynamic/"):
        res_name = display[1:].lstrip("+")
    if res_name is None and referenced_id is not None:
        return NscConfig(
            found=True,
            resolved_via=f"resource 0x{referenced_id:08x}",
            parse_error=(
                f"cannot resolve resource 0x{referenced_id:08x} to a file name "
                "(resources.arsc missing or unreadable)"
            ),
        )
    if res_name is None:
        return NscConfig(
            found=True,
            resolved_via=display,
            parse_error=f"unrecognised networkSecurityConfig value {display!r}",
        )

    path = _find_nsc_path(apk, res_name, arsc_value)
    cfg = NscConfig(found=True, resolved_via=res_name)
    if path is None:
        cfg.parse_error = f"resource {res_name!r} has no matching file in the APK"
        return cfg
    cfg.path = path
    try:
        data = apk.read_entry_safe(path, max_size=MAX_NSC_BYTES)
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        cfg.parse_error = f"cannot read {path}: {exc}"
        return cfg
    if data is None:
        cfg.parse_error = f"{path} vanished while reading"
        return cfg
    try:
        doc = binxml.parse_axml(data)
        parsed = parse_nsc_document(doc, path)
    except binxml.BinXmlError as exc:
        cfg.parse_error = f"malformed network security config: {exc}"
        return cfg
    # Preserve resolution metadata on the parsed config.
    parsed.resolved_via = res_name
    return parsed


# ---------------------------------------------------------------------------
# Effective policy
# ---------------------------------------------------------------------------


@dataclass
class EffectivePolicy:
    target_sdk: Optional[int]
    # Global cleartext for app traffic
    cleartext_global: bool
    cleartext_source: str
    # Whether user-installed CAs are trusted for all domains
    trusts_user_cas: bool
    user_ca_source: str
    debug_overrides_active: bool
    nsc: NscConfig


def compute_effective_policy(mf: manifest_mod.Manifest, cfg: NscConfig) -> EffectivePolicy:
    target = mf.target_sdk
    sdk_for_defaults = target if target is not None else 1

    # --- cleartext ---
    if cfg.found and cfg.parse_error is None:
        if cfg.base_cleartext is not None:
            cleartext = cfg.base_cleartext
            source = "network_security_config base-config"
        elif mf.uses_cleartext_traffic is not None:
            # usesCleartextTraffic is ignored when an NSC is present, but the
            # platform's default base-config still derives from it on API 28+.
            cleartext = mf.uses_cleartext_traffic
            source = "manifest usesCleartextTraffic (NSC present, no base-config override)"
        else:
            cleartext = sdk_for_defaults >= 28
            cleartext = not cleartext
            source = "platform default (targetSdk >= 28 blocks cleartext)" if sdk_for_defaults >= 28 else "platform default (targetSdk < 28 permits cleartext)"
    else:
        if mf.uses_cleartext_traffic is not None:
            cleartext = mf.uses_cleartext_traffic
            source = "manifest usesCleartextTraffic"
        elif sdk_for_defaults >= 28:
            cleartext = False
            source = "platform default (targetSdk >= 28)"
        else:
            cleartext = True
            source = "platform default (targetSdk < 28)"
        if cfg.found and cfg.parse_error:
            source += "; network security config could not be parsed"

    # --- user CAs ---
    if cfg.found and cfg.parse_error is None:
        base_trust = cfg.base_trust
        if base_trust is not None:
            trusts_user = base_trust.user
            source_ca = "network_security_config base-config trust-anchors"
        else:
            trusts_user = sdk_for_defaults <= 23
            source_ca = (
                "platform default (targetSdk <= 23 trusts user CAs)"
                if trusts_user
                else "platform default (system CAs only)"
            )
    else:
        trusts_user = sdk_for_defaults <= 23
        source_ca = (
            "platform default (targetSdk <= 23 trusts user CAs)"
            if trusts_user
            else "platform default (system CAs only)"
        )
    debug_active = bool(mf.debuggable) and cfg.has_debug_overrides
    return EffectivePolicy(
        target_sdk=target,
        cleartext_global=cleartext,
        cleartext_source=source,
        trusts_user_cas=trusts_user,
        user_ca_source=source_ca,
        debug_overrides_active=debug_active,
        nsc=cfg,
    )
