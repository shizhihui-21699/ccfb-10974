"""network_security_config.xml 分析。

关注两件事：
  1. cleartextTrafficPermitted —— 是否放开 HTTP 明文流量
  2. trust-anchors 里的 <certificates src="user"/> —— 是否信任用户
     自行安装的 CA（抓包 / 中间人风险）
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .axml import Element, parse_axml


@dataclass
class DomainRule:
    domains: list[str] = field(default_factory=list)
    cleartext: bool | None = None
    trust_user_ca: bool = False
    trust_system_ca: bool = False
    pinset: str | None = None


@dataclass
class NetworkSecurityModel:
    base_cleartext: bool | None = None          # base-config 的明文策略
    base_trust_user_ca: bool = False
    base_trust_system_ca: bool = False
    debug_overrides_cleartext: bool | None = None
    debug_trust_user_ca: bool = False
    domain_rules: list[DomainRule] = field(default_factory=list)
    pin_sets: dict = field(default_factory=dict)

    @property
    def any_user_ca_trusted(self) -> bool:
        if self.base_trust_user_ca or self.debug_trust_user_ca:
            return True
        return any(r.trust_user_ca for r in self.domain_rules)

    @property
    def any_cleartext_permitted(self) -> bool:
        """任意一条生效规则允许明文即视为存在明文面。"""
        vals = [self.base_cleartext, self.debug_overrides_cleartext]
        vals += [r.cleartext for r in self.domain_rules]
        return any(v is True for v in vals)


def _trust_anchors(elem: Element) -> tuple[bool, bool]:
    """返回 (信任用户 CA, 信任系统 CA)。"""
    user = system = False
    for ta in elem.findall("trust-anchors"):
        for cert in ta.findall("certificates"):
            src = cert.get("src")
            if src == "user":
                user = True
            elif src == "system":
                system = True
    return user, system


def _collect_domains(elem: Element) -> list[str]:
    out = []
    for d in elem.findall("domain"):
        # 域名是元素的 CDATA 文本节点
        include = d.get("includeSubdomains")
        name = d.text
        if name:
            out.append(str(name) + (" [含子域]" if include else ""))
    return out


class NetworkSecurityAnalyzer:
    def __init__(self, data: bytes):
        self.root = parse_axml(data)
        if self.root.tag != "network-security-config":
            raise ValueError("根元素不是 network-security-config")

    def analyze(self) -> NetworkSecurityModel:
        model = NetworkSecurityModel()

        for pin in self.root.findall("pin-set"):
            name = pin.get("name")
            digests = [
                str(c.get("digest")) for c in pin.findall("pin") if c.get("digest")
            ]
            model.pin_sets[str(name)] = digests

        base = self.root.find("base-config")
        if base is not None:
            model.base_cleartext = self._bool_or_none(
                base.get("cleartextTrafficPermitted")
            )
            user, system = _trust_anchors(base)
            model.base_trust_user_ca = user
            model.base_trust_system_ca = system

        debug = self.root.find("debug-overrides")
        if debug is not None:
            model.debug_overrides_cleartext = self._bool_or_none(
                debug.get("cleartextTrafficPermitted")
            )
            user, _system = _trust_anchors(debug)
            model.debug_trust_user_ca = user

        for rule_elem in self.root.findall("domain-config"):
            rule = DomainRule()
            rule.domains = _collect_domains(rule_elem)
            rule.cleartext = self._bool_or_none(
                rule_elem.get("cleartextTrafficPermitted")
            )
            user, system = _trust_anchors(rule_elem)
            rule.trust_user_ca = user
            rule.trust_system_ca = system
            pinset = rule_elem.get("pinset")
            if pinset:
                rule.pinset = str(pinset)
            # 嵌套 domain-config 展平为独立规则
            model.domain_rules.append(rule)
            for nested in rule_elem.findall("domain-config"):
                sub = DomainRule(
                    domains=_collect_domains(nested),
                    cleartext=self._bool_or_none(
                        nested.get("cleartextTrafficPermitted")
                    ),
                )
                u, s = _trust_anchors(nested)
                sub.trust_user_ca = u
                sub.trust_system_ca = s
                model.domain_rules.append(sub)

        return model

    @staticmethod
    def _bool_or_none(v) -> bool | None:
        if v is None:
            return None
        if isinstance(v, bool):
            return v
        return str(v).lower() == "true"


def analyze_network_config(data: bytes) -> NetworkSecurityModel:
    return NetworkSecurityAnalyzer(data).analyze()
