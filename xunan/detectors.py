"""Deterministic, offline checks for authorized document snapshots.

``detect_document(doc, custom_keywords)`` accepts ``url``, ``status``,
``headers`` (case insensitive), ``body``, ``content_type``, ``fetched_at`` and
``source_hash``. Body content is data only: no code or regular expression from
the document or user is executed. Findings are review candidates, never proof
of exploitation. Sensitive values and URL queries are removed from evidence.

IDs identify a rule, sanitized canonical URL and redacted match class. Repeated
occurrences of the same class on one page collapse to one finding, so IDs do
not change when a secret rotates or an unrelated line is inserted.

``compare_runs`` returns four lists and ``counts``: new, persistent,
not_observed, uncertain. A missing finding becomes not_observed only when the
current run is complete AND its page was successfully inspected. This does
not establish that an issue was fixed; uninspected pages remain uncertain.
The module makes no network requests and uses only the Python standard library.
"""

import datetime
import hashlib
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


_SECRET_KEY = (
    r"(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|secret[_-]?key|private[_-]?key|"
    r"password|passwd|pwd|authorization|secret|token|密码|口令|令牌|密钥)"
)
_SECRET = re.compile(
    r"(?<![\w-])(?P<keyquote>[\"']?)(?P<key>" + _SECRET_KEY + r")"
    r"(?P=keyquote)\s*[:=：]\s*"
    r"(?:\"(?P<double>(?:\\[^\r\n]|[^\"\\\r\n])*)\"|'(?P<single>(?:\\[^\r\n]|[^'\\\r\n])*)'|"
    r"(?P<bare>[^\r\n,;<>\"'&}]+))",
    re.IGNORECASE,
)
_EMAIL = re.compile(
    r"(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9-]+)*\.[A-Z]{2,63}",
    re.IGNORECASE,
)
_PHONE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")
_IDENTITY = re.compile(
    r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}"
    r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dA-Za-z])"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    r"[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|\Z)"
)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_KNOWN_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|"
    r"sk_(?:live|test)_[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16})\b"
)
_ABSOLUTE_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_RELATIVE_QUERY = re.compile(r"(?<![\w:])(?:\.\.?/|/)[^\s<>\"']*\?[^\s<>\"']*")
_QUERY_ATTRIBUTE = re.compile(
    r"(?P<prefix>\b(?:href|src|action|data)\s*=\s*)"
    r"(?P<quote>[\"'])(?P<value>[^\"']*)(?P=quote)", re.IGNORECASE
)
_TOOL = "巡安静态规则检查器 / xunan-detector-v1"
_MARKERS = ("[敏感值已脱敏]", "[邮箱已脱敏]", "[手机号已脱敏]",
            "[身份证号已脱敏]", "[自定义敏感词已脱敏]", "[私钥内容已脱敏]")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _preserve_lines(value: str, replacement: str) -> str:
    return replacement + "\n" * value.count("\n")


def _secret_value(match: re.Match) -> str:
    return next((match.group(name) for name in ("double", "single", "bare")
                 if match.group(name) is not None), "")


def _secret_replacement(match: re.Match) -> str:
    # Keep the field name so the evidence is useful without exposing its value.
    # Already-redacted evidence may pass through sanitisation more than once
    # (storage, comparison, report). Redaction must therefore be idempotent.
    if _secret_value(match).strip() == "[敏感值已脱敏]":
        return match.group()
    return _preserve_lines(match.group(), match.group("key") + "=[敏感值已脱敏]")


def _scrub_values(text: str, custom_keywords: Optional[List[str]] = None) -> str:
    """Redact whole values before snippets are truncated, avoiding partial leaks."""
    text = _PRIVATE_KEY.sub(lambda m: _preserve_lines(m.group(), "[私钥内容已脱敏]"), text)
    text = _SECRET.sub(_secret_replacement, text)
    text = _BEARER.sub("Bearer [敏感值已脱敏]", text)
    text = _KNOWN_TOKEN.sub("[敏感值已脱敏]", text)
    text = _EMAIL.sub("[邮箱已脱敏]", text)
    text = _IDENTITY.sub("[身份证号已脱敏]", text)
    text = _PHONE.sub("[手机号已脱敏]", text)
    # Match literals only; no user-supplied expressions enter re.compile().
    for keyword in sorted(set(custom_keywords or []), key=len, reverse=True):
        if keyword:
            text = text.replace(keyword, _preserve_lines(keyword, "[自定义敏感词已脱敏]"))
    return text


def sanitize_url(url: str) -> str:
    """Remove user info, fragments and EVERY query value, including unknown keys."""
    try:
        parts = urlsplit(str(url).strip())
        netloc = parts.netloc.rsplit("@", 1)[-1].lower()
        path = _scrub_values(parts.path)
        # Query keys may themselves contain secrets, so omit keys as well.
        query = "__redacted__" if parts.query else ""
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
    except (ValueError, TypeError):
        return "[无效地址]"


def _redact_text(text: str, custom_keywords: Optional[List[str]] = None) -> str:
    text = _QUERY_ATTRIBUTE.sub(
        lambda m: m.group("prefix") + m.group("quote") +
        sanitize_url(m.group("value")) + m.group("quote"), text)
    text = _ABSOLUTE_URL.sub(lambda m: sanitize_url(m.group()), text)
    text = _RELATIVE_QUERY.sub(lambda m: sanitize_url(m.group()), text)
    return _scrub_values(text, custom_keywords)


def redact_text(text: str) -> str:
    """Remove recognized sensitive formats from notes/reports; no I/O or execution.

    This helper covers the same built-in formats as evidence redaction. Arbitrary
    private prose cannot be inferred as sensitive and should not be entered.
    """
    return _redact_text(str(text or ""))


def _is_literal_secret(match: re.Match) -> bool:
    value = _secret_value(match).strip()
    if len(value) < 4:
        return False
    if value.lower() in {"null", "none", "true", "false", "undefined", "redacted"}:
        return False
    if value.startswith(("${", "{{", "<", "[", "$")):
        return False
    if re.match(r"^(?:your[_-]|process\.|os\.|env\.|getenv|input\(|get\()", value, re.I):
        return False
    if match.group("bare") is not None and ("(" in value or value.startswith("function")):
        return False
    return True


def _valid_identity(value: str) -> bool:
    try:
        datetime.datetime.strptime(value[6:14], "%Y%m%d")
    except ValueError:
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    checksum = "10X98765432"[sum(int(a) * b for a, b in zip(value[:17], weights)) % 11]
    return value[-1].upper() == checksum


class _HTMLChecks(HTMLParser):
    def __init__(self, https: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.https = https
        self.hits: List[Tuple[str, int, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = dict(attrs)
        line = self.getpos()[0]
        for attribute in ("href", "src", "action", "data", "formaction"):
            value = attributes.get(attribute) or ""
            compact = re.sub(r"[\x00-\x20]+", "", value).lower()
            if compact.startswith("javascript:"):
                payload = compact.split(":", 1)[1].rstrip(";")
                if payload not in {"", "void(0)", "void0", "returnfalse"}:
                    self.hits.append(("html.javascript-link", line, tag + ":" + attribute))
        if (attributes.get("action") or "").strip().lower().startswith("http://") and tag == "form":
            self.hits.append(("html.http-form", line, "form:action"))
        if not self.https:
            return
        resource_attributes = {
            "script": ("src",), "iframe": ("src",), "img": ("src", "srcset"),
            "source": ("src", "srcset"), "link": ("href",), "audio": ("src",),
            "video": ("src", "poster"), "embed": ("src",), "object": ("data",),
        }
        for attribute in resource_attributes.get(tag, ()):
            if re.search(r"(?:^|[\s,])http://", attributes.get(attribute) or "", re.I):
                self.hits.append(("html.mixed-content", line, tag + ":" + attribute))

    handle_startendtag = handle_starttag


def detect_document(doc: Dict[str, Any], custom_keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Return stable, deduplicated, redacted findings for a single document."""
    keywords = [str(item) for item in (custom_keywords or []) if isinstance(item, str) and item]
    body = str(doc.get("body") or "")
    url = _scrub_values(sanitize_url(str(doc.get("url") or "")), keywords)
    observed_at = str(doc.get("fetched_at") or "")
    headers = {str(key).lower(): str(value) for key, value in (doc.get("headers") or {}).items()}
    content_type = str(doc.get("content_type") or headers.get("content-type", "")).lower()
    is_html = "html" in content_type or (not content_type and bool(re.search(r"<(?:html|head|body|form|script)\b", body, re.I)))
    https = url.lower().startswith("https://")
    redacted_lines = _redact_text(body, keywords).splitlines()
    findings: Dict[str, Dict[str, Any]] = {}

    def add(rule: str, title: str, category: str, severity: str, confidence: str,
            line: int, identity: str, impact: str, remediation: str,
            fixed_evidence: Optional[str] = None) -> None:
        match_digest = _digest(identity)
        fingerprint = _digest(rule + "\n" + url + "\n" + match_digest)
        if fingerprint in findings:
            return
        evidence = fixed_evidence if fixed_evidence is not None else (
            redacted_lines[line - 1] if 0 < line <= len(redacted_lines) else "内容已脱敏")
        # Redact before limiting length; never cut a raw credential halfway.
        if len(evidence) > 320:
            marker_positions = [evidence.find(marker) for marker in _MARKERS if marker in evidence]
            center = min(marker_positions) if marker_positions else 0
            start = max(0, center - 90)
            evidence = ("…" if start else "") + evidence[start:start + 320] + "…"
        findings[fingerprint] = {
            "id": fingerprint, "rule_id": rule, "title": title, "category": category,
            "severity": severity, "confidence": confidence, "url": url,
            "evidence": evidence, "line": max(0, int(line)), "impact": impact,
            "remediation": remediation, "tool": _TOOL, "fingerprint": fingerprint,
            "observed_at": observed_at,
        }

    def line_at(position: int) -> int:
        return body.count("\n", 0, position) + 1

    for match in _SECRET.finditer(body):
        if _is_literal_secret(match):
            add("sensitive.credential-assignment", "发现疑似凭据明文赋值", "sensitive", "high", "medium",
                line_at(match.start()), match.group("key").lower() + ":<redacted>",
                "若该值为真实且有效的凭据，公开页面或资源可能导致账号或接口被冒用；需人工确认是否为演示数据。",
                "核实凭据用途与有效性；真实泄露时撤销或轮换，并将凭据移至服务端的安全配置中。")
    for pattern, rule, title, severity, confidence, identity, impact, remediation in (
        (_EMAIL, "sensitive.email", "页面出现邮箱地址，需确认公开范围", "low", "low", "email:<redacted>",
         "邮箱格式命中不等于违规泄露；需核实是否为公开联系邮箱或个人信息。", "核实公开必要性；不应公开的邮箱应移除或脱敏。"),
        (_PHONE, "sensitive.china-phone", "页面出现疑似中国大陆手机号", "medium", "medium", "phone:<redacted>",
         "疑似个人联系方式可能被收集；测试号码和公开服务号码需要人工区分。", "核实号码归属与授权，移除或遮蔽不应公开的完整号码。"),
        (_PRIVATE_KEY, "sensitive.private-key", "页面出现私钥格式内容", "high", "high", "private-key:<redacted>",
         "私钥格式文本可能泄露身份认证能力；需要核实是否为真实密钥。", "如为真实私钥，应立即撤销或轮换，移除公开副本并排查访问记录。"),
        (_BEARER, "sensitive.bearer-token", "页面出现疑似 Bearer 令牌", "high", "medium", "bearer:<redacted>",
         "若令牌有效，获得文本的人可能使用相应接口权限。", "核实有效性，撤销已泄露令牌，并避免在公开内容中写入访问令牌。"),
        (_KNOWN_TOKEN, "sensitive.token-format", "页面出现常见访问令牌格式", "high", "medium", "token:<redacted>",
         "命中常见令牌格式，可能是演示值，也可能包含有效访问权限。", "核实是否为演示值；真实令牌应轮换并从公开文件中移除。"),
    ):
        for match in pattern.finditer(body):
            add(rule, title, "sensitive", severity, confidence, line_at(match.start()), identity, impact, remediation)
    for match in _IDENTITY.finditer(body):
        valid = _valid_identity(match.group())
        add("sensitive.china-id", "页面出现疑似身份证号码", "sensitive", "high" if valid else "medium",
            "high" if valid else "low", line_at(match.start()), "identity:<redacted>:" + str(valid),
            "号码" + ("通过日期与校验码检查，但不能证明是真实身份。" if valid else "格式相似但未通过日期或校验码检查，可能是测试数据。"),
            "核实是否为个人信息；移除不必要的完整号码，展示时进行脱敏。")
    for keyword in sorted(set(keywords)):
        position = body.find(keyword)
        if position >= 0:
            add("custom.literal." + _digest(keyword)[:12], "命中自定义敏感词", "custom", "medium", "high",
                line_at(position), "custom:<redacted>",
                "输入内容包含团队配置的字面关键词；是否构成信息泄露需结合上下文确认。",
                "人工核实该内容的公开范围，并移除或脱敏不应公开的部分。")

    if is_html:
        parser = _HTMLChecks(https)
        parser.feed(body)
        parser.close()
        descriptions = {
            "html.javascript-link": ("页面包含执行脚本的链接，需人工确认", "low", "low",
                                     "javascript: 链接可执行页面脚本；这种写法本身不能证明存在跨站脚本漏洞。",
                                     "核实链接用途与输入来源，优先使用事件处理函数，避免拼接未经处理的外部输入。"),
            "html.http-form": ("表单提交地址使用明文 HTTP", "medium", "high",
                               "若提交个人信息或凭据，传输内容可能被旁路读取或修改。",
                               "将提交地址改为 HTTPS，并检查服务器的证书与跳转配置。"),
            "html.mixed-content": ("HTTPS 页面引用明文 HTTP 资源", "medium", "high",
                                   "浏览器可能阻止该资源；允许加载的明文资源可能在传输中被修改。",
                                   "将资源地址改为 HTTPS，并检查替代资源能够正常加载。"),
        }
        for rule, line, identity in parser.hits:
            title, severity, confidence, impact, remediation = descriptions[rule]
            add(rule, title, "transport" if rule != "html.javascript-link" else "review",
                severity, confidence, line, identity, impact, remediation)
        try:
            status = int(doc.get("status", 200))
        except (ValueError, TypeError):
            status = 0
        if 200 <= status < 300:
            hardening = [
                ("content-security-policy", "缺少 CSP 响应头（加固建议）", "配置适合网站资源的 Content-Security-Policy；先评估兼容性，逐步收紧。"),
                ("x-content-type-options", "缺少 X-Content-Type-Options 响应头（加固建议）", "在响应中配置 X-Content-Type-Options: nosniff，并确保资源类型正确。"),
            ]
            if https:
                hardening.append(("strict-transport-security", "缺少 HSTS 响应头（加固建议）", "确认全站及计划包含的子域均支持 HTTPS 后，配置合适的 Strict-Transport-Security 策略。"))
            for header, title, remediation in hardening:
                if not headers.get(header, "").strip():
                    add("hardening.missing-" + header, title, "hardening", "info", "high", 0, "missing:" + header,
                        "本次 HTML 响应未提供该安全加固头。这是配置建议，不能据此认定网站存在可利用漏洞。",
                        remediation, "本次响应未提供 " + header + "；仅代表该次响应。")
    return sorted(findings.values(), key=lambda item: ({"high": 0, "medium": 1, "low": 2, "info": 3}[item["severity"]], item["line"], item["id"]))


def compare_runs(current_findings: List[Dict[str, Any]], baseline_findings: List[Dict[str, Any]],
                 inspected_urls: List[str], complete: bool) -> Dict[str, Any]:
    """Compare snapshots conservatively; absence is never reported as a fix."""
    def indexed(items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        result = {}
        for item in items:
            entry = dict(item)
            entry["url"] = sanitize_url(str(entry.get("url") or ""))
            entry["evidence"] = _redact_text(str(entry.get("evidence") or ""))
            identity = str(entry.get("fingerprint") or entry.get("id") or
                           _digest(str(entry.get("rule_id", "")) + "\n" + entry["url"] + "\n" + entry["evidence"]))
            result[identity] = entry
        return result

    current = indexed(current_findings or [])
    baseline = indexed(baseline_findings or [])
    inspected = {sanitize_url(str(url)) for url in (inspected_urls or [])}
    groups: Dict[str, Any] = {"new": [], "persistent": [], "not_observed": [], "uncertain": []}
    for key, item in sorted(current.items()):
        groups["persistent" if key in baseline else "new"].append(item)
    for key, item in sorted(baseline.items()):
        if key not in current:
            covered = bool(complete) and bool(item["url"]) and item["url"] in inspected
            groups["not_observed" if covered else "uncertain"].append(item)
    groups["counts"] = {key: len(groups[key]) for key in ("new", "persistent", "not_observed", "uncertain")}
    groups["entries"] = [dict(item, status=status)
                         for status in ("new", "persistent", "not_observed", "uncertain")
                         for item in groups[status]]
    groups["complete"] = bool(complete)
    groups["inspected_urls"] = sorted(inspected)
    groups["current_total"] = len(current)
    groups["baseline_total"] = len(baseline)
    return groups
