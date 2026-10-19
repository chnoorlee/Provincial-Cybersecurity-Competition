"""Read-only bounded crawling with exact scope checks and DNS-pinned sockets.

No credentials, cookies, form submissions, JS execution, proxy environment, or
automatic redirect handling. Every redirect/resource is checked before a socket
is opened. Private addresses require an explicit operator configuration.
"""
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


class ScopeError(ValueError):
    pass


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_url(value):
    if not isinstance(value, str) or len(value) > 2048 or re.search(r"[\x00-\x20\\]", value):
        raise ScopeError("网址为空、过长，或含有不允许的字符")
    try:
        u = urlsplit(value)
        if u.scheme.lower() not in ("http", "https") or not u.hostname:
            raise ScopeError("只支持完整的 HTTP 或 HTTPS 网址")
        if u.username is not None or u.password is not None:
            raise ScopeError("网址不能包含账号或密码")
        host = u.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = u.port
    except (ValueError, UnicodeError) as exc:
        raise ScopeError("网址格式无效") from exc
    decoded = unquote(u.path or "/")
    # Reject ambiguous server-side normalisations (Tomcat path parameters,
    # IIS trailing spaces) rather than guessing how the origin interprets them.
    if re.search(r"[\x00-\x20\\;]", decoded) or any(x in ("..", ".") for x in decoded.split("/")):
        raise ScopeError("不允许路径跳转或控制字符")
    if "%" in decoded:  # Disallow ambiguous double-encoded traversal/separators.
        raise ScopeError("不支持重复编码的路径")
    path = quote(decoded, safe="/-._~!$&'()*+,;=:@")
    hostpart = "[" + host + "]" if ":" in host else host
    if port and port != (443 if u.scheme.lower() == "https" else 80):
        hostpart += ":" + str(port)
    # Query strings may contain credentials or trigger stateful GET actions.
    # They are never requested or persisted by this crawler.
    return urlunsplit((u.scheme.lower(), hostpart, path, "", ""))


class Scope:
    def __init__(self, allowed_targets, allow_private=False):
        self.allowed = [normalize_url(x) for x in allowed_targets]
        self.allow_private = allow_private

    def permits(self, url):
        u = urlsplit(normalize_url(url))
        for target in self.allowed:
            a = urlsplit(target)
            prefix = a.path.rstrip("/")
            if (a.scheme, a.netloc) == (u.scheme, u.netloc) and (
                not prefix or u.path == prefix or u.path.startswith(prefix + "/")
            ):
                return True
        return False

    def require(self, url):
        clean = normalize_url(url)
        if not self.permits(clean):
            raise ScopeError("目标不在服务端配置的授权范围内")
        if STATEFUL_PATH.search(urlsplit(clean).path):
            raise ScopeError("疑似退出、删除、重置或交易路径，已阻止只读访问")
        return clean

    def addresses(self, url):
        clean = self.require(url)
        u = urlsplit(clean)
        port = u.port or (443 if u.scheme == "https" else 80)
        records = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(r[4][0] for r in records))
        if not addresses:
            raise ScopeError("域名没有可用地址")
        for addr in addresses:
            ip = ipaddress.ip_address(addr)
            if not self.allow_private and not ip.is_global:
                raise ScopeError("目标解析到内网、回环或保留地址，已阻止访问")
        return addresses, port


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, port, address, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class PinnedHTTPSConnection(PinnedHTTPConnection):
    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        # Never submit a form, execute scripts, or request arbitrary methods.
        if tag in ("a", "link") and fields.get("href"):
            self.items.append(fields["href"])
        if tag in ("script", "iframe") and fields.get("src"):
            self.items.append(fields["src"])


SKIP_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".mp4", ".zip", ".pdf", ".docx")
STATEFUL_PATH = re.compile(r"(?:^|[/._-])(logout|signout|delete|remove|reset|unsubscribe|checkout|purchase)(?:[/._-]|$)", re.I)
TEXT_TYPES = ("text/", "application/json", "application/javascript", "application/xml", "application/xhtml+xml")


class Crawler:
    def __init__(self, scope, max_pages=12, delay=0.3, timeout=5, max_bytes=512 * 1024, page_deadline=15):
        self.scope = scope
        self.max_pages = max(1, min(int(max_pages), 30))
        self.delay = max(0.25, delay)
        self.timeout = min(max(timeout, 1), 10)
        self.max_bytes = max_bytes
        self.page_deadline = min(max(page_deadline, self.timeout), 30)

    def fetch(self, url):
        started = time.monotonic()
        url = self.scope.require(url)
        addresses, port = self.scope.addresses(url)
        u = urlsplit(url)
        connection_type = PinnedHTTPSConnection if u.scheme == "https" else PinnedHTTPConnection
        conn = connection_type(u.hostname, port, addresses[0], self.timeout)
        try:
            conn.request("GET", u.path or "/", headers={
                "Host": u.netloc, "User-Agent": "XunAn-Authorized-Inspection/0.1",
                "Accept": "text/html,application/json,text/plain,application/javascript;q=0.8",
                "Accept-Encoding": "identity", "Connection": "close",
            })
            response = conn.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            if response.status in (301, 302, 303, 307, 308):
                redirect = self.scope.require(urljoin(url, headers.get("location", "")))
                return {"redirect": redirect, "url": url, "status": response.status}
            content_type = headers.get("content-type", "").lower()
            if not any(content_type.startswith(t) for t in TEXT_TYPES):
                raise ScopeError("非文本资源已跳过（本版不解析图片、PDF或压缩包）")
            if headers.get("content-encoding", "identity").lower() not in ("", "identity"):
                raise ScopeError("压缩响应已跳过")
            chunks = []
            size = 0
            reader = getattr(response, "read1", response.read)
            while size <= self.max_bytes:
                remaining_time = self.page_deadline - (time.monotonic() - started)
                if remaining_time <= 0:
                    raise ScopeError("页面读取超过绝对时间限制，未纳入检查")
                sock = getattr(conn, "sock", None)
                if sock is not None and hasattr(sock, "settimeout"):
                    sock.settimeout(min(self.timeout, remaining_time))
                chunk = reader(min(64 * 1024, self.max_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            if len(raw) > self.max_bytes:
                raise ScopeError("响应超过单页 512 KB 限制，未纳入检查")
            if response.status >= 400:
                raise ScopeError("网站返回 HTTP " + str(response.status) + "，该页面未纳入检查")
            match = re.search(r"charset\s*=\s*[\"']?([\w-]+)", content_type)
            encoding = match.group(1) if match else "utf-8"
            try:
                body = raw.decode(encoding, errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")
            # Never retain cookies or arbitrary response headers.
            safe_headers = {k: v for k, v in headers.items() if k in (
                "content-type", "content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options"
            )}
            return {"url": url, "status": response.status, "headers": safe_headers,
                    "body": body, "content_type": content_type, "size": len(raw),
                    "source_hash": hashlib.sha256(raw).hexdigest(), "fetched_at": utcnow()}
        finally:
            conn.close()

    def crawl(self, target):
        queue = [self.scope.require(target)]
        seen, documents, errors = set(), [], []
        skipped = 0
        # Budget counts all attempted requests, including redirects and failures.
        while queue and len(seen) < self.max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if len(seen) > 1:
                time.sleep(self.delay)
            try:
                doc = self.fetch(url)
                if "redirect" in doc:
                    if doc["redirect"] in seen:
                        errors.append({"url": url, "reason": "重定向循环或重复目标，覆盖待确认"})
                    else:
                        queue.append(doc["redirect"])
                    continue
                documents.append(doc)
                if "html" in doc["content_type"]:
                    links = Links()
                    links.feed(doc["body"])
                    for link in links.items[:300]:
                        try:
                            parsed = urlsplit(link)
                            if parsed.query or parsed.fragment and not parsed.path:
                                skipped += 1
                                continue
                            clean = normalize_url(urljoin(url, link))
                            path = urlsplit(clean).path
                            if not self.scope.permits(clean) or path.lower().endswith(SKIP_EXTENSIONS) or STATEFUL_PATH.search(path):
                                skipped += 1
                                continue
                            if clean not in seen and clean not in queue:
                                queue.append(clean)
                        except (ScopeError, ValueError):
                            skipped += 1
            except (OSError, http.client.HTTPException, ScopeError, ValueError) as exc:
                reason = str(exc) if isinstance(exc, ScopeError) else "连接、证书或响应读取失败"
                errors.append({"url": url, "reason": reason})
        return documents, {"complete": not errors and not queue, "errors": errors,
                           "visited": len(documents), "attempted": len(seen),
                           "limit": self.max_pages, "skipped": skipped, "pending": len(queue),
                           "scope_note": "仅本次入口可发现的静态文本资源；不代表整个网站已覆盖"}
