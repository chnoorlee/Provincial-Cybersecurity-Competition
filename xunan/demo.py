"""Synthetic fixtures. Reserved .invalid domains; no real personal data."""
import hashlib
from .network import utcnow

BASE = "https://demo.xunan.invalid"
BEFORE = {
    "/index.html": '''<!doctype html><html lang="zh-CN"><head><title>巡安演示站</title></head>
<body><h1>校园信息站（全为虚构演示内容）</h1>
<p>公开联络地址 demo-contact@example.invalid</p>
<a href="/notice.html">公告</a><script src="http://demo.xunan.invalid/app.js"></script>
<form action="http://demo.xunan.invalid/feedback"><input name="message"></form>
<p>内部资料：DEMO_INTERNAL_ONLY 项目预算草案</p></body></html>''',
    "/notice.html": '''<!doctype html><html><head><title>测试公告</title></head><body>
<h1>技术支持说明（虚构）</h1><p>练习用邮箱 training@example.invalid</p>
<p>这个公开邮箱可能是正常联系方式，请人工复核，勿自动当成泄露。</p>
<a href="/index.html">首页</a></body></html>''',
    "/app.js": '''// Intentionally exposed synthetic fixture, never a real credential.
const api_key = "DEMO_ONLY_NOT_A_REAL_TOKEN_123456";
const environment = "demo";
''',
}
AFTER = {
    "/index.html": '''<!doctype html><html lang="zh-CN"><head><title>巡安演示站</title></head>
<body><h1>校园信息站（整改后样例）</h1><p>公开联络地址 demo-contact@example.invalid</p>
<a href="/notice.html">公告</a><script src="/app.js"></script>
<form action="/feedback"><input name="message"></form></body></html>''',
    "/notice.html": BEFORE["/notice.html"],
    "/app.js": '// Demo credential removed; server retrieves credentials from its private environment.\nconst environment = "demo";\n',
}


def documents(variant="before"):
    items = AFTER if variant == "after" else BEFORE
    result = []
    for path, body in items.items():
        ctype = "application/javascript" if path.endswith(".js") else "text/html; charset=utf-8"
        headers = {"content-type": ctype}
        if variant == "after":
            headers.update({"content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "strict-transport-security": "max-age=31536000"})
        result.append({"url": BASE + path, "status": 200, "headers": headers, "body": body,
                       "content_type": ctype, "size": len(body.encode()),
                       "source_hash": hashlib.sha256(body.encode()).hexdigest(), "fetched_at": utcnow()})
    return result

