import argparse
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .detectors import redact_text
from .network import Scope, ScopeError, utcnow
from .reports import render
from .service import BusyError, Service
from .storage import Store

ROOT = Path(__file__).resolve().parent.parent


class Application:
    def __init__(self, data_dir, targets=(), allow_private=False, token=None, public_origin=None):
        self.store = Store(Path(data_dir) / "xunan.sqlite3")
        self.scope = Scope(targets, allow_private)
        self.service = Service(self.store, self.scope)
        self.token = token or secrets.token_urlsafe(32)
        self.public_origin = public_origin.rstrip("/") if public_origin else None
        self.allowed_hosts = set()

    def state(self):
        return {"runs": self.store.list_runs(), "targets": self.scope.allowed,
                "schedules": self.store.schedules(), "events": self.store.events(),
                "version": "0.1.0", "platform": "恒脑接口待部署配置", "allow_private": self.scope.allow_private}


class Handler(BaseHTTPRequestHandler):
    server_version = "XunAn/0.1"
    protocol_version = "HTTP/1.0"

    @property
    def app(self):
        return self.server.app

    def log_message(self, format_string, *args):
        # Access paths / headers may contain user supplied data; do not print.
        pass

    def send_bytes(self, status, body, content_type="application/json; charset=utf-8", filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if filename:
            self.send_header("Content-Disposition", 'attachment; filename="' + filename + '"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json(self, status, data):
        self.send_bytes(status, json.dumps(data, ensure_ascii=False).encode())

    def guarded(self):
        host = self.headers.get("Host", "").lower()
        if host not in self.app.allowed_hosts:
            self.send_json(403, {"error": "Host 不在允许范围内"})
            return False
        origin = self.headers.get("Origin")
        expected = self.app.public_origin or "http://" + host
        if origin and origin != expected:
            self.send_json(403, {"error": "不允许跨站请求"})
            return False
        return True

    def authenticated(self):
        token = self.headers.get("X-API-Key", "")
        if not hmac.compare_digest(token.encode(), self.app.token.encode()):
            self.send_json(401, {"error": "需要有效的 API 令牌"})
            return False
        return True

    def do_GET(self):
        if not self.guarded():
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/health":
            return self.send_json(200, {"ok": True, "version": "0.1.0"})
        if path == "/api/session":
            # Only local direct users may bootstrap a dashboard token. A public
            # reverse proxy or a hostile Host header cannot use this shortcut.
            host = self.headers.get("Host", "").split(":")[0]
            peer_local = ipaddress.ip_address(self.client_address[0]).is_loopback
            if self.app.public_origin or not peer_local or host not in ("127.0.0.1", "localhost"):
                return self.send_json(401, {"error": "请输入管理员配置的 API 令牌"})
            return self.send_json(200, {"token": self.app.token})
        if path.startswith("/api/"):
            if not self.authenticated():
                return
            if path == "/api/state":
                return self.send_json(200, self.app.state())
            match = re.fullmatch(r"/api/(runs|reports)/([a-f0-9]{32})", path)
            if match:
                run = self.app.store.get_run(match.group(2))
                if not run:
                    return self.send_json(404, {"error": "任务不存在"})
                if match.group(1) == "runs":
                    return self.send_json(200, run)
                try:
                    data, mime, ext = render(run, parse_qs(parsed.query).get("format", ["json"])[0])
                except ValueError as exc:
                    return self.send_json(400, {"error": str(exc)})
                return self.send_bytes(200, data, mime, "xunan-" + run["id"][:8] + "." + ext)
            return self.send_json(404, {"error": "接口不存在"})
        files = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
                 "/app.js": ("app.js", "application/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
        if path in files:
            name, mime = files[path]
            try:
                return self.send_bytes(200, (ROOT / "web" / name).read_bytes(), mime)
            except FileNotFoundError:
                return self.send_json(503, {"error": "前端文件缺失，请使用完整项目"})
        self.send_json(404, {"error": "页面不存在"})

    def do_POST(self):
        if not self.guarded() or not self.authenticated():
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self.send_json(415, {"error": "请使用 application/json"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 32768:
                raise ValueError("请求大小应在 1～32768 字节之间")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("请求内容必须是 JSON 对象")
            path = urlsplit(self.path).path
            if path == "/api/runs":
                return self.send_json(201, self.app.service.inspect(data))
            if path == "/api/reviews":
                if data.get("status") not in ("pending", "confirmed", "false_positive"):
                    raise ValueError("不支持的人工复核状态")
                if not isinstance(data.get("note", ""), str) or len(data.get("note", "")) > 500:
                    raise ValueError("复核备注最多 500 字")
                for key in ("run_id", "finding_id"):
                    if not isinstance(data.get(key), str) or len(data[key]) > 128:
                        raise ValueError("缺少有效的记录编号")
                self.app.store.review(data["run_id"], data["finding_id"], data["status"], redact_text(data.get("note", "")))
                return self.send_json(200, {"ok": True})
            if path == "/api/schedules":
                return self.send_json(201, self.app.service.create_schedule(data))
            match = re.fullmatch(r"/api/schedules/([a-f0-9]{32})", path)
            if match:
                return self.send_json(200, self.app.service.update_schedule(match.group(1), data.get("enabled")))
            self.send_json(404, {"error": "接口不存在"})
        except BusyError as exc:
            self.send_json(409, {"error": str(exc)})
        except (ValueError, ScopeError, UnicodeDecodeError) as exc:
            message = "JSON 请求格式有误" if isinstance(exc, json.JSONDecodeError) else str(exc)
            self.send_json(400, {"error": message})
        except KeyError:
            self.send_json(404, {"error": "任务、发现或定时计划不存在"})
        except Exception:
            # Unexpected details may contain user data. Keep response generic.
            self.send_json(500, {"error": "服务处理失败，请检查部署终端并保留任务时间"})

    def setup(self):
        super().setup()
        self.connection.settimeout(15)


def make_server(app, host="127.0.0.1", port=8765):
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.app = app
    actual_port = server.server_address[1]
    app.allowed_hosts = {"127.0.0.1:" + str(actual_port), "localhost:" + str(actual_port)}
    if app.public_origin:
        u = urlsplit(app.public_origin)
        if u.scheme != "https" or not u.netloc or u.path or u.query or u.fragment or u.username:
            server.server_close()
            raise ValueError("XUNAN_PUBLIC_ORIGIN 必须是无路径的 HTTPS 来源地址")
        app.allowed_hosts.add(u.netloc.lower())
    return server


def main():
    parser = argparse.ArgumentParser(description="巡安授权网站巡检服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", default=str(ROOT / "data"))
    args = parser.parse_args()
    token = os.environ.get("XUNAN_API_KEY")
    public_origin = os.environ.get("XUNAN_PUBLIC_ORIGIN")
    if token and len(token) < 24:
        parser.error("XUNAN_API_KEY 至少 24 个字符；请使用随机令牌")
    if args.host not in ("127.0.0.1", "localhost") and (not token or not public_origin):
        parser.error("对外监听需设置 XUNAN_API_KEY 和 XUNAN_PUBLIC_ORIGIN，并通过 HTTPS 反向代理访问")
    targets = [t.strip() for t in os.environ.get("XUNAN_ALLOWED_TARGETS", "").split(",") if t.strip()]
    try:
        app = Application(args.data_dir, targets, os.environ.get("XUNAN_ALLOW_PRIVATE") == "1", token, public_origin)
        server = make_server(app, args.host, args.port)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    worker = threading.Thread(target=app.service.scheduler, daemon=True)
    worker.start()
    print("巡安已启动：http://127.0.0.1:" + str(server.server_address[1]), flush=True)
    print("内置演示可直接使用；已配置 " + str(len(targets)) + " 个授权目标。按 Ctrl+C 退出。", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.service.stop.set()
        server.server_close()
        worker.join(timeout=1)
        # daemon request threads may still finish; process exit owns cleanup.


if __name__ == "__main__":
    main()
