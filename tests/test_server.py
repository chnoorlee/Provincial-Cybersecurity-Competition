"""HTTP API integration tests using only a loopback server and synthetic data."""

import http.client
import json
import tempfile
import threading
import unittest

from xunan.server import Application, make_server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.token = "DEMO_LOCAL_API_KEY_0123456789ABCDEF"
        cls.app = Application(cls.temp.name, token=cls.token)
        cls.server = make_server(cls.app, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.host = "127.0.0.1:" + str(cls.port)
        cls.origin = "http://" + cls.host
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.app.service.stop.set()
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=2)
        cls.app.store.close()
        cls.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=dict(headers or {}))
            response = connection.getresponse()
            data = response.read()
            return response.status, {key.lower(): value for key, value in response.getheaders()}, data
        finally:
            connection.close()

    def json_request(self, method, path, payload, headers=None):
        request_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-API-Key": self.token,
        }
        request_headers.update(headers or {})
        return self.request(
            method,
            path,
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            request_headers,
        )

    def create_demo(self):
        status, headers, body = self.json_request("POST", "/api/runs", {
            "mode": "demo",
            "variant": "before",
            "authorized": True,
            "custom_keywords": ["内部资料"],
        })
        self.assertEqual(status, 201)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        return json.loads(body)

    def test_host_and_origin_guards(self):
        status, _headers, body = self.request("GET", "/health", headers={"Host": "host.invalid"})
        self.assertEqual(status, 403)
        self.assertIn("Host", json.loads(body)["error"])

        status, _headers, body = self.request(
            "GET", "/health", headers={"Host": self.host, "Origin": "https://origin.invalid"}
        )
        self.assertEqual(status, 403)
        self.assertIn("跨站", json.loads(body)["error"])

        status, _headers, body = self.request(
            "GET", "/health", headers={"Host": self.host, "Origin": self.origin}
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_authentication_and_local_session_bootstrap(self):
        status, _headers, body = self.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"token": self.token})

        status, _headers, body = self.request("GET", "/api/session", headers={"Host": "localhost:" + str(self.port)})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["token"], self.token)

        for key in (None, "DEMO_WRONG_KEY"):
            headers = {} if key is None else {"X-API-Key": key}
            with self.subTest(key=key):
                status, _response_headers, body = self.request("GET", "/api/state", headers=headers)
                self.assertEqual(status, 401)
                self.assertIn("API", json.loads(body)["error"])

        status, _headers, body = self.request("GET", "/api/state", headers={"X-API-Key": self.token})
        self.assertEqual(status, 200)
        self.assertIn("runs", json.loads(body))

        original_origin = self.app.public_origin
        self.app.public_origin = "https://dashboard.invalid"
        try:
            status, _headers, body = self.request("GET", "/api/session")
        finally:
            self.app.public_origin = original_origin
        self.assertEqual(status, 401)
        self.assertIn("管理员", json.loads(body)["error"])

    def test_create_run_returns_201_and_persisted_result_is_readable(self):
        run = self.create_demo()
        self.assertRegex(run["id"], r"^[a-f0-9]{32}$")
        self.assertEqual(run["status"], "completed")

        status, headers, body = self.request(
            "GET", "/api/runs/" + run["id"], headers={"X-API-Key": self.token}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertEqual(json.loads(body)["id"], run["id"])

    def test_post_content_type_and_size_limits(self):
        valid = b'{"mode":"demo","variant":"after","authorized":true}'
        status, _headers, _body = self.request(
            "POST",
            "/api/runs",
            body=valid,
            headers={"Content-Type": "text/plain", "X-API-Key": self.token},
        )
        self.assertEqual(status, 415)

        status, _headers, body = self.request(
            "POST",
            "/api/runs",
            body=valid,
            headers={"Content-Type": "Application/JSON", "X-API-Key": self.token},
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["status"], "completed")

        status, _headers, body = self.request(
            "POST",
            "/api/runs",
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": "32769",
                "X-API-Key": self.token,
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("32768", json.loads(body)["error"])

        prefix = b'{"mode":"demo","variant":"after","authorized":true,"padding":"'
        suffix = b'"}'
        boundary_body = prefix + b"x" * (32768 - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(boundary_body), 32768)
        status, _headers, body = self.request(
            "POST",
            "/api/runs",
            body=boundary_body,
            headers={"Content-Type": "application/json", "X-API-Key": self.token},
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["status"], "completed")

        status, _headers, body = self.request(
            "POST",
            "/api/runs",
            body=b"not-json",
            headers={"Content-Type": "application/json", "X-API-Key": self.token},
        )
        self.assertEqual(status, 400)
        self.assertIn("JSON", json.loads(body)["error"])

    def test_static_files_have_strict_content_security_policy(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertTrue(headers["content-type"].startswith("text/html"))
        policy = headers["content-security-policy"]
        for directive in (
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, policy)
        self.assertNotIn(b"<script>", body)
        self.assertIn(b'src="/app.js"', body)

    def test_report_download_headers_and_format_validation(self):
        run = self.create_demo()
        status, headers, body = self.request(
            "GET",
            "/api/reports/" + run["id"] + "?format=csv",
            headers={"X-API-Key": self.token},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/csv; charset=utf-8")
        self.assertEqual(
            headers["content-disposition"],
            'attachment; filename="xunan-' + run["id"][:8] + '.csv"',
        )
        self.assertTrue(body.startswith(b"\xef\xbb\xbf"))
        self.assertIn("发现编号".encode("utf-8"), body)

        status, _headers, body = self.request(
            "GET",
            "/api/reports/" + run["id"] + "?format=pdf",
            headers={"X-API-Key": self.token},
        )
        self.assertEqual(status, 400)
        self.assertIn("报告格式", json.loads(body)["error"])

    def test_review_note_is_redacted_before_persistence_and_export(self):
        run = self.create_demo()
        self.assertTrue(run["findings"])
        secret = "DEMO_REVIEW_SECRET_987654321"
        query = "DEMO_REVIEW_QUERY_987654321"
        email = "synthetic-review@example.invalid"
        note = (
            'API_TOKEN="' + secret + '"; see '
            "https://demo.invalid/review?opaque=" + query + " and " + email
        )
        status, _headers, body = self.json_request("POST", "/api/reviews", {
            "run_id": run["id"],
            "finding_id": run["findings"][0]["id"],
            "status": "confirmed",
            "note": note,
        })
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

        persisted = json.dumps(self.app.store.get_run(run["id"]), ensure_ascii=False)
        self.assertIn("敏感值已脱敏", persisted)
        self.assertIn("邮箱已脱敏", persisted)
        for raw in (secret, query, email):
            self.assertNotIn(raw, persisted)

        for format_name in ("json", "html", "markdown", "csv"):
            status, _headers, report = self.request(
                "GET",
                "/api/reports/" + run["id"] + "?format=" + format_name,
                headers={"X-API-Key": self.token},
            )
            with self.subTest(format=format_name):
                self.assertEqual(status, 200)
                decoded = report.decode("utf-8-sig")
                for raw in (secret, query, email):
                    self.assertNotIn(raw, decoded)


if __name__ == "__main__":
    unittest.main()
