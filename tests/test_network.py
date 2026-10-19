"""Crawler boundaries: every HTTP request here stays on a local mock server.

DNS/pinning tests use mocks and never connect to their example public address.
"""

import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

from xunan.network import Crawler, Scope, ScopeError, normalize_url


class NormalizeAndScopeTests(unittest.TestCase):
    def test_normalize_removes_query_fragment_and_default_port(self):
        self.assertEqual(normalize_url("HTTPS://Example.Invalid:443/allowed?q=secret#fragment"),
                         "https://example.invalid/allowed")

    def test_rejects_non_http_userinfo_controls_and_path_traversal(self):
        for url in ("file:///etc/passwd", "http://user:pass@example.invalid/", "http://example.invalid/../outside",
                    "http://example.invalid/allowed/%2e%2e/outside", "http://example.invalid/allowed/%252e%252e/outside",
                    "http://example.invalid/a\\b", "http://example.invalid/a%0db", "http://example.invalid/a b"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                normalize_url(url)

    def test_rejects_ambiguous_semicolon_and_space_traversal(self):
        # Tomcat-style semicolon stripping / IIS-style trailing-space trimming
        # must not reinterpret an allowed prefix as a parent traversal.
        for url in ("https://example.invalid/allowed/..;/outside",
                    "https://example.invalid/allowed/%2e%2e;arg/outside",
                    "https://example.invalid/allowed/..%20/outside"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                normalize_url(url)

    def test_scope_matches_exact_origin_and_path_segment(self):
        scope = Scope(["https://example.invalid/allowed"])
        self.assertTrue(scope.permits("https://example.invalid/allowed"))
        self.assertTrue(scope.permits("https://example.invalid/allowed/child"))
        for target in ("https://example.invalid/allowed-other", "http://example.invalid/allowed",
                       "https://example.invalid:8443/allowed", "https://sub.example.invalid/allowed",
                       "https://evil.invalid/allowed", "https://example.invalid/outside"):
            with self.subTest(target=target):
                self.assertFalse(scope.permits(target))

    def test_private_or_mixed_dns_answers_block_whole_request(self):
        scope = Scope(["https://example.invalid/"])
        for addresses in (("127.0.0.1",), ("93.184.216.34", "10.0.0.1"), ("::1",), ("169.254.169.254",)):
            records = [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses]
            with self.subTest(addresses=addresses), patch("xunan.network.socket.getaddrinfo", return_value=records), self.assertRaises(ScopeError):
                scope.addresses("https://example.invalid/")

    def test_empty_dns_answers_block_request(self):
        with patch("xunan.network.socket.getaddrinfo", return_value=[]), self.assertRaises(ScopeError):
            Scope(["https://example.invalid/"]).addresses("https://example.invalid/")

    def test_public_dns_is_pinned_and_original_host_is_preserved(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        response = MagicMock(status=200)
        response.getheaders.return_value = [("Content-Type", "text/html"), ("Set-Cookie", "session=DEMO")]
        response.read.return_value = b"<html>synthetic</html>"
        response.read1.side_effect = [b"<html>synthetic</html>", b""]
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch("xunan.network.socket.getaddrinfo", return_value=records) as resolve, patch("xunan.network.PinnedHTTPConnection", return_value=connection) as factory:
            result = Crawler(Scope(["http://example.invalid/allowed"])).fetch("http://example.invalid/allowed?token=NEVER_SENT")
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(factory.call_args.args[:3], ("example.invalid", 80, "93.184.216.34"))
        request = connection.request.call_args
        self.assertEqual(request.args, ("GET", "/allowed"))
        self.assertEqual(request.kwargs["headers"]["Host"], "example.invalid")
        self.assertNotIn("Cookie", request.kwargs["headers"])
        self.assertNotIn("Authorization", request.kwargs["headers"])
        self.assertNotIn("set-cookie", result["headers"])
        connection.close.assert_called_once()


class MockSite(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.seen.append((self.command, self.path))
        path = self.path
        redirects = {
            "/allowed/outside": "/escape",
            "/allowed/external": "http://outside.invalid/no-contact",
            "/allowed/chain1": "/allowed/chain2",
            "/allowed/chain2": "/allowed/chain3",
            "/allowed/loop1": "/allowed/loop2",
            "/allowed/loop2": "/allowed/loop1",
            "/allowed/stateful": "/allowed/delete",
        }
        if path in redirects:
            self.send_response(302)
            self.send_header("Location", redirects[path])
            self.end_headers()
            return
        status, content_type, body = 200, "text/html", b"<html>synthetic mock</html>"
        if path == "/allowed/index":
            body = b'''<a href="/allowed/a">A</a><a href="/allowed/b">B</a><a href="/allowed/a">duplicate</a>
<a href="/allowed/search?q=NEVER_SENT">query</a><a href="/allowed/delete">delete</a>
<a href="/escape">out of path</a><a href="http://outside.invalid/">external</a>
<form action="/allowed/form" method="post"><input name="secret"></form>'''
        elif path == "/allowed/big":
            body = b"X" * 200
        elif path == "/allowed/nontext":
            content_type, body = "application/octet-stream", b"DATA"
        elif path == "/allowed/error":
            status, body = 500, b"error body not inspected"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if path == "/allowed/compressed":
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class LocalCrawlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockSite)
        cls.server.daemon_threads = True
        cls.server.seen = []
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=2)

    def setUp(self):
        self.server.seen.clear()
        self.scope = Scope([self.base + "/allowed"], allow_private=True)

    def crawl(self, suffix, **kwargs):
        with patch("xunan.network.time.sleep"):
            return Crawler(self.scope, **kwargs).crawl(self.base + suffix)

    def test_only_in_scope_readonly_links_are_fetched(self):
        documents, coverage = self.crawl("/allowed/index")
        self.assertEqual(self.server.seen, [("GET", "/allowed/index"), ("GET", "/allowed/a"), ("GET", "/allowed/b")])
        self.assertEqual(len(documents), 3)
        self.assertGreaterEqual(coverage["skipped"], 4)
        self.assertTrue(coverage["complete"])

    def test_page_budget_keeps_coverage_partial(self):
        documents, coverage = self.crawl("/allowed/index", max_pages=2)
        self.assertEqual(len(self.server.seen), 2)
        self.assertEqual(coverage["attempted"], 2)
        self.assertGreater(coverage["pending"], 0)
        self.assertFalse(coverage["complete"])

    def test_redirects_count_toward_attempt_budget(self):
        documents, coverage = self.crawl("/allowed/chain1", max_pages=2)
        self.assertEqual(self.server.seen, [("GET", "/allowed/chain1"), ("GET", "/allowed/chain2")])
        self.assertEqual(documents, [])
        self.assertEqual(coverage["attempted"], 2)
        self.assertFalse(coverage["complete"])

    def test_outside_redirects_never_make_second_request(self):
        for path in ("/allowed/outside", "/allowed/external"):
            self.server.seen.clear()
            documents, coverage = self.crawl(path)
            self.assertEqual(self.server.seen, [("GET", path)])
            self.assertEqual(documents, [])
            self.assertFalse(coverage["complete"])
            self.assertTrue(coverage["errors"])

    def test_stateful_redirect_is_not_requested(self):
        documents, coverage = self.crawl("/allowed/stateful")
        self.assertEqual(self.server.seen, [("GET", "/allowed/stateful")])
        self.assertFalse(coverage["complete"])

    def test_direct_stateful_target_is_not_requested(self):
        try:
            self.crawl("/allowed/delete")
        except ScopeError:
            pass
        self.assertEqual(self.server.seen, [])

    def test_redirect_cycle_stops_without_false_complete(self):
        documents, coverage = self.crawl("/allowed/loop1")
        self.assertEqual(len(self.server.seen), 2)
        self.assertFalse(coverage["complete"])
        self.assertTrue(coverage["errors"])

    def test_size_type_encoding_and_http_failure_remain_uninspected(self):
        for path in ("/allowed/big", "/allowed/nontext", "/allowed/compressed", "/allowed/error"):
            with self.subTest(path=path):
                documents, coverage = self.crawl(path, max_bytes=40)
                self.assertEqual(documents, [])
                self.assertEqual(coverage["visited"], 0)
                self.assertFalse(coverage["complete"])

    def test_private_network_requires_explicit_operator_option(self):
        scope = Scope([self.base + "/allowed"], allow_private=False)
        documents, coverage = Crawler(scope).crawl(self.base + "/allowed/a")
        self.assertEqual(self.server.seen, [])
        self.assertEqual(documents, [])
        self.assertFalse(coverage["complete"])


if __name__ == "__main__":
    unittest.main()
