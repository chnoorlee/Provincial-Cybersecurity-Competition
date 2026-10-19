"""Service and report integration tests.

All URL-mode crawling is replaced with an in-memory fixture.  Addresses use
loopback-only examples and no test in this module opens a network connection.
"""

import csv
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from xunan.network import Scope, ScopeError
from xunan.reports import render
from xunan.service import Service
from xunan.storage import Store


def document(url, body="synthetic page"):
    raw = body.encode("utf-8")
    return {
        "url": url,
        "status": 200,
        "headers": {"content-type": "text/plain; charset=utf-8"},
        "body": body,
        "content_type": "text/plain; charset=utf-8",
        "size": len(raw),
        "source_hash": hashlib.sha256(raw).hexdigest(),
        "fetched_at": "2026-01-02T03:04:05+00:00",
    }


def complete_coverage(visited=1):
    return {
        "complete": True,
        "errors": [],
        "visited": visited,
        "attempted": visited,
        "limit": max(visited, 1),
        "skipped": 0,
        "pending": 0,
        "scope_note": "synthetic loopback fixture",
    }


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.sqlite3")
        self.service = Service(self.store, Scope([]))

    def tearDown(self):
        self.service.stop.set()
        self.store.close()
        self.temp.cleanup()

    def test_demo_before_after_and_baseline_classifications(self):
        config = {
            "mode": "demo",
            "variant": "before",
            "authorized": True,
            "custom_keywords": ["内部资料"],
        }
        before = self.service.inspect(config)
        after = self.service.inspect(dict(config, variant="after", baseline_id=before["id"]))

        self.assertEqual(before["status"], "completed")
        self.assertGreater(before["summary"]["total"], after["summary"]["total"])
        self.assertEqual(before["comparison"]["counts"]["new"], before["summary"]["total"])
        self.assertIn("首轮检查", before["comparison"]["baseline_note"])

        groups = after["comparison"]
        self.assertTrue(groups["complete"])
        self.assertEqual(groups["counts"], {
            "new": 0,
            "persistent": 2,
            "not_observed": before["summary"]["total"] - 2,
            "uncertain": 0,
        })
        self.assertEqual({item["rule_id"] for item in groups["persistent"]}, {"sensitive.email"})
        self.assertIn("sensitive.credential-assignment", {item["rule_id"] for item in groups["not_observed"]})
        self.assertIn("html.mixed-content", {item["rule_id"] for item in groups["not_observed"]})
        self.assertTrue(all(item["status"] in groups for item in groups["entries"]))
        self.assertEqual(len(after["content_changes"]), 2)
        self.assertEqual(self.store.get_run(after["id"]), after)

    def test_changed_keyword_rules_keep_old_custom_finding_uncertain(self):
        baseline = self.service.inspect({
            "mode": "demo",
            "variant": "before",
            "authorized": True,
            "custom_keywords": ["内部资料"],
        })
        current = self.service.inspect({
            "mode": "demo",
            "variant": "before",
            "authorized": True,
            "custom_keywords": [],
            "baseline_id": baseline["id"],
        })

        comparison = current["comparison"]
        self.assertFalse(comparison["complete"])
        self.assertEqual(comparison["counts"]["not_observed"], 0)
        self.assertEqual(comparison["counts"]["uncertain"], 1)
        self.assertEqual(comparison["uncertain"][0]["category"], "custom")
        self.assertIn("规则配置发生变化", comparison["baseline_note"])

    def test_baseline_must_match_url_target(self):
        first = "http://127.0.0.1:9/allowed/one"
        second = "http://127.0.0.1:9/allowed/two"
        self.service.scope = Scope([first, second], allow_private=True)
        crawler = Mock()
        crawler.crawl.return_value = ([document(first)], complete_coverage())

        with patch("xunan.service.Crawler", return_value=crawler):
            baseline = self.service.inspect({"mode": "url", "target": first, "authorized": True})
            with self.assertRaisesRegex(ValueError, "相同目标"):
                self.service.inspect({
                    "mode": "url",
                    "target": second,
                    "authorized": True,
                    "baseline_id": baseline["id"],
                })

        crawler.crawl.assert_called_once_with(first)
        with self.assertRaisesRegex(ValueError, "找不到基线"):
            self.service.inspect({
                "mode": "url",
                "target": first,
                "authorized": True,
                "baseline_id": "0" * 32,
            })
        for invalid in ([], 0, True, "not-a-run-id"):
            with self.subTest(baseline_id=invalid), self.assertRaisesRegex(ValueError, "基线编号"):
                self.service.inspect({"mode": "demo", "authorized": True, "baseline_id": invalid})

    def test_sensitive_url_path_is_absent_from_persisted_run_and_reports(self):
        secret = "DEMO_FAKE_PATH_VALUE_987654"
        query = "DEMO_FAKE_QUERY_VALUE_987654"
        target = "http://127.0.0.1:9/allowed/api_key=" + secret
        raw_url = target + "/page?opaque=" + query
        self.service.scope = Scope([target], allow_private=True)
        crawler = Mock()
        crawler.crawl.return_value = (
            [document(raw_url, 'api_token="DEMO_FAKE_BODY_VALUE_987654"')],
            complete_coverage(),
        )

        with patch("xunan.service.Crawler", return_value=crawler):
            run = self.service.inspect({"mode": "url", "target": target, "authorized": True})

        stored = self.store.get_run(run["id"])
        serialized = json.dumps(stored, ensure_ascii=False)
        for raw in (secret, query, "DEMO_FAKE_BODY_VALUE_987654"):
            self.assertNotIn(raw, serialized)
        self.assertIn("敏感值已脱敏", serialized)
        self.assertIn("__redacted__", serialized)

        for format_name in ("json", "html", "markdown", "csv"):
            report, _mime, _extension = render(stored, format_name)
            with self.subTest(format=format_name):
                decoded = report.decode("utf-8-sig")
                self.assertNotIn(secret, decoded)
                self.assertNotIn(query, decoded)
                self.assertNotIn("DEMO_FAKE_BODY_VALUE_987654", decoded)

    def test_schedule_validation_and_updates(self):
        target = "http://127.0.0.1:9/allowed"
        self.service.scope = Scope([target], allow_private=True)

        schedule = self.service.create_schedule({
            "target": target,
            "interval_minutes": 5,
            "authorized": True,
            "custom_keywords": ["演示标记", "演示标记"],
        })
        self.assertEqual(schedule["target"], target)
        self.assertEqual(schedule["custom_keywords"], ["演示标记"])
        self.assertTrue(schedule["enabled"])
        self.assertGreater(schedule["next_run_at"], 0)

        disabled = self.service.update_schedule(schedule["id"], False)
        self.assertFalse(disabled["enabled"])
        enabled = self.service.update_schedule(schedule["id"], True)
        self.assertTrue(enabled["enabled"])

        invalid_configs = (
            {"target": target, "interval_minutes": 5, "authorized": False},
            {"target": target, "interval_minutes": 4, "authorized": True},
            {"target": target, "interval_minutes": 10081, "authorized": True},
            {"target": target, "interval_minutes": True, "authorized": True},
            {"target": target, "interval_minutes": "5", "authorized": True},
            {"target": target, "interval_minutes": 5, "authorized": True, "custom_keywords": [""]},
        )
        for config in invalid_configs:
            with self.subTest(config=config), self.assertRaises((ValueError, ScopeError)):
                self.service.create_schedule(config)
        with self.assertRaises(ScopeError):
            self.service.create_schedule({
                "target": "http://127.0.0.1:9/outside",
                "interval_minutes": 5,
                "authorized": True,
            })
        with self.assertRaises(ValueError):
            self.service.update_schedule(schedule["id"], 1)
        with self.assertRaises(KeyError):
            self.service.update_schedule("0" * 32, False)


class ReportTests(unittest.TestCase):
    @staticmethod
    def run_fixture(finding):
        return {
            "id": "a" * 32,
            "created_at": "2026-01-02T03:04:05+00:00",
            "target": "https://demo.invalid/<target>",
            "status": "completed<script>alert(1)</script>",
            "summary": {"high": 0, "medium": 0, "low": 0, "info": 0, "total": 1},
            "findings": [finding],
            "comparison": {"counts": {"new": 1, "persistent": 0, "not_observed": 0, "uncertain": 0}},
            "coverage": {
                "visited": 1,
                "scope_note": "<img src=x onerror=alert(2)>",
                "errors": [{"url": "synthetic", "reason": "</pre><script>alert(3)</script>"}],
            },
            "limitations": ["<svg onload=alert(4)>"]
        }

    def test_html_report_escapes_all_rendered_fields(self):
        finding = {
            "id": "finding",
            "rule_id": "rule<script>alert(5)</script>",
            "severity": "high",
            "title": "</h2><script>alert(6)</script>",
            "url": "https://demo.invalid/&quot;<script>alert(7)</script>",
            "line": "1<script>alert(8)</script>",
            "evidence": "</pre><script>alert(9)</script>",
            "impact": "<img src=x onerror=alert(10)>",
            "remediation": "<svg onload=alert(11)>",
            "review_status": "pending<script>alert(12)</script>",
        }
        data, mime, extension = render(self.run_fixture(finding), "html")
        report = data.decode("utf-8")

        self.assertEqual(mime, "text/html; charset=utf-8")
        self.assertEqual(extension, "html")
        self.assertNotIn("<script>", report)
        self.assertNotIn("<img src=x", report)
        self.assertNotIn("<svg onload", report)
        self.assertIn("&lt;script&gt;alert(6)&lt;/script&gt;", report)
        self.assertIn("&lt;img src=x onerror=alert(2)&gt;", report)

    def test_csv_report_neutralizes_formula_cells(self):
        values = [
            "=1+1",
            " +SUM(1,1)",
            "-2+3",
            "@synthetic",
            "\t=HYPERLINK(\"https://demo.invalid\")",
            "=6",
            "+evidence",
            "-pending",
            "@remediation",
        ]
        keys = ("id", "rule_id", "severity", "title", "url", "line", "evidence", "review_status", "remediation")
        finding = dict(zip(keys, values))
        data, mime, extension = render(self.run_fixture(finding), "csv")
        rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))

        self.assertEqual(mime, "text/csv; charset=utf-8")
        self.assertEqual(extension, "csv")
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(rows[1]), len(values))
        self.assertTrue(all(cell.startswith("'") for cell in rows[1]))
        self.assertEqual([cell[1:] for cell in rows[1]], values)

    def test_csv_preserves_zero_line_number_for_header_findings(self):
        finding = {
            "id": "finding", "rule_id": "hardening.header", "severity": "info",
            "title": "header", "url": "https://demo.invalid/", "line": 0,
            "evidence": "header missing", "review_status": "pending", "remediation": "add header",
        }
        data, _mime, _extension = render(self.run_fixture(finding), "csv")
        rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))
        self.assertEqual(rows[1][5], "0")


if __name__ == "__main__":
    unittest.main()
