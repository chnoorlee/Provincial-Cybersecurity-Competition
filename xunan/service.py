import threading
import time
import uuid
import hashlib
import re
from collections import Counter

from . import demo
from .detectors import compare_runs, detect_document, sanitize_url
from .network import Crawler, ScopeError, utcnow


class BusyError(ValueError):
    pass


def keywords(value):
    if not isinstance(value, list) or len(value) > 30 or any(not isinstance(x, str) or not 1 <= len(x) <= 80 for x in value):
        raise ValueError("自定义关键词最多 30 个，每个 1～80 字，仅做文字匹配")
    return list(dict.fromkeys(value))


class Service:
    def __init__(self, store, scope):
        self.store, self.scope = store, scope
        self.run_lock = threading.Lock()
        self.schedule_lock = threading.RLock()
        self.stop = threading.Event()

    def inspect(self, config):
        if not isinstance(config, dict) or config.get("authorized") is not True:
            raise ValueError("请确认目标来自自建或明确授权的环境")
        mode = config.get("mode", "demo")
        if mode not in ("demo", "url"):
            raise ValueError("检查方式只能是 demo 或 url")
        rules = keywords(config.get("custom_keywords", []))
        variant = config.get("variant", "before")
        if variant not in ("before", "after"):
            raise ValueError("演示版本只能是 before 或 after")
        target = demo.BASE if mode == "demo" else self.scope.require(config.get("target", ""))
        target_digest = hashlib.sha256(target.encode()).hexdigest()
        rule_digest = hashlib.sha256("\0".join(sorted(rules)).encode()).hexdigest()
        max_pages = config.get("max_pages", 12)
        if type(max_pages) is not int or not 1 <= max_pages <= 30:
            raise ValueError("每轮最多检查 1～30 个资源")
        supplied_baseline = config.get("baseline_id")
        if supplied_baseline in (None, ""):
            baseline_id = None
        elif isinstance(supplied_baseline, str) and re.fullmatch(r"[a-f0-9]{32}", supplied_baseline):
            baseline_id = supplied_baseline
        else:
            raise ValueError("基线编号必须是巡安实际返回的 32 位任务编号")
        baseline = self.store.get_run(baseline_id) if baseline_id else None
        if baseline_id and baseline is None:
            raise ValueError("找不到基线任务")
        if baseline and (baseline.get("target_fingerprint") != target_digest or baseline["mode"] != mode):
            raise ValueError("基线必须来自相同目标和相同检查方式")
        if not self.run_lock.acquire(blocking=False):
            raise BusyError("已有巡检正在执行，请稍后再试")
        try:
            run_id = uuid.uuid4().hex
            created = utcnow()
            if mode == "demo":
                docs = demo.documents(variant)
                coverage = {"complete": True, "errors": [], "visited": len(docs), "attempted": len(docs), "limit": len(docs), "skipped": 0, "pending": 0, "scope_note": "内置三份固定虚构样例，不代表真实站点检测效果"}
            else:
                docs, coverage = Crawler(self.scope, max_pages=max_pages).crawl(target)
            # Persist only sanitized display URLs; original addresses exist only
            # for the in-memory bounded fetch and the operator's allowlist.
            for doc in docs:
                doc["display_url"] = sanitize_url(doc["url"])
            for error in coverage["errors"]:
                error["url"] = sanitize_url(error.get("url", ""))
            findings = []
            for doc in docs:
                findings.extend(detect_document(doc, rules))
            findings = list({f["id"]: f for f in findings}.values())
            priority = {"high": 0, "medium": 1, "low": 2, "info": 3}
            findings.sort(key=lambda f: (priority.get(f["severity"], 4), f["url"], f["rule_id"]))
            for finding in findings:
                finding["review_status"] = "pending"
            counts = Counter(f["severity"] for f in findings)
            summary = dict({k: counts[k] for k in ("high", "medium", "low", "info")}, total=len(findings))
            same_rules = not baseline or baseline.get("rule_config", {}).get("fingerprint") == rule_digest
            comparison = compare_runs(findings, baseline["findings"] if baseline else [], [d["display_url"] for d in docs], coverage["complete"] and same_rules)
            if not baseline:
                comparison["baseline_note"] = "首轮检查，全部记录为新增；尚无复测结论"
            elif not same_rules:
                comparison["baseline_note"] = "自定义规则配置发生变化；旧规则未再命中的记录保留为待复查，不能据此认定风险已消失"
            previous_hashes = {d["url"]: d["source_hash"] for d in baseline["documents"]} if baseline else {}
            changes = [{"url": d["display_url"], "before_hash": previous_hashes[d["display_url"]], "after_hash": d["source_hash"], "interpretation": "内容发生变化，不能仅凭摘要变化认定遭到篡改"}
                       for d in docs if d["display_url"] in previous_hashes and previous_hashes[d["display_url"]] != d["source_hash"]]
            run = {"id": run_id, "created_at": created, "target": sanitize_url(target), "target_fingerprint": target_digest, "mode": mode, "variant": variant if mode == "demo" else None,
                   "status": "completed" if coverage["complete"] else "partial" if docs else "failed",
                   "baseline_id": baseline_id, "summary": summary, "findings": findings, "comparison": comparison,
                   "coverage": coverage, "content_changes": changes,
                   "documents": [dict({k: d[k] for k in ("status", "content_type", "size", "source_hash", "fetched_at")}, url=d["display_url"]) for d in docs],
                   "timeline": [
                       {"step": "授权范围", "status": "done", "detail": "使用固定虚构样例" if mode == "demo" else "服务端白名单、请求预算、DNS地址检查生效"},
                       {"step": "发现与获取", "status": "done" if coverage["complete"] else "partial", "detail": "完成 " + str(len(docs)) + " 个文本资源；详情见覆盖情况"},
                       {"step": "规则检查", "status": "done", "detail": "按内容类型检查敏感信息、HTTPS引用和安全响应头；未运行漏洞利用工具"},
                       {"step": "证据与去重", "status": "done", "detail": "保留规则、位置、脱敏证据与修复建议；相同证据去重"},
                       {"step": "基线对比", "status": "done" if baseline else "skipped", "detail": "覆盖不足的未命中项保留待复查" if baseline else "首次结果可作为下轮基线"},
                       {"step": "报告归档", "status": "done", "detail": "结构化结果已保存，可人工复核和导出"},
                   ],
                   "engine": "xunan-rules-0.1", "agent_status": "恒脑接口已提供；本次结果来自本地规则工具，未调用大模型",
                   "limitations": ["静态只读检查；不执行JavaScript，不登录，不提交表单，不验证漏洞可利用性", "本次未发现不等于没有风险；邮箱等公开信息需人工确认", "未再发现不等于已经修复；覆盖不足项需要重测", "证据已脱敏；不保存网页原文、Cookie或查询参数"],
                   "rule_config": {"custom_keyword_count": len(rules), "fingerprint": rule_digest},
                   "authorization": {"confirmed": True, "confirmed_at": created, "scope": sanitize_url(target)}}
            self.store.save_run(run)
            if findings or run["status"] != "completed":
                self.store.add_event({"run_id": run_id, "created_at": created, "level": "warning" if run["status"] != "completed" else "info", "message": "巡检完成：" + str(summary["total"]) + " 条待复核发现，新增 " + str(comparison["counts"]["new"]) + " 条；状态 " + run["status"]})
            return run
        finally:
            self.run_lock.release()

    def create_schedule(self, config):
        if config.get("authorized") is not True:
            raise ValueError("请确认定时检查已获得授权")
        target = self.scope.require(config.get("target", ""))
        minutes = config.get("interval_minutes", 60)
        if type(minutes) is not int or not 5 <= minutes <= 10080:
            raise ValueError("定时间隔应为 5～10080 分钟")
        with self.schedule_lock:
            if len(self.store.schedules()) >= 20:
                raise ValueError("最多保存 20 条定时任务")
            item = {"id": uuid.uuid4().hex, "target": target, "interval_minutes": minutes,
                    "custom_keywords": keywords(config.get("custom_keywords", [])), "enabled": True,
                    "created_at": utcnow(), "next_run_at": time.time() + minutes * 60, "last_run_id": None}
            self.store.save_schedule(item)
        return item

    def update_schedule(self, schedule_id, enabled):
        if type(enabled) is not bool:
            raise ValueError("enabled 必须为 true 或 false")
        with self.schedule_lock:
            for item in self.store.schedules():
                if item["id"] == schedule_id:
                    item["enabled"] = enabled
                    if enabled:
                        item["next_run_at"] = time.time() + item["interval_minutes"] * 60
                    self.store.save_schedule(item)
                    return item
        raise KeyError("定时任务不存在")

    def scheduler(self):
        while not self.stop.wait(1):
            with self.schedule_lock:
                due = [s for s in self.store.schedules() if s["enabled"] and s["next_run_at"] <= time.time()]
            for item in due:
                # Reschedule before execution: no storm of overdue tasks on restart.
                with self.schedule_lock:
                    fresh = next((s for s in self.store.schedules() if s["id"] == item["id"]), None)
                    if not fresh or not fresh["enabled"]:
                        continue
                    fresh["next_run_at"] = time.time() + fresh["interval_minutes"] * 60
                    self.store.save_schedule(fresh)
                try:
                    result = self.inspect({"mode": "url", "target": item["target"], "authorized": True,
                                           "custom_keywords": item["custom_keywords"], "baseline_id": item.get("last_run_id")})
                    with self.schedule_lock:
                        latest = next(s for s in self.store.schedules() if s["id"] == item["id"])
                        if result["status"] != "failed":
                            latest["last_run_id"] = result["id"]
                        self.store.save_schedule(latest)
                except (ValueError, KeyError):
                    self.store.add_event({"created_at": utcnow(), "level": "warning", "message": "定时任务暂未执行：范围配置变化或有其他巡检运行中", "schedule_id": item["id"]})
