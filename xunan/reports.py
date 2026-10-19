"""Reports are generated from persisted, redacted records, never raw pages."""
import csv
import html
import io
import json


SEVERITY = {"high": "高", "medium": "中", "low": "低", "info": "提示"}


def csv_cell(value):
    text = "" if value is None else str(value)
    # Prevent spreadsheet formula execution, including leading whitespace.
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def render(run, format_name):
    if format_name == "json":
        return json.dumps(run, ensure_ascii=False, indent=2).encode(), "application/json; charset=utf-8", "json"
    if format_name == "csv":
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["发现编号", "规则", "等级", "标题", "页面", "行", "脱敏证据", "复核状态", "修复建议"])
        for finding in run["findings"]:
            writer.writerow([csv_cell(finding.get(k)) for k in ("id", "rule_id", "severity", "title", "url", "line", "evidence", "review_status", "remediation")])
        return ("\ufeff" + output.getvalue()).encode(), "text/csv; charset=utf-8", "csv"
    if format_name not in ("html", "markdown"):
        raise ValueError("报告格式支持 json、html、csv、markdown")
    e = lambda value: html.escape(str(value), quote=True)
    rows = []
    for index, finding in enumerate(run["findings"], 1):
        rows.append("<section><h2>" + str(index) + ". " + e(finding["title"]) + "</h2><p>等级：" + e(SEVERITY.get(finding["severity"], finding["severity"])) + " · 规则：" + e(finding["rule_id"]) + " · 复核：" + e(finding.get("review_status", "pending")) + "</p><p>位置：" + e(finding["url"]) + "，第 " + e(finding.get("line", 0)) + " 行</p><pre>" + e(finding["evidence"]) + "</pre><p>可能影响：" + e(finding["impact"]) + "</p><p>处理建议：" + e(finding["remediation"]) + "</p></section>")
    summary = run["summary"]
    coverage = run["coverage"]
    heading = "巡安授权网站巡检报告"
    metadata = "任务 " + run["id"] + " · " + run["created_at"]
    brief = "共 " + str(summary["total"]) + " 条待复核发现；检查 " + str(coverage["visited"]) + " 个资源。任务状态：" + run["status"] + "。"
    caveats = "；".join(run["limitations"])
    if format_name == "markdown":
        # Escape HTML and markdown syntax in all user-controlled prose.
        def md(value):
            return html.escape(str(value)).replace("\\", "\\\\").replace("`", "\\`").replace("[", "\\[").replace("]", "\\]").replace("*", "\\*").replace("#", "\\#").replace("_", "\\_").replace("\n", " ")
        lines = ["# " + heading, "", md(metadata), "", "目标：" + md(run["target"]), "", brief, "", "## 范围与限制", "", md(caveats), "", "## 基线对比", "", md(json.dumps(run["comparison"]["counts"], ensure_ascii=False)), "", "未再发现并不代表已修复；需要结合覆盖情况与人工复核。", ""]
        for i, f in enumerate(run["findings"], 1):
            lines += ["## " + str(i) + ". " + md(f["title"]), "", "等级：" + md(f["severity"]) + "；规则：" + md(f["rule_id"]), "", "位置：" + md(f["url"]) + "；行：" + str(f.get("line", 0)), "", "证据：" + md(f["evidence"]), "", "建议：" + md(f["remediation"]), ""]
        return "\n".join(lines).encode(), "text/markdown; charset=utf-8", "md"
    content = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>巡安巡检报告</title><style>body{font:16px/1.7 system-ui,sans-serif;color:#172b3a;max-width:960px;margin:40px auto;padding:0 24px}header{border-bottom:3px solid #167b79;padding-bottom:18px}section{border-bottom:1px solid #ddd;padding:16px 0;break-inside:avoid}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f5;padding:16px}p{overflow-wrap:anywhere}aside{background:#fff7e4;padding:18px}@media print{body{margin:0;max-width:none}h1{font-size:24px}}</style><header><h1>""" + heading + "</h1><p>" + e(metadata) + "</p><p>目标：" + e(run["target"]) + "</p><p>" + e(brief) + "</p></header><aside>" + e(caveats) + "</aside><h2>基线对比</h2><p>" + e(json.dumps(run["comparison"]["counts"], ensure_ascii=False)) + "</p><p>未再发现不等于已修复；覆盖不足时保留待复查。</p><h2>覆盖情况</h2><p>" + e(coverage.get("scope_note", "")) + "</p><pre>" + e(json.dumps(coverage["errors"], ensure_ascii=False, indent=2)) + "</pre>" + "".join(rows) + "</html>"
    return content.encode(), "text/html; charset=utf-8", "html"
