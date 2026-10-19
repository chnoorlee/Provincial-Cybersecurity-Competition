"use strict";

(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const pageNames = { overview: "工作台", "new-run": "发起巡检", history: "巡检记录", findings: "风险与证据", reports: "报告中心", settings: "接入与计划" };
  const severityNames = { high: "高风险", medium: "中风险", low: "低风险", info: "提示" };
  const reviewNames = { pending: "待确认", confirmed: "已确认", false_positive: "误报" };
  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  const tokenKey = "xunan-api-token";
  let token = "";
  let state = { runs: [], targets: [], schedules: [], events: [] };
  let selectedRun = null;
  let loadSequence = 0;
  let busy = false;
  let toastTimer;
  let connected = false;
  let cache = new Map();

  function node(tag, className, content) {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (content !== undefined && content !== null) result.textContent = String(content);
    return result;
  }

  function replace(selector, children) {
    const parent = typeof selector === "string" ? $(selector) : selector;
    parent.replaceChildren(...(Array.isArray(children) ? children : [children]));
    return parent;
  }

  function action(label, callback, className = "button secondary small") {
    const button = node("button", className, label);
    button.type = "button";
    button.addEventListener("click", callback);
    return button;
  }

  function notify(message, isError = false) {
    const toast = $("#toast");
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.classList.toggle("error", isError);
    toast.hidden = false;
    toastTimer = setTimeout(() => { toast.hidden = true; }, isError ? 11000 : 6000);
  }

  function string(value, fallback = "—") {
    if (value === undefined || value === null || value === "") return fallback;
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  }

  function number(value) { return Math.max(0, Number(value) || 0); }

  function date(value) {
    if (!value) return "时间未记录";
    const parsed = new Date(typeof value === "number" && value < 1e12 ? value * 1000 : value);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
  }

  function targetLabel(run) {
    if (run.mode === "demo") return "内置演示样例" + (run.variant === "before" ? " · 修复前" : run.variant === "after" ? " · 修复后" : "");
    return string(run.target, "未记录目标");
  }

  function runLabel(run) { return `${date(run.created_at)} · ${targetLabel(run)} · ${String(run.id).slice(0, 8)}`; }

  function targets() {
    return (state.targets || []).map(value => typeof value === "string" ? value : value.origin || value.url || value.target || "").filter(Boolean);
  }

  function statusBadge(status) {
    const map = {
      completed: ["检查完成", "success"], complete: ["检查完成", "success"], success: ["检查完成", "success"],
      partial: ["部分完成", "warning"], running: ["检查中", "neutral"], pending: ["等待执行", "neutral"],
      failed: ["检查失败", "danger"], error: ["检查失败", "danger"], blocked: ["范围未获准", "warning"]
    };
    const [label, className] = map[status] || [string(status, "状态未记录"), "neutral"];
    return node("span", `status-pill ${className}`, label);
  }

  function severityBadge(severity) {
    const safe = Object.hasOwn(severityNames, severity) ? severity : "info";
    return node("span", `severity-badge ${safe}`, severityNames[safe]);
  }

  function reviewBadge(status) {
    const safe = Object.hasOwn(reviewNames, status) ? status : "pending";
    return node("span", `review-badge ${safe}`, reviewNames[safe]);
  }

  function empty(title, description, buttonLabel, callback) {
    const box = node("div", "empty-state");
    box.append(node("span", "empty-icon", "◇"), node("strong", "", title), node("p", "", description));
    if (buttonLabel && callback) box.append(action(buttonLabel, callback));
    return box;
  }

  function setConnection(ok, message) {
    connected = ok;
    const connection = $("#connection-status");
    connection.className = `connection ${ok ? "connected" : "error"}`;
    connection.replaceChildren(node("i"), document.createTextNode(message));
    $("#settings-connection").textContent = message;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (token) headers.set("X-API-Key", token);
    if (options.body) headers.set("Content-Type", "application/json");
    let response;
    try {
      response = await fetch(path, { ...options, headers, credentials: "same-origin", cache: "no-store" });
    } catch (_) {
      setConnection(false, "服务未连接");
      throw new Error("无法连接巡安服务。请确认服务已启动，并通过服务地址打开此页面。");
    }
    if (!response.ok) {
      let details;
      try { details = await response.json(); } catch (_) { details = null; }
      const raw = details?.error?.message || details?.error || details?.detail || details?.message;
      const message = raw ? string(raw) : `服务返回错误（${response.status}）。`;
      if (response.status === 401 || response.status === 403) {
        if (response.status === 401) setConnection(false, "需要访问令牌");
        throw new Error(`${message} ${response.status === 401 ? "请到“接入与计划”填写正确的 API 访问令牌。" : "请核对访问权限和服务端授权目标配置。"}`);
      }
      throw new Error(message);
    }
    if (options.raw) return response;
    return response.json();
  }

  function go(page, updateHash = true) {
    if (!Object.hasOwn(pageNames, page)) page = "overview";
    $$(".page").forEach(section => {
      const active = section.id === `page-${page}`;
      section.hidden = !active;
      section.classList.toggle("active", active);
    });
    $$(".nav-item").forEach(button => {
      const active = button.dataset.page === page;
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    $("#breadcrumb-current").textContent = pageNames[page];
    if (updateHash) history.replaceState(null, "", `#${page}`);
    if (page === "findings" && !selectedRun && state.runs.length) loadRun(state.runs[0].id).catch(error => notify(error.message, true));
    window.scrollTo({ top: 0, behavior: "instant" });
  }

  function updateRunOptions() {
    const baseline = $("#baseline-select");
    const currentBaseline = baseline.value;
    baseline.replaceChildren(new Option("首次检查，暂不对比", ""));
    const runSelector = $("#finding-run");
    const currentRunId = selectedRun?.id || runSelector.value;
    runSelector.replaceChildren();
    for (const run of state.runs) {
      baseline.add(new Option(runLabel(run), run.id));
      runSelector.add(new Option(runLabel(run), run.id));
    }
    if (state.runs.some(run => run.id === currentBaseline)) baseline.value = currentBaseline;
    if (state.runs.some(run => run.id === currentRunId)) runSelector.value = currentRunId;
    if (!state.runs.length) runSelector.add(new Option("暂无巡检记录", ""));
    runSelector.disabled = !state.runs.length;
  }

  function renderMetrics() {
    const latest = state.runs[0];
    $("#metric-runs").replaceChildren(document.createTextNode(String(state.runs.length)), node("span", "", "次"));
    $("#metric-findings").textContent = latest ? number(latest.summary?.total) : "—";
    $("#metric-high").textContent = latest ? number(latest.summary?.high) : "—";
    $("#metric-schedules").replaceChildren(document.createTextNode(String(state.schedules.filter(item => item.enabled).length)), node("span", "", "个"));
    $("#metric-findings-caption").textContent = latest ? `最近检查于 ${date(latest.created_at)}` : "发起巡检后显示";
    $("#nav-finding-count").textContent = latest ? number(latest.summary?.total) : 0;
  }

  function renderLatest(run) {
    if (!run) {
      replace("#latest-run-content", empty("还没有巡检记录", "从内置样例开始，几步走完整个检查与复查过程。", "开始第一次巡检", () => go("new-run")));
      replace("#overview-findings", empty("发现会出现在这里", "完成一次巡检后，优先展示需要关注的证据。"));
      return;
    }
    const box = node("div");
    const meta = node("div", "run-meta");
    meta.append(statusBadge(run.status), node("span", "", date(run.created_at)), node("span", "", run.mode === "demo" ? "演示样例" : "授权目标"));
    box.append(node("h3", "run-target", targetLabel(run)), meta);
    const bars = node("div", "severity-bars");
    const max = Math.max(1, ...Object.keys(severityNames).map(key => number(run.summary?.[key])));
    for (const [key, label] of Object.entries(severityNames)) {
      const count = number(run.summary?.[key]);
      const row = node("div", "severity-row");
      const track = node("progress", `severity-meter ${key}`);
      track.max = max;
      track.value = count;
      track.setAttribute("aria-label", `${label} ${count} 条`);
      row.append(node("span", "", label), track, node("strong", "", count));
      bars.append(row);
    }
    box.append(bars);
    const bottom = node("div", "latest-bottom");
    bottom.append(node("span", "", run.coverage ? `检查 ${number(run.coverage.visited)} 个页面 · ${run.coverage.complete ? "本轮覆盖完整" : "存在未覆盖内容"}` : "点击查看页面覆盖与检查过程"), action("查看巡检详情 →", () => openRun(run.id), "text-button"));
    box.append(bottom);
    replace("#latest-run-content", box);
    if (Array.isArray(run.findings)) {
      const top = [...run.findings].sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)).slice(0, 5);
      replace("#overview-findings", findingsTable(top, run.id, true));
    }
  }

  function findingsTable(findings, runId, compact = false) {
    if (!findings.length) return empty("当前没有匹配的发现", "这表示本轮规则没有命中；请结合检查范围和抓取情况评估结果。");
    const wrap = node("div", "table-wrap");
    const table = node("table");
    const head = node("thead");
    const headRow = node("tr");
    ["风险级别", "发现与来源", "检测规则", "确认状态", ""].forEach(label => headRow.append(node("th", "", label)));
    head.append(headRow);
    const body = node("tbody");
    for (const finding of findings) {
      const row = node("tr");
      const severity = node("td");
      severity.append(severityBadge(finding.severity));
      const title = node("td");
      title.append(action(string(finding.title, "未命名发现"), () => showFinding(runId, finding.id), "finding-title"), node("span", "cell-subline", string(finding.url)));
      const rule = node("td");
      rule.append(node("span", "", string(finding.rule_id)), node("span", "cell-subline", string(finding.category, "内容与配置检查")));
      const review = node("td");
      review.append(reviewBadge(finding.review_status));
      const link = node("td");
      link.append(action("查看证据 ↗", () => showFinding(runId, finding.id), "table-action"));
      row.append(severity, title, rule, review, link);
      body.append(row);
    }
    table.append(head, body);
    table.setAttribute("aria-label", compact ? "最新巡检优先发现" : "本次巡检风险清单");
    wrap.append(table);
    return wrap;
  }

  function renderHistory() {
    $("#history-count").textContent = `${state.runs.length} 条记录`;
    if (!state.runs.length) return replace("#history-list", empty("暂时没有检查记录", "完成第一次巡检后，可以在这里回看结果。", "发起巡检", () => go("new-run")));
    const wrap = node("div", "table-wrap");
    const table = node("table");
    table.setAttribute("aria-label", "巡检历史记录");
    const head = node("thead");
    const headRow = node("tr");
    ["巡检目标", "开始时间", "执行状态", "发现数量", "对比基线", ""].forEach(text => headRow.append(node("th", "", text)));
    head.append(headRow);
    const body = node("tbody");
    for (const run of state.runs) {
      const row = node("tr");
      const target = node("td");
      target.append(action(targetLabel(run), () => openRun(run.id), "finding-title"), node("small", "cell-subline", run.id));
      const status = node("td"); status.append(statusBadge(run.status));
      const detail = node("td"); detail.append(action("查看结果 →", () => openRun(run.id), "table-action"));
      row.append(target, node("td", "", date(run.created_at)), status, node("td", "", `${number(run.summary?.total)} 条 · 高风险 ${number(run.summary?.high)}`), node("td", "", run.baseline_id ? "已选择" : "首次 / 未选择"), detail);
      body.append(row);
    }
    table.append(head, body); wrap.append(table); replace("#history-list", wrap);
  }

  function renderComparison(run) {
    const parent = $("#comparison-panel");
    parent.replaceChildren();
    if (!run.baseline_id || !run.comparison) return;
    const box = node("div", "comparison-card");
    box.append(node("h2", "", "与基线相比，这次发生了什么？"));
    const grid = node("div", "comparison-grid");
    const names = { new: "新发现", persistent: "持续存在", not_observed: "本次未再发现（待确认）", uncertain: "覆盖不足，待复查" };
    for (const [key, label] of Object.entries(names)) {
      const item = node("div", `comparison-item ${key}`);
      item.append(node("strong", "", number(run.comparison.counts?.[key])), node("span", "", label));
      grid.append(item);
    }
    box.append(grid, node("p", "", "本次未再发现不直接等于已修复。请结合页面内容、抓取范围和人工确认记录判断。"));
    if (run.comparison.entries?.length) {
      const details = node("details", "detail-section");
      details.append(node("summary", "", `查看 ${run.comparison.entries.length} 条对比明细`));
      const list = node("ul", "timeline");
      for (const entry of run.comparison.entries) {
        const item = node("li");
        item.append(node("strong", "", names[entry.status] || string(entry.status)), node("span", "", string(entry.title)), node("small", "", string(entry.url)), node("small", "", string(entry.evidence, "")));
        list.append(item);
      }
      details.append(list); box.append(details);
    }
    parent.append(box);
  }

  function renderCoverage(run) {
    const panel = $("#coverage-panel");
    panel.hidden = !run;
    if (!run) return;
    const box = node("div");
    const coverage = run.coverage || {};
    const summary = node("div", "coverage-summary");
    summary.append(node("span", "", `已检查 ${number(coverage.visited)} 个页面`), node("span", "", `本轮上限 ${number(coverage.limit)} 页`), node("span", "", coverage.complete ? "本轮覆盖完整" : "覆盖不完整，结果需结合范围解读"));
    box.append(summary);
    if (coverage.scope_note) box.append(node("p", "body-copy", coverage.scope_note));
    if (coverage.errors?.length) {
      const errors = node("ul", "error-list");
      coverage.errors.forEach(error => errors.append(node("li", "", typeof error === "string" ? error : [error.url, error.message || error.error || error.reason].filter(Boolean).join(" · ") || string(error))));
      box.append(node("h3", "", "未能完整检查的内容"), errors);
    }
    if (run.timeline?.length) {
      const timeline = node("ol", "timeline");
      run.timeline.forEach(step => {
        const item = node("li");
        item.append(node("strong", "", string(step.step)), node("span", "", ({ completed: "已完成", complete: "已完成", ok: "已完成", done: "已完成", success: "已完成", partial: "部分完成", skipped: "已跳过", failed: "未完成", running: "执行中" })[step.status] || string(step.status, "")), node("small", "", string(step.detail, "")));
        timeline.append(item);
      });
      box.append(timeline);
    }
    if (run.documents?.length) {
      const details = node("details", "detail-section");
      details.append(node("summary", "", `查看 ${run.documents.length} 个页面的来源与内容指纹`));
      const list = node("ul", "timeline");
      run.documents.forEach(document => {
        const item = node("li");
        item.append(node("strong", "", string(document.url)), node("small", "", `状态 ${string(document.status)} · ${string(document.content_type)} · ${number(document.size)} 字节`), node("small", "", `内容指纹 ${string(document.source_hash)}`));
        list.append(item);
      });
      details.append(list); box.append(details);
    }
    if (run.content_changes?.length) {
      const changes = node("details", "detail-section");
      changes.append(node("summary", "", `${run.content_changes.length} 个资源的内容发生变化`));
      const list = node("ul", "timeline");
      for (const change of run.content_changes) {
        const item = node("li");
        item.append(node("strong", "", string(change.url)), node("small", "", string(change.interpretation)), node("small", "", `上次指纹 ${string(change.before_hash)}`), node("small", "", `本次指纹 ${string(change.after_hash)}`));
        list.append(item);
      }
      changes.append(list); box.append(changes);
    }
    replace("#coverage-content", box);
  }

  function renderSelectedRun() {
    const run = selectedRun;
    if (!run) {
      $("#finding-run-meta").replaceChildren();
      $("#comparison-panel").replaceChildren();
      $("#findings-count").textContent = "0 条发现";
      replace("#findings-table", empty("先选择一次巡检", "完成巡检后，这里会显示风险、证据与确认状态。", "发起巡检", () => go("new-run")));
      renderCoverage(null); return;
    }
    $("#finding-run").value = run.id;
    const meta = node("div", "run-summary-strip");
    const label = node("div");
    label.append(node("h3", "", targetLabel(run)), node("p", "", `${date(run.created_at)} · ${run.mode === "demo" ? "内置合成样例" : "已授权网站"} · ${run.id}`));
    meta.append(label, statusBadge(run.status));
    replace("#finding-run-meta", meta);
    const severity = $("#severity-filter").value;
    const review = $("#review-filter").value;
    const findings = (run.findings || []).filter(item => (severity === "all" || item.severity === severity) && (review === "all" || (item.review_status || "pending") === review)).sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));
    $("#findings-count").textContent = `${findings.length} / ${(run.findings || []).length} 条发现`;
    replace("#findings-table", findingsTable(findings, run.id));
    renderComparison(run); renderCoverage(run);
  }

  async function loadRun(id, fresh = false) {
    if (!id) return;
    const sequence = ++loadSequence;
    const run = !fresh && cache.has(id) ? cache.get(id) : await api(`/api/runs/${encodeURIComponent(id)}`);
    cache.set(id, run);
    if (sequence !== loadSequence) return;
    selectedRun = run;
    renderSelectedRun();
    return run;
  }

  async function openRun(id) {
    go("findings");
    replace("#findings-table", node("div", "loading-placeholder loading-dot", "正在载入巡检证据"));
    try { await loadRun(id); } catch (error) { notify(error.message, true); renderSelectedRun(); }
  }

  async function showFinding(runId, findingId) {
    try {
      const run = cache.get(runId) || await api(`/api/runs/${encodeURIComponent(runId)}`);
      cache.set(runId, run);
      const finding = (run.findings || []).find(item => item.id === findingId);
      if (!finding) return notify("未找到这条发现，请刷新巡检记录。", true);
      $("#dialog-title").textContent = string(finding.title, "风险详情");
      const content = node("div");
      const badges = node("div", "button-row");
      badges.append(severityBadge(finding.severity), reviewBadge(finding.review_status));
      content.append(badges);
      const grid = node("dl", "detail-grid");
      const fields = [["来源页面", finding.url], ["检测规则", finding.rule_id], ["检测工具", finding.tool], ["发现时间", date(finding.observed_at)], ["证据位置", finding.line ? `第 ${finding.line} 行` : "页面 / 响应元数据"], ["置信度（仍需人工确认）", finding.confidence]];
      for (const [label, value] of fields) {
        const item = node("div", "detail-item"); item.append(node("dt", "", label), node("dd", "", string(value))); grid.append(item);
      }
      content.append(grid);
      const evidence = node("section", "detail-section");
      evidence.append(node("h3", "", "命中证据"), node("pre", "evidence-box", string(finding.evidence, "本条发现未提供文本证据，请核查原始记录。")));
      content.append(evidence);
      for (const [label, value] of [["可能带来的影响", finding.impact], ["建议如何处理", finding.remediation]]) {
        const section = node("section", "detail-section"); section.append(node("h3", "", label), node("p", "", string(value))); content.append(section);
      }
      const form = node("form", "review-form");
      const label = node("label", "", "人工确认意见"); label.htmlFor = "review-note";
      const note = node("textarea"); note.id = "review-note"; note.rows = 3; note.maxLength = 500; note.placeholder = "记录你确认或排除这条风险的依据（可选，最多 500 字）";
      note.value = finding.review_note || finding.note || "";
      const buttons = node("div", "button-row");
      for (const [status, text] of [["confirmed", "确认是问题"], ["false_positive", "标记为误报"], ["pending", "保留待确认"]]) {
        buttons.append(action(text, async () => {
          const allButtons = $$("button", form); allButtons.forEach(button => { button.disabled = true; });
          try {
            await api("/api/reviews", { method: "POST", body: JSON.stringify({ run_id: runId, finding_id: findingId, status, note: note.value.trim() }) });
            cache.delete(runId);
            if (selectedRun?.id === runId) await loadRun(runId, true);
            if (state.runs[0]?.id === runId) {
              const latest = cache.get(runId) || await api(`/api/runs/${encodeURIComponent(runId)}`); cache.set(runId, latest); renderLatest(latest);
            }
            $("#finding-dialog").close(); notify("确认记录已保存，报告中会保留这次判断。");
          } catch (error) { notify(error.message, true); } finally { allButtons.forEach(button => { button.disabled = false; }); }
        }, `button ${status === "confirmed" ? "primary" : "secondary"} small`));
      }
      form.addEventListener("submit", event => event.preventDefault());
      form.append(label, note, buttons, node("p", "review-note", "标记误报会保留原始发现与证据，方便后续审阅。"));
      content.append(form); replace("#dialog-content", content);
      const dialog = $("#finding-dialog"); if (!dialog.open) dialog.showModal();
    } catch (error) { notify(error.message, true); }
  }

  function renderReports() {
    if (!state.runs.length) return replace("#report-list", empty("暂时没有可导出的报告", "完成巡检后，可以导出实际检查结果。"));
    const rows = state.runs.map(run => {
      const row = node("div", "report-row");
      const description = node("div");
      description.append(node("h3", "", targetLabel(run)), node("p", "", `${date(run.created_at)} · ${number(run.summary?.total)} 条发现 · ${run.id}`));
      const buttons = node("div", "button-row");
      for (const [format, label] of [["html", "网页报告 ↓"], ["markdown", "Markdown ↓"], ["csv", "CSV ↓"], ["json", "JSON ↓"]]) {
        buttons.append(action(label, event => downloadReport(run.id, format, event.currentTarget)));
      }
      row.append(description, buttons); return row;
    });
    replace("#report-list", rows);
  }

  async function downloadReport(id, format, button) {
    button.disabled = true;
    try {
      const response = await api(`/api/reports/${encodeURIComponent(id)}?format=${encodeURIComponent(format)}`, { raw: true });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = node("a");
      anchor.href = url;
      anchor.download = `巡安巡检报告_${id}.${format === "markdown" ? "md" : format}`;
      document.body.append(anchor); anchor.click(); anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      notify("报告已下载，内容对应本次巡检的实际记录。");
    } catch (error) { notify(error.message, true); } finally { button.disabled = false; }
  }

  function renderSettings() {
    const list = targets();
    $("#target-options").replaceChildren(...list.map(target => new Option(target, target)));
    const oldTarget = $("#schedule-target").value;
    $("#schedule-target").replaceChildren(...(list.length ? list.map(target => new Option(target, target)) : [new Option("尚未配置授权目标", "")]));
    if (list.includes(oldTarget)) $("#schedule-target").value = oldTarget;
    $("#schedule-target").disabled = !list.length;
    $("#schedule-form button[type=submit]").disabled = !list.length;
    $("#target-help").textContent = list.length ? `已配置 ${list.length} 个目标。请从建议地址中选择，或输入该范围内的页面地址。` : "尚未配置授权目标。请先按仓库部署文档配置服务端允许列表，也可以先使用内置样例。";
    replace("#configured-targets", list.length ? [...list.map(target => node("div", "target-item", target)), node("p", "field-help", "授权列表限定可检查的范围。新增目标需由部署者按仓库说明配置。")] : empty("还没有配置网站", "可以先体验内置样例。真实网站需在服务端配置允许列表。"));
    const schedules = state.schedules || [];
    if (!schedules.length) replace("#schedule-list", empty("还没有定时计划", "先配置授权目标，再设置自动检查间隔。"));
    else replace("#schedule-list", schedules.map(schedule => {
      const row = node("div", "schedule-row");
      const info = node("div");
      info.append(node("strong", "", string(schedule.target)), node("p", "", `每 ${number(schedule.interval_minutes)} 分钟 · ${schedule.enabled ? "已启用" : "已停用"}${schedule.next_run_at ? ` · 下次 ${date(schedule.next_run_at)}` : ""}`));
      row.append(info);
      if (schedule.enabled) row.append(action("停用计划", async event => {
        const button = event.currentTarget; button.disabled = true;
        try { await api(`/api/schedules/${encodeURIComponent(schedule.id)}`, { method: "POST", body: JSON.stringify({ enabled: false }) }); await refresh(false); notify("定时计划已停用。"); }
        catch (error) { notify(error.message, true); button.disabled = false; }
      }));
      else row.append(node("span", "status-pill neutral", "已停用"));
      return row;
    }));
    const events = (state.events || []).slice(0, 15);
    replace("#event-list", events.length ? events.map(event => {
      const row = node("div", "event-row");
      row.append(node("time", "", date(event.created_at || event.time || event.timestamp)), node("span", "", string(event.message || event.detail || event.event || event.type || event)));
      return row;
    }) : node("p", "body-copy", "暂时没有事件。巡检和计划执行后，这里会显示实际记录。"));
  }

  async function refresh(showMessage = true) {
    const button = $("#refresh-button"); button.disabled = true;
    try {
      const data = await api("/api/state");
      state = {
        runs: Array.isArray(data.runs) ? data.runs : [],
        targets: Array.isArray(data.targets) ? data.targets : [],
        schedules: Array.isArray(data.schedules) ? data.schedules : [],
        events: Array.isArray(data.events) ? data.events : []
      };
      state.runs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      setConnection(true, "服务已连接");
      updateRunOptions(); renderMetrics(); renderHistory(); renderReports(); renderSettings();
      const latest = state.runs[0];
      renderLatest(latest);
      if (latest) {
        const full = await api(`/api/runs/${encodeURIComponent(latest.id)}`);
        cache.set(latest.id, full); renderLatest(full);
        if (!selectedRun) selectedRun = full;
        else if (selectedRun.id === full.id) selectedRun = full;
      }
      renderSelectedRun();
      if (showMessage) notify("数据已刷新。");
    } catch (error) {
      if (!connected || !state.runs.length) {
        setConnection(false, "服务未连接");
        replace("#latest-run-content", empty("暂时无法连接服务", "请确认服务已启动；远程访问请先填写 API 访问令牌。", "设置连接", () => go("settings")));
      }
      notify(error.message, true);
      throw error;
    } finally { button.disabled = false; }
  }

  async function bootstrap() {
    try { token = sessionStorage.getItem(tokenKey) || ""; } catch (_) { token = ""; }
    if (!token) {
      try {
        const response = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" });
        if (response.ok) { const data = await response.json(); token = data.token || ""; }
      } catch (_) { /* Remote sessions can use the visible token form. */ }
    }
    try { await refresh(false); } catch (_) { /* The connection panel provides a recoverable path. */ }
  }

  function updateMode() {
    const mode = $("input[name=mode]:checked").value;
    $("#demo-fields").hidden = mode !== "demo";
    $("#url-fields").hidden = mode !== "url";
    $("#target-input").required = mode === "url";
    $("#target-input").disabled = mode !== "url";
    $("#max-pages").disabled = mode !== "url";
  }

  $$("[data-page]").forEach(button => button.addEventListener("click", () => go(button.dataset.page)));
  $$("[data-go]").forEach(button => button.addEventListener("click", () => go(button.dataset.go)));
  $(".brand").addEventListener("click", event => { event.preventDefault(); go("overview"); });
  $("#quick-demo").addEventListener("click", () => {
    $("input[name=mode][value=demo]").checked = true; $("#demo-variant").value = "before"; $("#baseline-select").value = ""; updateMode(); go("new-run");
  });
  $$("input[name=mode]").forEach(input => input.addEventListener("change", updateMode));
  $("#refresh-button").addEventListener("click", () => { refresh().catch(() => {}); });
  $("#finding-run").addEventListener("change", event => openRun(event.target.value));
  $("#severity-filter").addEventListener("change", renderSelectedRun);
  $("#review-filter").addEventListener("change", renderSelectedRun);
  $("#custom-keywords").addEventListener("input", event => event.target.setCustomValidity(""));
  $("#close-dialog").addEventListener("click", () => $("#finding-dialog").close());
  $("#finding-dialog").addEventListener("click", event => {
    const dialog = event.currentTarget;
    const rect = dialog.getBoundingClientRect();
    if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close();
  });
  window.addEventListener("hashchange", () => go(location.hash.slice(1), false));

  $("#run-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const keywordInput = $("#custom-keywords");
    const customKeywords = keywordInput.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    keywordInput.setCustomValidity(customKeywords.length > 30 || customKeywords.some(value => value.length > 80) ? "最多填写 30 个关键词，每个关键词不能超过 80 字。" : "");
    if (!form.reportValidity()) return;
    const mode = $("input[name=mode]:checked").value;
    const body = {
      mode, variant: $("#demo-variant").value,
      target: mode === "url" ? $("#target-input").value.trim() : "",
      authorized: $("#authorized").checked,
      custom_keywords: customKeywords,
      max_pages: mode === "url" ? Number($("#max-pages").value) || 12 : 12
    };
    const baselineId = $("#baseline-select").value;
    if (baselineId) body.baseline_id = baselineId;
    busy = true;
    $("#run-submit").disabled = true;
    $("#run-submit").textContent = "正在巡检…";
    $("#run-progress").textContent = "正在检查页面并整理证据，请保留页面。完成后会自动显示结果。";
    $("#run-progress").classList.add("loading-dot");
    try {
      const run = await api("/api/runs", { method: "POST", body: JSON.stringify(body) });
      cache.set(run.id, run); selectedRun = run;
      await refresh(false);
      $("#severity-filter").value = "all"; $("#review-filter").value = "all";
      renderSelectedRun(); go("findings");
      notify(`巡检记录已保存，共 ${number(run.summary?.total)} 条发现。请查看覆盖范围并确认结果。`);
      $("#run-progress").textContent = `上次巡检记录：${run.id}`;
    } catch (error) {
      $("#run-progress").textContent = error.message; notify(error.message, true);
    } finally {
      busy = false; $("#run-submit").disabled = false; $("#run-submit").textContent = "开始巡检 →"; $("#run-progress").classList.remove("loading-dot");
    }
  });

  $("#token-form").addEventListener("submit", async event => {
    event.preventDefault();
    const entered = $("#api-token").value.trim();
    if (!entered) return notify("请填写部署者提供的 API 访问令牌。", true);
    token = entered;
    try {
      await refresh(false);
      try { sessionStorage.setItem(tokenKey, token); } catch (_) { notify("浏览器未允许保存会话，刷新后需要重新填写令牌。"); }
      $("#api-token").value = "";
      notify("服务连接成功。");
    } catch (_) { /* Existing error notification explains recovery. */ }
  });

  $("#clear-token").addEventListener("click", async () => {
    token = ""; try { sessionStorage.removeItem(tokenKey); } catch (_) { /* Nothing persisted. */ }
    $("#api-token").value = "";
    await bootstrap();
    if (connected) notify("手动令牌已清除，已切换到本机会话。");
  });

  $("#schedule-form").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const button = $("button[type=submit]", form); button.disabled = true;
    try {
      await api("/api/schedules", { method: "POST", body: JSON.stringify({ target: $("#schedule-target").value, interval_minutes: Number($("#schedule-interval").value), authorized: $("#schedule-authorized").checked, custom_keywords: [], enabled: true }) });
      await refresh(false); $("#schedule-authorized").checked = false; notify("定时计划已创建。请保持服务运行。");
    } catch (error) { notify(error.message, true); } finally { button.disabled = !targets().length; }
  });

  updateMode(); renderMetrics(); renderLatest(null); renderHistory(); renderSelectedRun(); renderReports(); renderSettings();
  go(location.hash.slice(1) || "overview", false);
  bootstrap();
})();
