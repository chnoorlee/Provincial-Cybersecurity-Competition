# 巡安：授权网站安全巡检智能体

巡安为经过明确授权的网站做只读检查，把每条发现连同脱敏证据、影响、建议和复测状态保存下来。它面向第九届浙江省大学生网络与信息安全竞赛安恒信息企业命题。

当前版本已经跑通这条完整演示链路：

```text
授权确认 → 有边界的页面发现 → 确定性规则检查 → 脱敏证据与去重
        → 人工复核 → 基线对比 → 站内告警 → 报告导出
```

系统不会把“规则命中”写成“漏洞已经证实”，也不会把“本轮未再发现”直接写成“问题已经修复”。页面抓取失败或规则发生变化时，旧发现会保留为待复查。

## 三分钟开始

只需要 Python 3.9 或更高版本，无第三方依赖：

```bash
python3 -m xunan
```

看到启动地址后，用浏览器打开 `http://127.0.0.1:8765`。选择“内置演示样例”，勾选授权确认，然后依次运行“修复前”和“修复后”。第二次选择第一次记录作为基线，就能看到新增、持续、未再发现和待复查四种结果。

停止服务时在终端按 `Ctrl+C`。运行数据默认保存在 `data/xunan.sqlite3`，该目录不会提交到仓库。

## 现在能做什么

- 检查合成样例，或服务端白名单中的真实授权 HTTP/HTTPS 目标。
- 限定协议、域名、端口、路径、页面数量、单页大小、请求速度和读取时间。
- 阻止私网/回环地址、跨范围重定向、查询参数、危险路径、表单提交和非文本资源。
- 发现疑似明文凭据、邮箱、手机号、身份证格式、自定义关键词、HTTP 表单、混合内容和安全响应头加固项。
- 保存脱敏证据、稳定编号、严重程度、可信度、影响、建议及人工复核状态。
- 对比基线并记录页面内容摘要变化；支持进程内定时任务和站内事件。
- 导出 JSON、HTML、CSV 和 Markdown 报告。
- 提供恒脑可注册的 OpenAPI 契约与提示词。

当前不执行 JavaScript、不登录网站、不提交表单、不携带 Cookie、不访问含查询参数的链接，也不验证漏洞是否可利用。它不能替代人工审计或完整渗透测试。

## 检查团队自己的授权网站

服务端白名单由环境变量控制。例子中的域名必须换成团队自建或书面授权的目标：

```bash
export XUNAN_ALLOWED_TARGETS="https://demo.example/allowed-path"
python3 -m xunan
```

多个范围用英文逗号分隔。路径范围严格匹配，`/allowed-path` 不会自动包含 `/allowed-path-other`。默认阻止内网、回环和保留地址；只有在隔离实验室明确需要时才设置 `XUNAN_ALLOW_PRIVATE=1`。

所有 URL 查询参数都会被删除且不会发出请求。这能减少敏感信息泄露和有副作用 GET 请求的风险，但也意味着当前版本不会覆盖依赖查询参数的页面。

## 对外部署

对外监听需要一个至少 24 字符的随机 API 令牌，以及最终 HTTPS 来源：

```bash
export XUNAN_API_KEY="请替换为随机长令牌"
export XUNAN_PUBLIC_ORIGIN="https://scanner.example"
export XUNAN_ALLOWED_TARGETS="https://authorized-demo.example/"
python3 -m xunan --host 0.0.0.0 --port 8765
```

请用 Nginx、Caddy 或云平台网关在服务前终止 HTTPS，并限制恒脑平台和管理员的网络来源。当前是单管理员令牌模型，没有多用户角色权限；不要把服务直接暴露到公网，也不要把令牌写入仓库、截图或比赛材料。

容器构建：

```bash
docker build -t xunan:0.1.0 .
docker run --rm -p 127.0.0.1:8765:8765 \
  -e XUNAN_API_KEY \
  -e XUNAN_PUBLIC_ORIGIN \
  -e XUNAN_ALLOWED_TARGETS \
  -v xunan-data:/app/data \
  xunan:0.1.0
```

## 恒脑接入

1. 把本服务部署为恒脑可以访问的 HTTPS 地址。
2. 将 [`integrations/hengnao/openapi.json`](integrations/hengnao/openapi.json) 中的占位域名替换为实际地址。
3. 在恒脑注册 API 工具，认证头使用 `X-API-Key`，令牌只保存在平台密钥配置里。
4. 使用 [`integrations/hengnao/system-prompt.txt`](integrations/hengnao/system-prompt.txt) 约束模型只解释真实工具结果。
5. 先用 `mode=demo`、`variant=before`、`max_pages=3` 验证字段，再测试白名单目标。

完整步骤见[恒脑接入指南](docs/hengnao-guide.md)。仓库提供的是可导入契约；只有完成真实部署、注册、试运行和发布后，才能在作品中写“已接入恒脑”。

## 项目结构

| 目录 | 用途 |
| --- | --- |
| `xunan/` | 检测、抓取、存储、基线、报告、定时和 HTTP 服务 |
| `web/` | 中文操作台，无外部前端依赖 |
| `tests/` | 检测、范围限制、服务与接口测试 |
| `integrations/hengnao/` | OpenAPI 契约与智能体系统提示词 |
| `docs/` | 比赛要求、演示稿、报告提纲与平台接入说明 |
| `demo-target/` | 可放在团队 GitHub Pages 上的纯合成测试页面 |

## 验证

```bash
python3 -m unittest discover -s tests -v
node --check web/app.js
python3 -m json.tool integrations/hengnao/openapi.json >/dev/null
```

测试只使用内置合成数据和本机临时 HTTP 服务，不扫描公网。比赛前还需要在团队明确授权的演示环境做一次记录完整的验收，并把测试条件、正确发现、漏报和误报写入报告。

## 比赛材料

- [比赛要求、评分和提交清单](docs/requirements.md)
- [约 4 分 40 秒的演示稿](docs/demo-script.md)
- [匿名作品报告提纲](docs/report-outline.md)
- [恒脑部署与字段绑定](docs/hengnao-guide.md)

网络初赛材料计划截止时间为 **2026 年 10 月 25 日 24:00**；比赛文件同时注明最终以组委会正式通知为准。报告网络评审版不要出现学校、院系、指导教师或个人登录资料。

## 安全说明

只检查团队自建或明确授权的目标。真实凭据、个人资料和平台账号不得放入样例、日志、报告或仓库。发现安全问题请不要在公开 Issue 中附带原始敏感证据；先撤销泄露凭据，再通过私下渠道联系仓库维护者。

项目采用 [MIT License](LICENSE)。

