# 调研（2026-10-24）

所有数字都是 2026-10-24 用 `gh api` 或官方文档实查的。没有克隆、下载或打开任何可疑仓库里的文件，只读了仓库元数据和 git tree。

## 1. 同类工具

拆词搜索用 `gh api search/repositories -f sort=stars`，12 组关键词，每次间隔约 2 秒。

| 关键词 | 相关结果 |
|---|---|
| `github impersonation repo` | beardwhocodes/github-healthcheck 0★；bloodarea/github-repo-authenticity 1★ |
| `github-healthcheck` | 75 条，全是服务健康检查，同类只有上面那一个 |
| `fake repo detection github` | serenakeyitan/real-stars 5★（假星），其余不相关 |
| `malicious clone github` | WBChain3/repo-guard 5★（用户侧，克隆前扫 tasks.json / hooks） |
| `malicious repository scanner github` | cowenpa/github-repo-scanner 2★、fsgaleti-create/repo-safety-scanner 0★、otomay/repomancer 0★，都是用户侧扫单个仓库 |
| `git-malware-finder` | orchidfiles/git-malware-finder 62★ |
| `repo clone detector`、`detect cloned repositories` | 只有代码克隆检测的学术项目和噪声 |
| `fakegit` | 只有 2016 年的同名玩具项目 |
| `blob sha clone detection`、`copycat repo github`、`impersonat repository maintainer` | 0 条相关 |

逐个看的结论：

| 项目 | ★ | 开源 | 面向谁 | 怎么判定 | 和 clonewatch 的关系 |
|---|---:|---|---|---|---|
| [beardwhocodes/github-healthcheck](https://github.com/beardwhocodes/github-healthcheck)（[在线服务](https://github-healthcheck.beardwho.codes)） | 0 | MIT，TypeScript，Cloudflare Workers | 维护者 | 用 GitHub 账号登录；对每个仓库搜 `"<name> in:name"` 取前 20 条，再只保留**完全同名**、不同 owner 的前 8 个（`src/github/clone-detection.ts`）。每个候选跑 13 条规则：README 里的压缩包链接、下载徽章、加密压缩包、短链、“只改 README”的最近提交、深层压缩包路径（只看 tree 的 path）、loader 文件名、release 资产、“不是 fork 但同名”。可以每天复扫并发邮件，有生成举报草稿的功能（`src/reports/takedown.ts`，指向 support.github.com/contact/report-abuse） | **最直接的竞品**。10-23 最新提交只是依赖升级，**仍然没有比对 blob SHA**：tree 只用来看路径名。它判断的是“这个候选像不像诱饵”，而不是“这个候选是不是复制了我的代码”。托管服务，要把 OAuth token 交给第三方，开提醒时 token 长期加密存储 |
| [orchidfiles/git-malware-finder](https://github.com/orchidfiles/git-malware-finder) | 62 | 开源脚本 | 研究者 | 从 GHArchive 的 push 事件频率里挑出疑似诱饵仓库，附 9,330 个仓库的列表 | 全网撒网，不回答“谁在冒充我”。它的列表可作为离线 IOC 来源 |
| [bloodarea/github-repo-authenticity](https://github.com/bloodarea/github-repo-authenticity) | 1 | Agent Skill + Python 脚本 | 用户 | 审查单个仓库的假星、空壳、冒名来源 | 输入是一个可疑仓库，不做反向发现 |
| [WBChain3/repo-guard](https://github.com/WBChain3/repo-guard) 等用户侧扫描器 | 0～5 | 开源 | 用户 | 克隆前查 `.vscode/tasks.json`、git hooks、IOC | 用户侧，场景不同 |

结论：维护者侧只有 github-healthcheck 一个，而且检测停留在“同名 + README/路径特征”。clonewatch 的差异仍然成立：

1. **blob 指纹**：用原仓库和候选仓库共享的 git blob SHA 判断“是不是整仓复制”，只要代码照搬，README 怎么改写都绕不过去。
2. **本地运行**：只用用户自己的 `GITHUB_TOKEN`（或 `gh auth token`），不交给第三方；同一个二进制可以放进 GitHub Action 定时跑。
3. **证据包**：输出共享文件对照和新增文件清单，用户可以直接贴进举报表单。

## 2. 实测：一个仍在线的 FakeGit 诱饵

本节和 `examples/` 里的第三方账号、仓库名都换成了占位符（原仓库 `original-a/b/c`，复制品 `owner-a…e/<项目名>-copy-N`），分数、理由、路径和 SHA 保持原样。

探索报告 E4 里的原仓库 original-a/claudecode-rule2hook（403★）。按名搜索 `claudecode-rule2hook in:name` 只有 2 条非 fork 结果，其中 owner-a/claudecode-rule2hook-copy-1 今天仍然在线：

- 不是 fork；19★；账号只有 1 个公开仓库、1 个 follower。
- 原仓库 18 个 blob，候选 16 个 blob，**共享 14 个**（`.claude/commands/rule2hook.md`、`validate-hooks.py`、`LICENSE` 等 SHA 完全相同）。
- 候选多出的只有两项：改写过的 `README.md`，以及 `.claude/hook_rule_claudecode_3.4-alpha.4.zip`（584,482 字节，藏在子目录，带 `-alpha.N` 版本号）。
- 最近 3 次提交都是 “Update README.md”（2026-02-19、02-20、10-14），10-14 正是 Apiiro 报告的第二波。

这个仓库可以当作“已知阳性”回归样本（tests 里用的是根据它合成的 tree，不含真实压缩包内容）。

用 clonewatch 重放探索报告里的 3 个原仓库（original-a/claudecode-rule2hook、original-b/envcrypt、original-c/beautiful-mermaid），结果在 `examples/validation-3-repos.*`：比较了 **113 个候选**（和探索报告的数字一致），5 个判为复制品，其中 3 个 high（100 分），就是探索报告里命中 IOC 列表的那 3 个；另外 2 个是正常的整仓镜像或二次开发，分别是 35 分和 30 分，默认不输出。其中 owner-d/beautiful-mermaid-copy-2 在 release 里发布了自己用 CI 打包的 `beautiful-mermaid-1.1.5.zip`，README 没有链接它。第一版规则给它 45 分（medium），之后改成“README 指向 releases 时才计分”，才降下来。

## 3. GitHub API 能力与限流

| 能力 | 接口 | 限制（官方文档原文或实测） | 用法 |
|---|---|---|---|
| 按名找候选 | `GET /search/repositories?q=<name> in:name` | 认证后 30 次/分钟（实测 `rate_limit.search.limit = 30`）；每个查询最多 1,000 条结果，`per_page` 最大 100；默认不含 fork | 主力发现方式 |
| 按 README / 描述关键词 | 同上，`q="<phrase>" in:readme` / `in:description` | 同上 | 补充发现改了名的复制品 |
| 代码搜索 | `GET /search/code` | 必须认证，**10 次/分钟**；“Only the default branch is considered”；“Only files smaller than 384 KB are searchable”；不索引压缩包（实测 `filename:hook_rule_claudecode extension:zip` 返回 0） | 不作为主力：太慢，而且搜不到压缩包。只可选地用来搜“README 里出现我仓库全名”的仓库 |
| 读文件树 | `GET /repos/{o}/{r}/git/trees/{sha}?recursive=1` | 走 core 配额 5,000 次/小时；“The limit for the tree array is 100,000 entries with a maximum size of 7 MB when using the recursive parameter”，超过时 `truncated: true`；每个条目有 `path`、`mode`、`type`、`sha`、`size` | **指纹的唯一来源**。1 次请求拿到全部 blob SHA，不用克隆，也不下载任何文件内容 |
| 仓库元数据 | `GET /repos/{o}/{r}`、`GET /users/{u}` | core 配额 | fork 标记、创建时间、星数、账号年龄 |
| 最近提交 | `GET /repos/{o}/{r}/commits?per_page=5` | core 配额 | “只改 README”的提交模式 |
| README 文本 | `GET /repos/{o}/{r}/readme` | core 配额，返回 base64 文本 | 找下载链接。README 是文本，读取它不算下载可执行内容 |
| releases | `GET /repos/{o}/{r}/releases` | core 配额，只读资产名和大小 | 资产名可疑时提示，**不下载资产** |

预算估算：每个原仓库 1 次搜索 + 每个候选 3～4 次 core 请求（repo 元数据已包含在搜索结果里，所以是 tree + commits + readme + 必要时 user）。50 个原仓库、每个 20 个候选：50 次搜索（≥100 秒，按 30 次/分钟节流）+ 约 3,500 次 core 请求，在 1 小时配额内。只有共享 blob 达到阈值的候选才去拉 commits / readme，大多数同名仓库只花 1 次 tree 请求。

注意事项：

- `in:name` 是分词匹配，`foo` 会命中 `foo-bar`、`my-foo`。需要在本地再按名字过滤，但不能只留完全同名，因为复制者有时会加前后缀。
- 搜索结果也有 secondary rate limit；遇到 403/429 要读 `retry-after` / `x-ratelimit-reset` 等待，而不是吞掉错误。
- tree 被截断时（超大仓库）结果不完整，要在输出里明确标注，不能当作“共享 0 个”。

## 4. GitHub 对诱饵仓库的处置与举报流程

政策依据：[Active malware or exploits](https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits) 禁止用 GitHub “deliver malicious executables or as attack infrastructure”。

处置现状：没有找到 GitHub 对 10 月 FakeGit 第二波的官方回应。Apiiro 的说法是，下架依赖的列表只覆盖了一部分诱饵，而且被封的载荷还有备份可用（[BleepingComputer, 2026-10-08](https://bleepingcomputer.com/news/security/fakegit-malware-campaign-returns-with-17-610-malicious-github-repos)）。探索报告抽样时 79% 的已公开诱饵仍在线，上面的 owner-a 也还在线。

举报流程（[Reporting abuse or spam](https://docs.github.com/en/communities/maintaining-your-safety-on-github/reporting-abuse-or-spam)），**clonewatch 只生成证据，不代替用户举报**：

1. 打开可疑仓库首页，右侧 About 栏点 **Report repository**，会进入 GitHub Support 的联系表单；也可以直接打开 <https://support.github.com/contact/report-abuse>。
2. 官方文档没有列出表单字段。github-healthcheck 的代码里记录了表单的两个类别 ID（`cat_ts_malware`、`cat_ts_impersonation`，作者注明 2026-06-19 验证过），本项目没有打开表单核实。描述里写清楚：原仓库地址、它不是 fork、共享了哪些文件（clonewatch 的 Markdown 报告可以直接贴）、新增了哪些压缩包或可执行文件、README 里指向它们的下载链接。
3. 不要自己下载或解压那个压缩包来“确认”。文件名、大小、SHA 和路径已经足够让 GitHub 处理。
4. 文档没有写审核时限和结果通知方式。复制品如果把许可证也删了，原作者还可以走 DMCA 流程（版权途径），但开源许可下的整仓复制本身通常是合法的，恶意载荷才是举报重点。
