# 设计

目标：给维护者一个本地命令，回答“GitHub 上有没有人整仓复制了我的项目，并且往里塞了压缩包或可执行文件”。核心证据是共享的 git blob SHA，其他特征只用来给“已确认是复制品”的仓库排序。

```
clonewatch scan majiayu000                 # 扫描这个账号所有非 fork 公开仓库
clonewatch scan majiayu000/spellbook       # 只扫一个仓库
clonewatch scan majiayu000 --top 5 --format md -o report.md
```

## 1. 安全边界（硬性）

- **绝不下载或解压候选仓库里的压缩包、可执行文件、release 资产。** 不 `git clone`，不请求 `raw.githubusercontent.com`、`codeload`、`objects.githubusercontent.com`，也不请求 blob 内容接口。
- 只读这些 api.github.com 接口：`search/repositories`、`repos/{o}/{r}`、`git/trees`、`commits`、`readme`、`releases`（只读资产名和大小）、`users/{u}`、`users/{u}/repos`。HTTP 客户端只暴露这些方法，并且在发请求前断言 URL 以 `https://api.github.com/` 开头。
- README 只当作文本读取，用于提取链接，从不跟随链接。
- 不写任何东西到 GitHub：不评论、不开 issue、不举报。Action 示例里开 issue 的一步是用户自己工作流里的 `gh` 命令，写在用户自己的仓库里。
- token 从 `GITHUB_TOKEN` / `GH_TOKEN` 读取，否则调用 `gh auth token`；只发给 api.github.com，不写入输出。

## 2. 候选发现

对每个原仓库（默认是账号下非 fork、非 archived 的公开仓库，按星数排序，`--top N` 截取）：

1. **同名搜索**：`<name> in:name`，分页取到 `--max-candidates`（默认 100）。搜索默认不含 fork，正好排除正常 fork。本地再过滤：去掉自己账号下的仓库；仓库名规范化（小写、只留字母数字）后必须包含原仓库名，比如 `tool`、`tool-pro`、`my_tool`。
2. **README 标题搜索**：原 README 的第一个 Markdown 标题如果和仓库名不同（规范化后），再搜一次 `"<标题>" in:readme`，不做名字过滤。用来抓改了仓库名但保留标题的复制品。诱饵通常会重写 README，所以这只是补充。
3. **同一账号的其他仓库**：一旦某个账号的仓库被判为复制品，取这个账号的公开仓库列表（1 次请求），名字和我其他仓库同名的也加入候选。诱饵账号常常一口气复制同一作者的多个项目。

每个候选去重后，只要拿一次 tree 就能决定是否继续。

## 3. 指纹比对

- 取原仓库和候选仓库默认分支的 recursive tree（`git/trees/{default_branch}?recursive=1`），只看 `type == "blob"` 的条目，得到 `{sha → path, size}`。
- 忽略不带区分度的 blob：空文件（`e69de29…`）和小于 `--min-blob-size`（默认 64 字节）的文件。剩下的叫“有效 blob”。
- `shared` = 两边有效 blob SHA 的交集大小。
- `overlap` = `max(shared / |原仓库有效 blob|, shared / |候选有效 blob|)`。取两个方向的最大值，是因为复制品可能是原仓库较早的快照（原仓库后来长大了），也可能只复制了一个子目录。
- 判定为**复制品**：`shared ≥ 3` 且 `overlap ≥ 0.5`（`--min-shared`、`--min-overlap` 可调）。达不到的同名仓库只计数，不输出细节。
- 任意一边 tree 被截断（`truncated: true`，超过 100,000 条或 7 MB）时照常计算，但在结果里标注 `incomplete`，不当作“共享 0 个”。

不做源码规范化后再哈希：那需要下载文件内容，违反安全边界的精神，也贵很多。复制者如果重新格式化所有文件，blob 就对不上，这是已知限制。

## 4. 可疑特征

只对已判为复制品的候选计算。“新增文件”指候选里 SHA 不在原仓库、路径也不在原仓库的 blob。

| 特征 | 怎么判断 | 需要的额外请求 |
|---|---|---|
| 新增压缩包 | 扩展名 `.zip .rar .7z .tar .gz .tgz .xz .bz2 .cab .iso .dmg .img` | 无（来自 tree） |
| 新增可执行文件 | 扩展名 `.exe .dll .scr .msi .com .bat .cmd .ps1 .vbs .jar .apk .lnk`（不按 `100755` 权限位判断，普通脚本太多，误报高） | 无 |
| 藏得深 / 带版本号 | 新增载荷在子目录里，或文件名带 `v1.2`、`-alpha.4` 这类版本号 | 无 |
| README 下载链接 | README 里的链接指向压缩包或可执行文件、`releases/download`、`/raw/`、短链域名；如果链接指向的正是新增载荷的路径，权重更高 | 1 次 readme |
| release 资产 | 候选的 release 里有压缩包或可执行文件，原仓库的 release 里没有同名资产，**并且候选 README 里有指向 `/releases` 的链接**。没有 README 指向时只记一条 0 分的说明：很多二次开发项目会用 CI 发布自己的打包产物（实测 owner-d/beautiful-mermaid-copy-2 就是这样） | 候选 1 次 + 原仓库 1 次（缓存） |
| 只改 README 的提交 | 最近 5 个提交中至少 2 个的标题是 “Update README.md” 一类 | 1 次 commits |
| 账号异常 | 账号创建不到 180 天，或者只有 1 个公开仓库 | 1 次 users |
| 星数与创建时间异常 | 候选比原仓库晚创建，但星数不低于原仓库 | 无（搜索结果里有） |

## 5. 评分与阈值

分数 0～100，每条理由都写出来：

| 项 | 分 |
|---|---:|
| 是复制品（不是 fork，但共享 blob 达标） | 30 |
| 新增压缩包或可执行文件 | 35 |
| 载荷藏在子目录或带版本号 | 10 |
| README 链接到新增载荷 / 链接到别处的压缩包、短链 | 20 / 10 |
| release 里有原仓库没有的压缩包或可执行文件，且 README 指向 releases | 15 |
| 最近提交只改 README | 10 |
| 账号异常 | 5 |
| 星数与创建时间异常 | 5 |

等级：`≥ 70` high（疑似恶意复制品），`40～69` medium（可疑复制品），`< 40` low（复制品，多半是镜像或二次开发）。

误报控制：

- **没有载荷就到不了 high**：tree 里没有新增压缩包或可执行文件、release 里也没有被 README 指向的可疑资产时，分数封顶 50。整仓复制本身在开源许可下通常是合法的，单靠 README 特征不足以说“恶意”。
- 原仓库自己就有的压缩包（同 SHA 或同路径）不算新增，测试 fixture 里的 zip 不会误报。
- `--allow owner/repo` 和 `--allow-file`（每行一个 `owner/repo`，`#` 开头为注释）用于白名单，比如自己的镜像、合作者的二次开发。
- 默认只输出 medium 及以上，`--all` 输出全部复制品。
- 所有输出都用“疑似”措辞，只列事实（共享文件、新增文件、链接），不对账号下结论。

## 6. 输出

- `--format text`（默认）：每个原仓库一行汇总（候选数、复制品数），每个可疑复制品一个块：分数、等级、共享比例、新增载荷、理由。
- `--format json`：完整结构，供脚本使用。
- `--format md`：证据报告，每个复制品一节，包括共享文件表（路径对照，最多 20 行）、新增文件列表、README 下载链接、时间线，以及 GitHub 举报入口和“不要下载压缩包”的提醒。可以直接贴进举报表单。
- `-o <file>` 写入文件；`--fail-on <score>` 在有分数达到阈值的结果时退出码为 1，便于 Action 判断；出错时退出码为 2。
- `clonewatch render report.json --format md`：把保存的 JSON 报告重新渲染成其他格式，不再调用 API。Action 里扫描一次，再分别生成 job summary 和 issue 正文。

GitHub Action 示例见 `examples/clonewatch-weekly.yml`：每周一跑一次，默认 `GITHUB_TOKEN` 每小时只有 1,000 次请求，所以示例用 `--top 20`，并允许换成只读 PAT；把 Markdown 报告写进 job summary；有 high 结果时，用 `gh issue` 在用户自己的仓库里开一个 issue，已有就更新同一个 issue。

## 7. 限流

- 搜索：每次请求之间至少间隔 2.1 秒（30 次/分钟）。
- 所有请求：读 `x-ratelimit-remaining`，为 0 时等到 `x-ratelimit-reset`；收到 403/429 且带 `retry-after` 或 remaining 为 0 时等待后重试一次。需要等待超过 15 分钟时报错退出，并说明还剩多少没扫，而不是静默返回空结果。
- 其他 4xx/5xx 直接报错，带上接口和状态码。候选仓库 404/451（扫描期间被删除或封禁）记为 `gone`，计入汇总，不中断扫描。

## 8. 不做的事

- 不缓存、不做增量：每周扫一次的成本在 1 小时配额以内，先不引入状态。
- 不做全网 IOC 匹配、不做 GHArchive 分析、不做网页服务。
- 不检查私有仓库。
