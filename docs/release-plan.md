# 发布步骤

已定（2026-10-29）：

1. 许可证 MIT（`LICENSE`，`Cargo.toml` 里 `license = "MIT"`）。
2. 仓库 `majiayu000/clonewatch`，公开。
3. `examples/`、README 和 docs 里的第三方账号与仓库名都换成了占位符，检测结构、分数、理由和证据不变。
4. 不举报任何扫描结果，工具也不加举报功能。
5. 发布到 crates.io，`clonewatch` 这个名字在 2026-10-29 查询时未被占用（API 返回 404）。

步骤：

1. 建仓库并推送 `main`（由发起会话执行）。topics 建议：`fake-repo`、`malicious-clone`、`github-impersonation`、`maintainer`、`supply-chain-security`、`fakegit`、`rust`、`cli`。
2. 确认 CI（`.github/workflows/ci.yml`，ubuntu + macOS 跑 test 和 clippy）通过。
3. 打 tag `v0.1.0`，发布 GitHub Release；`release.yml` 会上传 macOS arm64/x86_64、Linux x86_64 musl 二进制和 `.sha256`。
4. `cargo publish --dry-run` 通过后执行 `cargo publish`。
5. 不实际触发 `examples/clonewatch-weekly.yml`。
