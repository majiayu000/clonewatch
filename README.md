# clonewatch

Find fake repos that impersonate your GitHub project: malicious clones that copy your files (same git blob SHAs), are not forks, and add a zip or executable plus a rewritten README. A local, read-only CLI for open-source maintainers.

FakeGit-style campaigns copy a real project, rewrite the README with a "Download" button and drop a versioned archive into a subdirectory. The copy is not a GitHub fork, so the original maintainer never gets a notification, while people searching for the project (and AI agents searching for MCP servers or skills) land on the copy. Island counted about 7,600 such repositories in July 2026; Apiiro saw 17,610 reactivated in October, 97% of the sampled pushes changing only the README.

The README is rewritten, but the code isn't. clonewatch compares git blob SHAs from the GitHub tree API, so a copy is caught no matter how its README reads.

## Install

```bash
cargo install --locked --git https://github.com/majiayu000/clonewatch
```

It needs a GitHub token: `GITHUB_TOKEN` / `GH_TOKEN`, or whatever `gh auth token` prints. The token stays on your machine and is only sent to api.github.com.

## Usage

```bash
clonewatch scan majiayu000                    # every public non-fork repo of an account
clonewatch scan majiayu000 --top 10           # only the 10 most-starred
clonewatch scan owner/repo other/repo         # specific repos
clonewatch scan majiayu000 --format md -o report.md    # evidence report for an abuse form
clonewatch scan majiayu000 --format json -o report.json
clonewatch render report.json --format md     # re-render a saved scan, no API calls
```

Useful flags: `--all` (also show low-score clones such as mirrors), `--allow owner/repo` / `--allow-file` (never report these), `--fail-on 70` (exit 1 when something scores that high), `--max-candidates`, `--min-shared`, `--min-overlap`.

## Example

A real read-only run (2026-10-24) against one of the original projects named in Island's FakeGit report. Third-party account and repository names in this README and in `examples/` are replaced with placeholders (`original-a`, `owner-a/<project>-copy-1`); scores, reasons, paths and SHAs are unchanged.

```text
$ clonewatch scan original-a/claudecode-rule2hook
original-a/claudecode-rule2hook  ★403  candidates 1  clones 1
  [HIGH 100] https://github.com/owner-a/claudecode-rule2hook-copy-1  ★19  created 2025-07-04  shared 14/18 files (88%)
      + .claude/hook_rule_claudecode_3.4-alpha.4.zip (571 KB, archive)
      +30  not a fork, yet shares 14 of 18 distinctive files with original-a/claudecode-rule2hook (88% overlap)
      +35  adds archive/executable not in the original: .claude/hook_rule_claudecode_3.4-alpha.4.zip
      +10  payload is buried in a subdirectory or carries a version-like name
      +20  README links straight to the added payload
      +10  3 of the last 5 commits only touch the README
       +5  owner account is 1011 days old with 1 public repo(s)
```

The same run over the three originals from that report compared 113 same-name candidates and found 5 clones. Exactly the 3 known FakeGit baits scored high (100); the 2 plain mirrors scored 30 and 35, below the default output threshold ([`examples/validation-3-repos.txt`](examples/validation-3-repos.txt)). A scan of my own ten most-starred repositories compared 586 candidates and found no clones, using 622 API requests ([`examples/majiayu000-top10.txt`](examples/majiayu000-top10.txt)).

## How it works

1. **Find candidates**: repository search for `<name> in:name` (forks are excluded by GitHub search), plus `"<README title>" in:readme` when the title differs from the name. When a clone is found, that account's other repos are checked against your other repo names.
2. **Fingerprint**: one recursive tree call per candidate gives every blob SHA. Empty and tiny files (< 64 bytes) are ignored. A candidate is a *clone* if it shares at least 3 blobs and at least 50% of the smaller side.
3. **Score clones** (0 to 100, each point has a stated reason): added archives or executables (+35), buried or version-named payloads (+10), README linking to the payload (+20) or to other downloads or shorteners (+10), release assets the original never shipped, when the README points to releases (+15), recent commits that only touch the README (+10), a new or single-repo owner account (+5), as many stars as the original despite being newer (+5).
4. **False-positive control**: without an added archive or executable the score is capped at 50, so mirrors and forks-by-copy never reach `high`. Files the original already contains (for example a test fixture zip) never count as added. Default output shows `medium` (40+) and `high` (70+).

Details: [docs/design.md](docs/design.md). Research, API limits and GitHub's reporting flow: [docs/research.md](docs/research.md).

## Safety boundary

clonewatch never downloads, clones or unpacks anything from a candidate repository. It reads repository metadata, git trees (paths, sizes, SHAs), README text and release asset *names* from api.github.com. It doesn't follow links. It never writes to GitHub: no comments, issues or reports. You do the reporting yourself, with the Markdown evidence.

## Reporting a clone

Open the suspect repository, choose **Report repository** in the About sidebar (or use <https://support.github.com/contact/report-abuse>), and paste the finding from `--format md`: original URL, "not a fork", shared files, the added payload path and the README link. Don't download the archive to check it.

## Scheduled scan

[`examples/clonewatch-weekly.yml`](examples/clonewatch-weekly.yml) runs every Monday, writes the report to the job summary, and opens or updates one issue in your own repository when something scores `high`. Run it from a private repository, because the issue names the suspect repositories.

## Compared with github-healthcheck

[github-healthcheck](https://github.com/beardwhocodes/github-healthcheck) is a hosted service with the same goal. As of 2026-10-24:

| | github-healthcheck | clonewatch |
|---|---|---|
| Runs | hosted web service, sign in with GitHub, token stored for alerts | local binary or your own GitHub Action, token never leaves you |
| Finds candidates | `"<name> in:name"`, top 20, exact-name only, 8 inspected | name search up to 1,000, README title search, clone owners' other repos |
| Decides "is a copy" | same name + not a fork | shared git blob SHAs (how much of your code it contains) |
| Payload signals | README patterns, tree path names, release assets | tree additions relative to *your* tree, README links to that exact file, release assets your repo never shipped |
| Output | web report, email | terminal, JSON, Markdown evidence |

github-healthcheck also scores accounts and arbitrary repos, which clonewatch doesn't.

## Limits

- Public repositories and default branches only. A trees response over 100,000 entries or 7 MB is truncated, and the result is marked incomplete.
- A copier who reformats every file breaks blob matching. Renamed repos are found only through the README title search.
- Rate limits: search allows 30 requests a minute and core 5,000 an hour (1,000 for the Actions `GITHUB_TOKEN`). clonewatch waits for resets and exits with an error if a wait would be longer than 15 minutes.
- Findings are suspected copies. Copying open-source code is often allowed by its license; the payload is what matters.
