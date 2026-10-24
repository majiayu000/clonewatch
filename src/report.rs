//! Terminal, JSON and Markdown renderings of a scan report.

use std::fmt::Write;

use crate::scan::{Finding, Report};

const REPORT_URL: &str = "https://support.github.com/contact/report-abuse";

fn size(n: Option<u64>) -> String {
    match n {
        Some(b) if b >= 1024 * 1024 => format!("{:.1} MB", b as f64 / 1048576.0),
        Some(b) if b >= 1024 => format!("{:.0} KB", b as f64 / 1024.0),
        Some(b) => format!("{b} B"),
        None => "? B".into(),
    }
}

fn shown(r: &Report, min_score: u32) -> impl Iterator<Item = &Finding> {
    r.sources
        .iter()
        .flat_map(|s| &s.findings)
        .filter(move |f| f.signals.score >= min_score)
}

struct Totals {
    candidates: usize,
    clones: usize,
    flagged: usize,
}

fn totals(r: &Report, min_score: u32) -> Totals {
    Totals {
        candidates: r.sources.iter().map(|s| s.candidates).sum(),
        clones: r.sources.iter().map(|s| s.clones).sum(),
        flagged: shown(r, min_score).count(),
    }
}

pub fn json(r: &Report) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
}

pub fn text(r: &Report, min_score: u32) -> String {
    let t = totals(r, min_score);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "clonewatch {}  repos {}  candidates {}  clones {}  shown {} (score >= {})  api requests {}\n",
        &r.generated_at[..10],
        r.sources.len(),
        t.candidates,
        t.clones,
        t.flagged,
        min_score,
        r.api_requests
    );
    for s in &r.sources {
        let _ = writeln!(
            o,
            "{}  ★{}  candidates {}  clones {}{}{}{}",
            s.source.full_name,
            s.source.stargazers_count,
            s.candidates,
            s.clones,
            if s.gone > 0 {
                format!("  gone {}", s.gone)
            } else {
                String::new()
            },
            if s.allowed > 0 {
                format!("  allowed {}", s.allowed)
            } else {
                String::new()
            },
            if s.source_incomplete {
                "  [source tree truncated]"
            } else {
                ""
            },
        );
        let mut findings: Vec<&Finding> = s
            .findings
            .iter()
            .filter(|f| f.signals.score >= min_score)
            .collect();
        findings.sort_by_key(|f| std::cmp::Reverse(f.signals.score));
        for f in findings {
            let c = &f.comparison;
            let _ = writeln!(
                o,
                "  [{} {:>3}] {}  ★{}  created {}  shared {}/{} files ({:.0}%){}",
                f.signals.level.to_uppercase(),
                f.signals.score,
                f.candidate.html_url,
                f.candidate.stargazers_count,
                &f.candidate.created_at[..10],
                c.shared,
                c.source_blobs,
                c.overlap * 100.0,
                if c.incomplete {
                    " [tree truncated]"
                } else {
                    ""
                },
            );
            for p in &f.signals.payloads {
                let _ = writeln!(
                    o,
                    "      + {} ({}, {})",
                    p.path,
                    size(p.size),
                    p.kind.as_str()
                );
            }
            for reason in &f.signals.reasons {
                let _ = writeln!(o, "      {:>+3}  {}", reason.points, reason.text);
            }
        }
    }
    if t.flagged > 0 {
        let _ = writeln!(
            o,
            "\nDo not download or open the payloads above. Report with --format md evidence at {REPORT_URL}"
        );
    }
    o
}

pub fn markdown(r: &Report, min_score: u32) -> String {
    let t = totals(r, min_score);
    let mut o = String::new();
    let _ = writeln!(o, "# clonewatch report\n");
    let _ = writeln!(
        o,
        "Generated {} for `{}`. {} source repos, {} candidates compared, {} clones (shared git blobs, not forks), {} shown with score >= {}.\n",
        r.generated_at,
        r.targets.join("`, `"),
        r.sources.len(),
        t.candidates,
        t.clones,
        t.flagged,
        min_score
    );
    let _ = writeln!(
        o,
        "Only repository metadata, git trees and README text were read. No archive, executable or release asset was downloaded. Findings are *suspected* copies; verify before reporting.\n"
    );
    let _ = writeln!(
        o,
        "| Source | ★ | Candidates | Clones | Shown |\n|---|---:|---:|---:|---:|"
    );
    for s in &r.sources {
        let n = s
            .findings
            .iter()
            .filter(|f| f.signals.score >= min_score)
            .count();
        let _ = writeln!(
            o,
            "| [{}]({}) | {} | {} | {} | {} |",
            s.source.full_name,
            s.source.html_url,
            s.source.stargazers_count,
            s.candidates,
            s.clones,
            n
        );
    }
    let mut findings: Vec<&Finding> = shown(r, min_score).collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.signals.score));
    for f in findings {
        let c = &f.comparison;
        let cand = &f.candidate;
        let _ = writeln!(
            o,
            "\n## {} — {} ({})\n",
            cand.full_name, f.signals.level, f.signals.score
        );
        let _ = writeln!(
            o,
            "- Suspect: <{}> (not a fork, ★{})",
            cand.html_url, cand.stargazers_count
        );
        let _ = writeln!(o, "- Original: <https://github.com/{}>", f.source);
        let _ = writeln!(
            o,
            "- Shared files: {} of {} in the original, {} in the suspect ({:.0}% overlap){}",
            c.shared,
            c.source_blobs,
            c.candidate_blobs,
            c.overlap * 100.0,
            if c.incomplete {
                "; tree truncated, counts are partial"
            } else {
                ""
            }
        );
        let _ = writeln!(
            o,
            "- Timeline: created {}, last push {}",
            cand.created_at,
            cand.pushed_at.as_deref().unwrap_or("?")
        );
        let _ = writeln!(o, "\n**Why**\n");
        for reason in &f.signals.reasons {
            let _ = writeln!(o, "- (+{}) {}", reason.points, reason.text);
        }
        if !f.signals.payloads.is_empty() || !f.signals.release_payloads.is_empty() {
            let _ = writeln!(o, "\n**Added payloads (do not download)**\n");
            let _ = writeln!(o, "| Path | Size | Blob SHA |\n|---|---:|---|");
            for p in &f.signals.payloads {
                let _ = writeln!(o, "| `{}` | {} | `{}` |", p.path, size(p.size), p.sha);
            }
            for a in &f.signals.release_payloads {
                let _ = writeln!(o, "| release asset `{a}` | | |");
            }
        }
        if !f.signals.readme_links.is_empty() {
            let _ = writeln!(o, "\n**README download links (not followed)**\n");
            for l in &f.signals.readme_links {
                let _ = writeln!(o, "- `{l}`");
            }
        }
        let _ = writeln!(
            o,
            "\n<details><summary>Shared files (same git blob SHA)</summary>\n"
        );
        let _ = writeln!(
            o,
            "| Original path | Suspect path | Blob SHA |\n|---|---|---|"
        );
        for sf in c.shared_files.iter().take(20) {
            let _ = writeln!(
                o,
                "| `{}` | `{}` | `{}` |",
                sf.source_path,
                sf.candidate_path,
                &sf.sha[..12.min(sf.sha.len())]
            );
        }
        if c.shared_files.len() > 20 {
            let _ = writeln!(o, "| … {} more | | |", c.shared_files.len() - 20);
        }
        let _ = writeln!(o, "\n</details>");
        let other_added: Vec<&str> = c
            .added
            .iter()
            .filter(|a| !f.signals.payloads.iter().any(|p| p.path == a.path))
            .map(|a| a.path.as_str())
            .collect();
        if !other_added.is_empty() {
            let _ = writeln!(
                o,
                "\nOther files not in the original: {}",
                other_added
                    .iter()
                    .map(|p| format!("`{p}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if t.flagged > 0 {
        let _ = writeln!(
            o,
            "\n## Reporting\n\nOn each suspect repository page use **Report repository** (About sidebar), or the form at <{REPORT_URL}>. Paste the section above: original URL, \"not a fork\", shared files, added payload paths and README links. Do not download the payload to confirm it."
        );
    }
    o
}
