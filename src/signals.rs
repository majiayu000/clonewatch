//! Suspicious-feature detection and scoring for a confirmed clone.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fingerprint::Comparison;
use crate::model::{Evidence, Repo};

const ARCHIVE_EXT: &[&str] = &[
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".cab", ".iso", ".dmg", ".img",
];
const EXECUTABLE_EXT: &[&str] = &[
    ".exe", ".dll", ".scr", ".msi", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".apk", ".lnk",
];
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "goo.gl",
    "t.co",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
];
const NEW_ACCOUNT_DAYS: i64 = 180;
/// Without an archive or executable payload a clone cannot reach "high".
const NO_PAYLOAD_CAP: u32 = 50;

pub const HIGH: u32 = 70;
pub const MEDIUM: u32 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadKind {
    Archive,
    Executable,
}

impl PayloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadKind::Archive => "archive",
            PayloadKind::Executable => "executable",
        }
    }
}

pub fn payload_kind(path: &str) -> Option<PayloadKind> {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if ARCHIVE_EXT.iter().any(|e| name.ends_with(e)) {
        Some(PayloadKind::Archive)
    } else if EXECUTABLE_EXT.iter().any(|e| name.ends_with(e)) {
        Some(PayloadKind::Executable)
    } else {
        None
    }
}

/// `tool_v2.5.zip`, `hook_3.4-alpha.4.zip`, `setup-rc1.exe`.
fn has_version(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let b = lower.as_bytes();
    let dotted = b
        .windows(3)
        .any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit());
    dotted || ["alpha", "beta", "-rc"].iter().any(|t| lower.contains(t))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub path: String,
    pub sha: String,
    pub size: Option<u64>,
    pub kind: PayloadKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reason {
    pub points: u32,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signals {
    pub payloads: Vec<Payload>,
    pub readme_links: Vec<String>,
    pub release_payloads: Vec<String>,
    pub score: u32,
    pub level: String,
    pub reasons: Vec<Reason>,
}

pub fn level(score: u32) -> &'static str {
    if score >= HIGH {
        "high"
    } else if score >= MEDIUM {
        "medium"
    } else {
        "low"
    }
}

/// Links in markdown/HTML/plain text. Only extracted, never followed.
pub fn extract_links(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |s: &str| {
        let s = s
            .trim()
            .trim_matches(|c| c == '<' || c == '>' || c == '"' || c == '\'');
        if !s.is_empty() && !out.iter().any(|o: &String| o == s) {
            out.push(s.to_string());
        }
    };
    // Markdown targets: `](target)` including relative paths.
    for part in text.split("](").skip(1) {
        if let Some(end) = part.find([')', ' ']) {
            push(&part[..end]);
        }
    }
    // href="..." and bare URLs.
    for marker in ["href=\"", "href='"] {
        for part in text.split(marker).skip(1) {
            if let Some(end) = part.find(['"', '\'']) {
                push(&part[..end]);
            }
        }
    }
    for scheme in ["https://", "http://"] {
        for part in text.split(scheme).skip(1) {
            let end = part
                .find(|c: char| c.is_whitespace() || "()[]<>\"'`".contains(c))
                .unwrap_or(part.len());
            push(&format!("{scheme}{}", &part[..end]));
        }
    }
    // Broken markup glues text onto a URL; keep only the shortest variant.
    let all = out.clone();
    out.retain(|l| {
        !all.iter()
            .any(|o| o.len() < l.len() && l.starts_with(o.as_str()))
    });
    out
}

fn strip_query(link: &str) -> &str {
    link.split(['?', '#']).next().unwrap_or(link)
}

fn is_shortener(link: &str) -> bool {
    let host = link
        .split("://")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .unwrap_or("")
        .trim_start_matches("www.");
    SHORTENERS.contains(&host)
}

fn is_download_link(link: &str) -> bool {
    let target = strip_query(link);
    payload_kind(target).is_some()
        || target.contains("/releases/download/")
        || target.contains("/raw/")
        || target.contains("raw.githubusercontent.com")
        || is_shortener(link)
}

fn links_to(link: &str, payload_path: &str) -> bool {
    let target = strip_query(link).replace("%20", " ");
    let file = payload_path.rsplit('/').next().unwrap_or(payload_path);
    target.ends_with(payload_path) || target.ends_with(&format!("/{file}")) || target == file
}

fn readme_only_commit(title: &str) -> bool {
    let t = title.trim().to_ascii_lowercase();
    t.starts_with("update readme")
        || t.starts_with("create readme")
        || t == "readme"
        || t == "readme.md"
}

fn days_between(earlier: &str, later: DateTime<Utc>) -> Option<i64> {
    let t = DateTime::parse_from_rfc3339(earlier).ok()?;
    Some((later - t.with_timezone(&Utc)).num_days())
}

pub fn evaluate(
    cmp: &Comparison,
    source: &Repo,
    candidate: &Repo,
    evidence: &Evidence,
    source_release_assets: &[String],
    now: DateTime<Utc>,
) -> Signals {
    let mut reasons = Vec::new();
    let mut add = |points: u32, text: String| reasons.push(Reason { points, text });

    add(
        30,
        format!(
            "not a fork, yet shares {} of {} distinctive files with {} ({:.0}% overlap)",
            cmp.shared,
            cmp.source_blobs,
            source.full_name,
            cmp.overlap * 100.0
        ),
    );

    let payloads: Vec<Payload> = cmp
        .added
        .iter()
        .filter_map(|a| {
            payload_kind(&a.path).map(|kind| Payload {
                path: a.path.clone(),
                sha: a.sha.clone(),
                size: a.size,
                kind,
            })
        })
        .collect();
    if !payloads.is_empty() {
        let names: Vec<&str> = payloads.iter().map(|p| p.path.as_str()).collect();
        add(
            35,
            format!(
                "adds archive/executable not in the original: {}",
                names.join(", ")
            ),
        );
        if payloads
            .iter()
            .any(|p| p.path.contains('/') || has_version(&p.path))
        {
            add(
                10,
                "payload is buried in a subdirectory or carries a version-like name".into(),
            );
        }
    }

    let all_links = evidence
        .readme
        .as_deref()
        .map(extract_links)
        .unwrap_or_default();
    let readme_links: Vec<String> = all_links
        .iter()
        .filter(|l| is_download_link(l) || payloads.iter().any(|p| links_to(l, &p.path)))
        .cloned()
        .collect();
    if readme_links
        .iter()
        .any(|l| payloads.iter().any(|p| links_to(l, &p.path)))
    {
        add(20, "README links straight to the added payload".into());
    } else if !readme_links.is_empty() {
        add(
            10,
            format!(
                "README has download/shortener links: {}",
                readme_links.join(", ")
            ),
        );
    }

    let release_payloads: Vec<String> = evidence
        .release_assets
        .iter()
        .filter(|a| payload_kind(a).is_some() && !source_release_assets.contains(a))
        .cloned()
        .collect();
    // Projects legitimately ship their own builds as release assets; they only
    // count when the README sends readers to the releases page.
    let readme_points_to_releases = all_links.iter().any(|l| l.contains("/releases"));
    if !release_payloads.is_empty() {
        let points = if readme_points_to_releases { 15 } else { 0 };
        add(
            points,
            format!(
                "release assets the original never shipped{}: {}",
                if readme_points_to_releases {
                    ", linked from the README"
                } else {
                    " (README does not link to releases)"
                },
                release_payloads.join(", ")
            ),
        );
    }

    let readme_commits = evidence
        .commit_titles
        .iter()
        .filter(|t| readme_only_commit(t))
        .count();
    if readme_commits >= 2 {
        add(
            10,
            format!(
                "{readme_commits} of the last {} commits only touch the README",
                evidence.commit_titles.len()
            ),
        );
    }

    if let Some(user) = &evidence.owner {
        let age = days_between(&user.created_at, now);
        if age.is_some_and(|d| d < NEW_ACCOUNT_DAYS) || user.public_repos <= 1 {
            add(
                5,
                format!(
                    "owner account is {} days old with {} public repo(s)",
                    age.map_or("?".into(), |d| d.to_string()),
                    user.public_repos
                ),
            );
        }
    }

    if candidate.created_at > source.created_at
        && candidate.stargazers_count > 0
        && candidate.stargazers_count >= source.stargazers_count
    {
        add(
            5,
            format!(
                "created after the original but has as many stars ({} vs {})",
                candidate.stargazers_count, source.stargazers_count
            ),
        );
    }

    let mut score: u32 = reasons.iter().map(|r| r.points).sum::<u32>().min(100);
    if payloads.is_empty() && !(readme_points_to_releases && !release_payloads.is_empty()) {
        score = score.min(NO_PAYLOAD_CAP);
    }
    Signals {
        payloads,
        readme_links,
        release_payloads,
        score,
        level: level(score).to_string(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_payloads() {
        assert_eq!(
            payload_kind("a/b/Tool_v2.5.ZIP"),
            Some(PayloadKind::Archive)
        );
        assert_eq!(payload_kind("x.tar.gz"), Some(PayloadKind::Archive));
        assert_eq!(payload_kind("setup.exe"), Some(PayloadKind::Executable));
        assert_eq!(payload_kind("src/main.rs"), None);
        assert_eq!(payload_kind("docs/zip.md"), None);
    }

    #[test]
    fn version_names() {
        assert!(has_version("hook_rule_claudecode_3.4-alpha.4.zip"));
        assert!(has_version("convertor_v2.5.zip"));
        assert!(!has_version("release.zip"));
    }

    #[test]
    fn extracts_and_classifies_links() {
        let md = "[Download](https://github.com/x/y/raw/refs/heads/main/.claude/hook_3.4.zip) \
                  <a href=\"https://bit.ly/abc\">go</a> see https://docs.rs/foo and [rel](test/a_v2.5.zip)";
        let links = extract_links(md);
        assert!(links.contains(&"https://bit.ly/abc".to_string()));
        assert!(links.contains(&"test/a_v2.5.zip".to_string()));
        let glued = extract_links(
            "[x](https://h/a.zip) https://h/a.zip%20Latest%20Release-Click%https://h/a.zip",
        );
        assert_eq!(glued, ["https://h/a.zip"]);
        assert!(is_download_link("https://bit.ly/abc"));
        assert!(!is_download_link("https://docs.rs/foo"));
        assert!(links_to(
            "https://github.com/x/y/raw/refs/heads/main/.claude/hook_3.4.zip",
            ".claude/hook_3.4.zip"
        ));
        assert!(links_to("test/a_v2.5.zip", "test/a_v2.5.zip"));
    }

    #[test]
    fn readme_commit_titles() {
        assert!(readme_only_commit("Update README.md"));
        assert!(!readme_only_commit("Fix installation instructions"));
    }
}
