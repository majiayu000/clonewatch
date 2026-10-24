//! End-to-end scoring on synthetic git trees (no network).

use chrono::{DateTime, Utc};
use clonewatch::fingerprint::compare;
use clonewatch::model::{Evidence, Owner, Repo, Tree, User};
use clonewatch::signals::{PayloadKind, evaluate};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn load_tree(name: &str) -> Tree {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn repo(full: &str, stars: u64, created: &str) -> Repo {
    let (owner, name) = full.split_once('/').unwrap();
    Repo {
        full_name: full.into(),
        name: name.into(),
        owner: Owner {
            login: owner.into(),
        },
        html_url: format!("https://github.com/{full}"),
        fork: false,
        archived: false,
        stargazers_count: stars,
        created_at: created.into(),
        pushed_at: None,
    }
}

fn now() -> DateTime<Utc> {
    "2026-10-24T00:00:00Z".parse().unwrap()
}

#[test]
fn bait_clone_scores_high() {
    let src_tree = load_tree("source_tree.json");
    let bait_tree = load_tree("bait_tree.json");
    let cmp = compare(&src_tree, &bait_tree, 64);
    assert_eq!(cmp.shared, 9);
    assert!(cmp.is_clone(3, 0.5), "overlap {}", cmp.overlap);
    let added: Vec<&str> = cmp.added.iter().map(|a| a.path.as_str()).collect();
    assert_eq!(added, [".claude/hook_rule_claudecode_3.4-alpha.4.zip"]);

    let evidence = Evidence {
        readme: Some(std::fs::read_to_string(format!("{FIXTURES}/bait_readme.md")).unwrap()),
        commit_titles: vec![
            "Update README.md".into(),
            "Update README.md".into(),
            "Update README.md".into(),
            "Enhance rule2hook prompt".into(),
        ],
        owner: Some(User {
            created_at: "2024-01-16T18:46:08Z".into(),
            public_repos: 1,
        }),
        release_assets: vec![],
    };
    let s = evaluate(
        &cmp,
        &repo("original/claudecode-rule2hook", 403, "2025-07-01T13:18:41Z"),
        &repo(
            "example-bait/claudecode-rule2hook",
            19,
            "2025-07-04T18:23:05Z",
        ),
        &evidence,
        &[],
        now(),
    );
    assert_eq!(s.level, "high");
    assert_eq!(s.score, 100);
    assert_eq!(s.payloads.len(), 1);
    assert_eq!(s.payloads[0].kind, PayloadKind::Archive);
    assert!(
        s.reasons
            .iter()
            .any(|r| r.text.contains("README links straight"))
    );
    assert!(
        s.reasons
            .iter()
            .any(|r| r.text.contains("only touch the README"))
    );
}

#[test]
fn benign_mirror_is_a_clone_but_stays_low() {
    let cmp = compare(
        &load_tree("source_tree.json"),
        &load_tree("mirror_tree.json"),
        64,
    );
    assert!(cmp.is_clone(3, 0.5));
    // The source's own fixture zip is shared, so it is not an added payload.
    assert_eq!(cmp.added.len(), 1);
    let s = evaluate(
        &cmp,
        &repo("original/tool", 50, "2025-01-01T00:00:00Z"),
        &repo("mirror/tool", 0, "2025-06-01T00:00:00Z"),
        &Evidence::default(),
        &[],
        now(),
    );
    assert!(s.payloads.is_empty());
    assert_eq!(s.level, "low", "score {}", s.score);
}

#[test]
fn readme_lure_without_payload_is_capped() {
    let cmp = compare(
        &load_tree("source_tree.json"),
        &load_tree("mirror_tree.json"),
        64,
    );
    let evidence = Evidence {
        readme: Some("[Download](https://bit.ly/xyz)".into()),
        commit_titles: vec!["Update README.md".into(), "Update README.md".into()],
        owner: Some(User {
            created_at: "2026-10-01T00:00:00Z".into(),
            public_repos: 1,
        }),
        release_assets: vec![],
    };
    let s = evaluate(
        &cmp,
        &repo("original/tool", 5, "2025-01-01T00:00:00Z"),
        &repo("lure/tool", 10, "2026-10-02T00:00:00Z"),
        &evidence,
        &[],
        now(),
    );
    assert_eq!(s.score, 50, "{:?}", s.reasons);
    assert_eq!(s.level, "medium");
}

#[test]
fn release_assets_shipped_by_the_original_do_not_count() {
    let cmp = compare(
        &load_tree("source_tree.json"),
        &load_tree("mirror_tree.json"),
        64,
    );
    let evidence = Evidence {
        release_assets: vec!["tool-x86_64.tar.gz".into(), "Setup_v2.1.exe".into()],
        ..Default::default()
    };
    let s = evaluate(
        &cmp,
        &repo("original/tool", 5, "2025-01-01T00:00:00Z"),
        &repo("other/tool", 0, "2025-02-01T00:00:00Z"),
        &evidence,
        &["tool-x86_64.tar.gz".into()],
        now(),
    );
    assert_eq!(s.release_payloads, ["Setup_v2.1.exe"]);
    // Own builds in releases are normal; without a README pointer they add nothing.
    assert_eq!(s.score, 30);

    let lured = Evidence {
        readme: Some("[Get it](https://github.com/other/tool/releases/latest)".into()),
        ..evidence
    };
    let s = evaluate(
        &cmp,
        &repo("original/tool", 5, "2025-01-01T00:00:00Z"),
        &repo("other/tool", 0, "2025-02-01T00:00:00Z"),
        &lured,
        &["tool-x86_64.tar.gz".into()],
        now(),
    );
    assert_eq!(s.score, 45, "{:?}", s.reasons);
}

#[test]
fn unrelated_same_name_repo_is_not_a_clone() {
    let cmp = compare(
        &load_tree("source_tree.json"),
        &load_tree("unrelated_tree.json"),
        64,
    );
    assert_eq!(cmp.shared, 0);
    assert!(!cmp.is_clone(3, 0.5));
}

#[test]
fn truncated_tree_is_marked_incomplete() {
    let mut t = load_tree("bait_tree.json");
    t.truncated = true;
    let cmp = compare(&load_tree("source_tree.json"), &t, 64);
    assert!(cmp.incomplete);
}
