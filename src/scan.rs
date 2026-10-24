//! Candidate discovery and per-candidate analysis.

use std::collections::HashSet;

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fingerprint::{Comparison, compare};
use crate::github::GitHub;
use crate::model::{Evidence, Repo, Tree};
use crate::signals::{Signals, evaluate};

pub struct Options {
    pub top: Option<usize>,
    pub max_candidates: usize,
    pub min_shared: usize,
    pub min_overlap: f64,
    pub min_blob_size: u64,
    /// Lowercase `owner/repo` entries never reported.
    pub allow: HashSet<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub source: String,
    pub candidate: Repo,
    pub comparison: Comparison,
    pub signals: Signals,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SourceResult {
    pub source: Repo,
    pub source_incomplete: bool,
    /// Distinct candidates whose tree was compared.
    pub candidates: usize,
    pub clones: usize,
    /// Candidates deleted or blocked while scanning, or empty.
    pub gone: usize,
    pub allowed: usize,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub generated_at: String,
    pub targets: Vec<String>,
    pub sources: Vec<SourceResult>,
    pub api_requests: u32,
}

/// Lowercase alphanumerics only, so `My_Tool` and `my-tool` compare equal.
pub fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// A name-search hit must contain the source name (`tool`, `tool-pro`,
/// `my_tool`); search tokenizing alone also returns unrelated names.
pub fn name_matches(source: &str, candidate: &str) -> bool {
    norm(candidate).contains(&norm(source))
}

/// First `# ` heading of a README, reduced to plain words, if it says more
/// than the repository name does.
pub fn readme_title(readme: &str, repo_name: &str) -> Option<String> {
    let line = readme.lines().find(|l| l.starts_with("# "))?;
    let words: Vec<String> = line[2..]
        .split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
                .collect::<String>()
        })
        .filter(|w| !w.is_empty())
        .collect();
    let title = words.join(" ");
    (words.len() >= 2 && title.len() <= 80 && norm(&title) != norm(repo_name)).then_some(title)
}

enum Outcome {
    Gone,
    NotClone,
    Clone(Box<Finding>),
}

struct Source {
    repo: Repo,
    tree: Tree,
    release_assets: Option<Vec<String>>,
    compared: HashSet<String>,
    result: SourceResult,
}

pub struct Scanner<'a> {
    gh: &'a GitHub,
    opts: Options,
    now: DateTime<Utc>,
}

impl<'a> Scanner<'a> {
    pub fn new(gh: &'a GitHub, opts: Options, now: DateTime<Utc>) -> Self {
        Self { gh, opts, now }
    }

    fn resolve(&self, targets: &[String]) -> Result<Vec<Repo>> {
        let mut out = Vec::new();
        for t in targets {
            if t.contains('/') {
                match self.gh.repo(t)? {
                    Some(r) => out.push(r),
                    None => bail!("repository {t} not found"),
                }
            } else {
                let mut repos: Vec<Repo> = self
                    .gh
                    .owner_repos(t)?
                    .ok_or_else(|| anyhow!("account {t} not found"))?
                    .into_iter()
                    .filter(|r| !r.fork && !r.archived)
                    .collect();
                repos.sort_by_key(|r| std::cmp::Reverse(r.stargazers_count));
                if let Some(n) = self.opts.top {
                    repos.truncate(n);
                }
                if repos.is_empty() {
                    bail!("{t} has no public non-fork repositories");
                }
                out.extend(repos);
            }
        }
        Ok(out)
    }

    pub fn run(&self, targets: &[String]) -> Result<Report> {
        let repos = self.resolve(targets)?;
        let mine: HashSet<String> = repos.iter().map(|r| r.owner.login.to_lowercase()).collect();
        let mut sources = Vec::new();
        for (i, repo) in repos.into_iter().enumerate() {
            eprintln!("clonewatch: [{}] {}", i + 1, repo.full_name);
            let tree = self.gh.tree(&repo.full_name)?.unwrap_or(Tree {
                tree: vec![],
                truncated: false,
            });
            let mut src = Source {
                result: SourceResult {
                    source: repo.clone(),
                    source_incomplete: tree.truncated,
                    candidates: 0,
                    clones: 0,
                    gone: 0,
                    allowed: 0,
                    findings: vec![],
                },
                repo,
                tree,
                release_assets: None,
                compared: HashSet::new(),
            };
            if src.tree.tree.is_empty() {
                sources.push(src);
                continue;
            }
            for cand in self.discover(&src.repo)? {
                self.consider(&mut src, cand, &mine)?;
            }
            sources.push(src);
        }
        self.expand_clone_owners(&mut sources, &mine)?;

        Ok(Report {
            generated_at: self.now.to_rfc3339(),
            targets: targets.to_vec(),
            sources: sources.into_iter().map(|s| s.result).collect(),
            api_requests: self.gh.requests(),
        })
    }

    fn discover(&self, source: &Repo) -> Result<Vec<Repo>> {
        let max = self.opts.max_candidates;
        let mut out: Vec<Repo> = self
            .gh
            .search_repos(&format!("{} in:name", source.name), max)?
            .into_iter()
            .filter(|r| name_matches(&source.name, &r.name))
            .collect();
        if let Some(title) = self
            .gh
            .readme(&source.full_name)?
            .and_then(|readme| readme_title(&readme, &source.name))
        {
            out.extend(
                self.gh
                    .search_repos(&format!("\"{title}\" in:readme"), max)?,
            );
        }
        let mut seen = HashSet::new();
        out.retain(|r| seen.insert(r.full_name.to_lowercase()));
        Ok(out)
    }

    fn consider(&self, src: &mut Source, cand: Repo, mine: &HashSet<String>) -> Result<()> {
        let key = cand.full_name.to_lowercase();
        if cand.fork
            || mine.contains(&cand.owner.login.to_lowercase())
            || !src.compared.insert(key.clone())
        {
            return Ok(());
        }
        if self.opts.allow.contains(&key) {
            src.result.allowed += 1;
            return Ok(());
        }
        src.result.candidates += 1;
        match self.analyze(src, cand)? {
            Outcome::Gone => src.result.gone += 1,
            Outcome::NotClone => {}
            Outcome::Clone(f) => {
                src.result.clones += 1;
                src.result.findings.push(*f);
            }
        }
        Ok(())
    }

    fn analyze(&self, src: &mut Source, cand: Repo) -> Result<Outcome> {
        let Some(tree) = self.gh.tree(&cand.full_name)? else {
            return Ok(Outcome::Gone);
        };
        let cmp = compare(&src.tree, &tree, self.opts.min_blob_size);
        if !cmp.is_clone(self.opts.min_shared, self.opts.min_overlap) {
            return Ok(Outcome::NotClone);
        }
        let name = cand.full_name.as_str();
        let evidence = Evidence {
            readme: self.gh.readme(name)?,
            commit_titles: self.gh.commit_titles(name, 5)?,
            owner: self.gh.user(&cand.owner.login)?,
            release_assets: self.gh.release_asset_names(name)?,
        };
        if src.release_assets.is_none() {
            src.release_assets = Some(self.gh.release_asset_names(&src.repo.full_name)?);
        }
        let signals = evaluate(
            &cmp,
            &src.repo,
            &cand,
            &evidence,
            src.release_assets.as_deref().unwrap_or_default(),
            self.now,
        );
        Ok(Outcome::Clone(Box::new(Finding {
            source: src.repo.full_name.clone(),
            candidate: cand,
            comparison: cmp,
            signals,
        })))
    }

    /// Copier accounts often take several projects from the same author: look
    /// at each clone owner's other repos for names matching our other sources.
    fn expand_clone_owners(&self, sources: &mut [Source], mine: &HashSet<String>) -> Result<()> {
        let owners: Vec<String> = {
            let mut seen = HashSet::new();
            sources
                .iter()
                .flat_map(|s| &s.result.findings)
                .map(|f| f.candidate.owner.login.clone())
                .filter(|o| seen.insert(o.to_lowercase()))
                .collect()
        };
        for owner in owners {
            // The account may have been removed since its clone was found.
            let Some(theirs) = self.gh.owner_repos(&owner)? else {
                continue;
            };
            for repo in theirs {
                for src in sources.iter_mut() {
                    if !src.tree.tree.is_empty() && norm(&repo.name) == norm(&src.repo.name) {
                        self.consider(src, repo.clone(), mine)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matching() {
        assert!(name_matches("litellm-rs", "LiteLLM_RS"));
        assert!(name_matches("spellbook", "spellbook-pro"));
        assert!(!name_matches("spellbook", "book"));
        assert!(!name_matches("harness", "harn"));
    }

    #[test]
    fn titles() {
        assert_eq!(
            readme_title("<p>x</p>\n# 🦀 LiteLLM in Rust\n", "litellm-rs").as_deref(),
            Some("LiteLLM in Rust")
        );
        assert_eq!(readme_title("# spellbook\n", "spellbook"), None);
        assert_eq!(readme_title("# Spell Book\n", "spellbook"), None);
    }
}
