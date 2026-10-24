//! Blob-SHA comparison between a source tree and a candidate tree.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::model::{Tree, TreeEntry};

/// SHA of the empty blob; every repo with an empty file shares it.
const EMPTY_BLOB: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFile {
    pub source_path: String,
    pub candidate_path: String,
    pub sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddedFile {
    pub path: String,
    pub sha: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    /// Distinct effective blob SHAs present in both trees.
    pub shared: usize,
    pub source_blobs: usize,
    pub candidate_blobs: usize,
    pub overlap: f64,
    pub incomplete: bool,
    pub shared_files: Vec<SharedFile>,
    /// Candidate blobs whose SHA and path are both absent from the source.
    pub added: Vec<AddedFile>,
}

impl Comparison {
    pub fn is_clone(&self, min_shared: usize, min_overlap: f64) -> bool {
        self.shared >= min_shared && self.overlap >= min_overlap
    }
}

fn effective(e: &TreeEntry, min_blob_size: u64) -> bool {
    e.sha != EMPTY_BLOB && e.size.unwrap_or(0) >= min_blob_size
}

pub fn compare(source: &Tree, candidate: &Tree, min_blob_size: u64) -> Comparison {
    let mut source_eff: HashMap<&str, &str> = HashMap::new();
    let mut source_all: HashSet<&str> = HashSet::new();
    let mut source_paths: HashSet<&str> = HashSet::new();
    for e in source.blobs() {
        source_all.insert(&e.sha);
        source_paths.insert(&e.path);
        if effective(e, min_blob_size) {
            source_eff.entry(&e.sha).or_insert(&e.path);
        }
    }

    let mut candidate_eff: HashSet<&str> = HashSet::new();
    let mut shared_files = Vec::new();
    let mut added = Vec::new();
    for e in candidate.blobs() {
        if effective(e, min_blob_size)
            && candidate_eff.insert(&e.sha)
            && let Some(src_path) = source_eff.get(e.sha.as_str())
        {
            shared_files.push(SharedFile {
                source_path: src_path.to_string(),
                candidate_path: e.path.clone(),
                sha: e.sha.clone(),
            });
        }
        if !source_all.contains(e.sha.as_str()) && !source_paths.contains(e.path.as_str()) {
            added.push(AddedFile {
                path: e.path.clone(),
                sha: e.sha.clone(),
                size: e.size,
            });
        }
    }

    let shared = shared_files.len();
    let ratio = |n: usize| {
        if n == 0 {
            0.0
        } else {
            shared as f64 / n as f64
        }
    };
    Comparison {
        shared,
        source_blobs: source_eff.len(),
        candidate_blobs: candidate_eff.len(),
        overlap: ratio(source_eff.len()).max(ratio(candidate_eff.len())),
        incomplete: source.truncated || candidate.truncated,
        shared_files,
        added,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(entries: &[(&str, &str, u64)]) -> Tree {
        Tree {
            tree: entries
                .iter()
                .map(|(p, s, n)| TreeEntry {
                    path: p.to_string(),
                    kind: "blob".into(),
                    sha: s.to_string(),
                    size: Some(*n),
                })
                .collect(),
            truncated: false,
        }
    }

    #[test]
    fn ignores_empty_and_tiny_blobs() {
        let src = tree(&[("a", EMPTY_BLOB, 0), ("b", "tiny", 10), ("c", "big", 500)]);
        let cand = tree(&[("x", EMPTY_BLOB, 0), ("y", "tiny", 10), ("z", "big", 500)]);
        let c = compare(&src, &cand, 64);
        assert_eq!(c.shared, 1);
        assert_eq!(c.source_blobs, 1);
        assert!(
            c.added.is_empty(),
            "tiny shared blob is not added: {:?}",
            c.added
        );
    }

    #[test]
    fn overlap_uses_the_larger_direction() {
        // Candidate copied 3 of 10 source files and added nothing else.
        let mut src: Vec<(String, String)> = (0..10)
            .map(|i| (format!("f{i}"), format!("s{i}")))
            .collect();
        let s = tree(
            &src.iter()
                .map(|(p, h)| (p.as_str(), h.as_str(), 100))
                .collect::<Vec<_>>(),
        );
        src.truncate(3);
        let c = tree(
            &src.iter()
                .map(|(p, h)| (p.as_str(), h.as_str(), 100))
                .collect::<Vec<_>>(),
        );
        let cmp = compare(&s, &c, 64);
        assert_eq!(cmp.shared, 3);
        assert!((cmp.overlap - 1.0).abs() < 1e-9);
    }

    #[test]
    fn same_path_with_new_content_is_not_added() {
        let src = tree(&[("README.md", "r1", 900)]);
        let cand = tree(&[("README.md", "r2", 1200), ("pkg/tool.zip", "z", 5000)]);
        let c = compare(&src, &cand, 64);
        let added: Vec<_> = c.added.iter().map(|a| a.path.as_str()).collect();
        assert_eq!(added, ["pkg/tool.zip"]);
    }
}
