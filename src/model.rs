use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub sha: String,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tree {
    pub tree: Vec<TreeEntry>,
    #[serde(default)]
    pub truncated: bool,
}

impl Tree {
    pub fn blobs(&self) -> impl Iterator<Item = &TreeEntry> {
        self.tree.iter().filter(|e| e.kind == "blob")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Owner {
    pub login: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Repo {
    pub full_name: String,
    pub name: String,
    pub owner: Owner,
    pub html_url: String,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub archived: bool,
    pub stargazers_count: u64,
    pub created_at: String,
    #[serde(default)]
    pub pushed_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub created_at: String,
    pub public_repos: u64,
}

/// Everything fetched about a confirmed clone beyond its tree. All of it is
/// metadata or README text; no file content of the candidate is downloaded.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub readme: Option<String>,
    pub commit_titles: Vec<String>,
    pub owner: Option<User>,
    pub release_assets: Vec<String>,
}
