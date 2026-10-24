//! Read-only GitHub REST client. It exposes only the metadata endpoints
//! clonewatch needs; there is deliberately no method that fetches blob
//! contents, raw files, archives or release asset downloads.

use std::cell::Cell;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::model::{Repo, Tree, User};

const API: &str = "https://api.github.com";
/// 30 search requests per minute for authenticated clients.
const SEARCH_INTERVAL: Duration = Duration::from_millis(2100);
const MAX_WAIT: Duration = Duration::from_secs(15 * 60);
const TRANSPORT_RETRIES: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_secs(3);

pub struct GitHub {
    agent: ureq::Agent,
    auth: String,
    last_search: Cell<Option<Instant>>,
    requests: Cell<u32>,
}

pub fn token() -> Result<String> {
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(t) = std::env::var(var)
            && !t.trim().is_empty()
        {
            return Ok(t.trim().to_string());
        }
    }
    let out = Command::new("gh")
        .args(["auth", "token"])
        .output()
        .context("no GITHUB_TOKEN/GH_TOKEN set and `gh` is not available")?;
    let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || t.is_empty() {
        bail!(
            "no GITHUB_TOKEN/GH_TOKEN set and `gh auth token` returned nothing; run `gh auth login`"
        );
    }
    Ok(t)
}

#[derive(Deserialize)]
struct SearchPage {
    total_count: u64,
    items: Vec<Repo>,
}

#[derive(Deserialize)]
struct Readme {
    content: String,
}

#[derive(Deserialize)]
struct CommitItem {
    commit: CommitInner,
}

#[derive(Deserialize)]
struct CommitInner {
    message: String,
}

#[derive(Deserialize)]
struct Release {
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
}

fn header<'a>(resp: &'a ureq::http::Response<ureq::Body>, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

fn until_reset(resp: &ureq::http::Response<ureq::Body>) -> Option<Duration> {
    if let Some(secs) = header(resp, "retry-after").and_then(|v| v.parse::<u64>().ok()) {
        return Some(Duration::from_secs(secs));
    }
    if header(resp, "x-ratelimit-remaining") != Some("0") {
        return None;
    }
    let reset = header(resp, "x-ratelimit-reset")?.parse::<u64>().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(reset.saturating_sub(now) + 1))
}

impl GitHub {
    pub fn new(token: String) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            // A truncated recursive tree can be 7 MB.
            .timeout_global(Some(Duration::from_secs(300)))
            .user_agent(concat!("clonewatch/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self {
            agent,
            auth: format!("Bearer {token}"),
            last_search: Cell::new(None),
            requests: Cell::new(0),
        }
    }

    pub fn requests(&self) -> u32 {
        self.requests.get()
    }

    /// GET an api.github.com path. `Ok(None)` means the resource is gone
    /// (404), blocked (451) or an empty repository (409).
    fn get<T: DeserializeOwned>(&self, path: &str, query: &[(&str, &str)]) -> Result<Option<T>> {
        let url = format!("{API}{path}");
        assert!(
            url.starts_with("https://api.github.com/"),
            "refusing non-API URL {url}"
        );
        let mut rate_waited = false;
        let mut transport_retries = 0;
        loop {
            let mut req = self
                .agent
                .get(&url)
                .header("Authorization", &self.auth)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
            for (k, v) in query {
                req = req.query(*k, *v);
            }
            self.requests.set(self.requests.get() + 1);
            // Connection drops on large trees happen; retry those a couple of times.
            let mut resp = match req.call() {
                Ok(r) => r,
                Err(e) if transport_retries < TRANSPORT_RETRIES => {
                    transport_retries += 1;
                    eprintln!("clonewatch: GET {path} failed ({e}), retrying");
                    sleep(RETRY_DELAY);
                    continue;
                }
                Err(e) => return Err(e).with_context(|| format!("GET {path}")),
            };
            let status = resp.status().as_u16();
            match status {
                200..=299 => {
                    let wait = until_reset(&resp);
                    let body: T = match resp
                        .body_mut()
                        .with_config()
                        .limit(16 * 1024 * 1024)
                        .read_json()
                    {
                        Ok(b) => b,
                        Err(ureq::Error::Json(e)) => {
                            return Err(e).with_context(|| format!("decode {path}"));
                        }
                        Err(e) if transport_retries < TRANSPORT_RETRIES => {
                            transport_retries += 1;
                            eprintln!("clonewatch: reading {path} failed ({e}), retrying");
                            sleep(RETRY_DELAY);
                            continue;
                        }
                        Err(e) => return Err(e).with_context(|| format!("read {path}")),
                    };
                    if let Some(w) = wait {
                        self.wait(w, path)?;
                    }
                    return Ok(Some(body));
                }
                404 | 409 | 451 => return Ok(None),
                403 | 429 if !rate_waited => {
                    if let Some(w) = until_reset(&resp) {
                        rate_waited = true;
                        self.wait(w, path)?;
                        continue;
                    }
                }
                _ => {}
            }
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            bail!(
                "GET {path}: HTTP {status}: {}",
                body.chars().take(300).collect::<String>()
            );
        }
    }

    fn wait(&self, d: Duration, path: &str) -> Result<()> {
        if d > MAX_WAIT {
            bail!(
                "rate limit for {path} resets in {}s (> {}s); rerun later",
                d.as_secs(),
                MAX_WAIT.as_secs()
            );
        }
        eprintln!("clonewatch: rate limited, waiting {}s", d.as_secs());
        sleep(d);
        Ok(())
    }

    fn throttle_search(&self) {
        if let Some(last) = self.last_search.get() {
            let elapsed = last.elapsed();
            if elapsed < SEARCH_INTERVAL {
                sleep(SEARCH_INTERVAL - elapsed);
            }
        }
        self.last_search.set(Some(Instant::now()));
    }

    pub fn repo(&self, full_name: &str) -> Result<Option<Repo>> {
        self.get(&format!("/repos/{full_name}"), &[])
    }

    /// Public repos owned by an account; `None` if the account does not exist.
    pub fn owner_repos(&self, owner: &str) -> Result<Option<Vec<Repo>>> {
        let mut all = Vec::new();
        for page in 1.. {
            let p = page.to_string();
            let Some(items) = self.get::<Vec<Repo>>(
                &format!("/users/{owner}/repos"),
                &[("per_page", "100"), ("type", "owner"), ("page", &p)],
            )?
            else {
                return Ok(None);
            };
            let n = items.len();
            all.extend(items);
            if n < 100 {
                break;
            }
        }
        Ok(Some(all))
    }

    /// Repository search, up to `max` results (GitHub caps any query at 1,000).
    pub fn search_repos(&self, q: &str, max: usize) -> Result<Vec<Repo>> {
        let per_page = max.clamp(1, 100);
        let pp = per_page.to_string();
        let mut out = Vec::new();
        for page in 1.. {
            self.throttle_search();
            let p = page.to_string();
            let res: SearchPage = self
                .get(
                    "/search/repositories",
                    &[("q", q), ("per_page", &pp), ("page", &p)],
                )?
                .ok_or_else(|| anyhow!("search returned 404 for {q:?}"))?;
            let n = res.items.len();
            out.extend(res.items);
            if n < per_page || out.len() >= max || out.len() as u64 >= res.total_count.min(1000) {
                break;
            }
        }
        out.truncate(max);
        Ok(out)
    }

    /// Recursive tree of the default branch: paths, modes, blob SHAs, sizes.
    pub fn tree(&self, full_name: &str) -> Result<Option<Tree>> {
        self.get(
            &format!("/repos/{full_name}/git/trees/HEAD"),
            &[("recursive", "1")],
        )
    }

    /// README as text; used only to extract link targets.
    pub fn readme(&self, full_name: &str) -> Result<Option<String>> {
        let Some(r) = self.get::<Readme>(&format!("/repos/{full_name}/readme"), &[])? else {
            return Ok(None);
        };
        let raw: String = r.content.split_whitespace().collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .with_context(|| format!("decode README of {full_name}"))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    pub fn commit_titles(&self, full_name: &str, n: usize) -> Result<Vec<String>> {
        let n = n.to_string();
        let items: Vec<CommitItem> = self
            .get(&format!("/repos/{full_name}/commits"), &[("per_page", &n)])?
            .unwrap_or_default();
        Ok(items
            .into_iter()
            .map(|c| c.commit.message.lines().next().unwrap_or("").to_string())
            .collect())
    }

    /// Names of assets on the most recent releases. Assets are never downloaded.
    pub fn release_asset_names(&self, full_name: &str) -> Result<Vec<String>> {
        let rels: Vec<Release> = self
            .get(
                &format!("/repos/{full_name}/releases"),
                &[("per_page", "10")],
            )?
            .unwrap_or_default();
        Ok(rels
            .into_iter()
            .flat_map(|r| r.assets)
            .map(|a| a.name)
            .collect())
    }

    pub fn user(&self, login: &str) -> Result<Option<User>> {
        self.get(&format!("/users/{login}"), &[])
    }
}
