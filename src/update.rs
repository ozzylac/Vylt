//! Optional check for a newer release, against the project's public GitHub Releases. Manual only
//! (a button in Settings): nothing is ever downloaded or installed on its own, and no check runs
//! without the user asking. Only the installed version number is compared — no personal data is
//! sent. Like the breach check, this is one of the few features that touch the network.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use eframe::egui;

use crate::errcode;
use crate::i18n::tr;

const API: &str = "https://api.github.com/repos/ozzylac/Vylt/releases/latest";
const TIMEOUT: Duration = Duration::from_secs(15);

/// The version built into this binary.
pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// (major, minor, patch) from "1.2.3" or "v1.2.3"; None when it does not look like a version.
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let mut it = s.split('.');
    let a = it.next()?.trim().parse().ok()?;
    let b = it.next().map_or(Ok(0), |p| p.trim().parse()).ok()?;
    let c = it.next().map_or(Ok(0), |p| p.trim().parse()).ok()?;
    Some((a, b, c))
}

/// True only when both parse and `latest` is strictly greater.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

#[derive(Clone)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub notes: String,
}

/// Pull the tag, release-page URL and notes out of GitHub's "latest release" JSON.
pub fn parse_release(body: &str) -> Option<Release> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(Release {
        version: v.get("tag_name")?.as_str()?.to_owned(),
        url: v.get("html_url").and_then(|x| x.as_str()).unwrap_or_default().to_owned(),
        notes: v.get("body").and_then(|x| x.as_str()).unwrap_or_default().to_owned(),
    })
}

#[derive(Clone, Default)]
pub enum Status {
    #[default]
    Idle,
    UpToDate,
    Newer(Release),
    Error(String),
}

fn state() -> &'static Mutex<Status> {
    static S: OnceLock<Mutex<Status>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Status::Idle))
}

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn status() -> Status {
    state().lock().map(|s| s.clone()).unwrap_or_default()
}

fn fetch() -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(TIMEOUT)).build().into();
    let mut res = agent
        .get(API)
        .header("User-Agent", "Vylt") // GitHub rejects requests without a User-Agent
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?;
    res.body_mut().read_to_string().map_err(|e| e.to_string())
}

/// Ask GitHub for the latest release, in the background. Result via `status()`.
pub fn check(ctx: &egui::Context) {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let next = match fetch().ok().and_then(|b| parse_release(&b)) {
            Some(r) if is_newer(&r.version, current()) => Status::Newer(r),
            Some(_) => Status::UpToDate,
            None => Status::Error(errcode::tag(tr("Impossible de vérifier les mises à jour."), "SV-E80")),
        };
        if let Ok(mut s) = state().lock() {
            *s = next;
        }
        RUNNING.store(false, Ordering::SeqCst);
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_tolerates_v_prefix_and_missing_parts() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("2"), Some((2, 0, 0)));
        assert_eq!(parse_version("nightly"), None);
    }

    #[test]
    fn newer_is_strict_and_safe_on_garbage() {
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("???", "0.1.0"), "unparseable never counts as newer");
    }

    #[test]
    fn release_is_read_from_the_github_json() {
        let body = r#"{"tag_name":"v0.2.0","html_url":"https://example/r/0.2.0","body":"- fix"}"#;
        let r = parse_release(body).unwrap();
        assert_eq!(r.version, "v0.2.0");
        assert_eq!(r.url, "https://example/r/0.2.0");
        assert_eq!(r.notes, "- fix");
        assert!(parse_release("not json").is_none());
    }
}
