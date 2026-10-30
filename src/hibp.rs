//! Optional, opt-in check against Have I Been Pwned's Pwned Passwords range API, using
//! k-anonymity: only the first 5 hex characters of a password's SHA-1 hash ever leave this
//! computer. The password, and its full hash, never do. This is the only feature that uses the
//! network, and it is off by default.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use eframe::egui;
use sha1::{Digest, Sha1};

const API: &str = "https://api.pwnedpasswords.com/range/";
const TIMEOUT: Duration = Duration::from_secs(15);

/// Uppercase hex SHA-1 of the password (HIBP uses SHA-1 for Pwned Passwords).
pub fn sha1_hex(pw: &str) -> String {
    Sha1::digest(pw.as_bytes()).iter().map(|b| format!("{b:02X}")).collect()
}

/// Times this suffix (35 hex chars) appears in a range-API body of "SUFFIX:COUNT" lines; 0 if not.
pub fn count_in(body: &str, suffix: &str) -> u32 {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .map_or(0, |(_, c)| c.trim().parse().unwrap_or(1))
}

fn fetch(prefix: &str) -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(TIMEOUT)).build().into();
    let mut res = agent
        .get(format!("{API}{prefix}"))
        .header("Add-Padding", "true") // same-size responses: resists traffic analysis
        .call()
        .map_err(|e| e.to_string())?;
    res.body_mut().read_to_string().map_err(|e| e.to_string())
}

/// A finished check: entries (by the index given to `start`) whose password is known-breached, with
/// the breach count, highest first.
#[derive(Default, Clone)]
pub struct Report {
    pub done: bool,
    pub err: Option<String>,
    pub pwned: Vec<(usize, u32)>,
    pub checked: usize,
}

fn state() -> &'static Mutex<Report> {
    static S: OnceLock<Mutex<Report>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Report::default()))
}

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn report() -> Report {
    state().lock().map(|r| r.clone()).unwrap_or_default()
}

/// Check `items` (index, password) in the background. One request per distinct 5-char prefix, so
/// several passwords sharing a prefix cost a single request. Results via `report()`.
pub fn start(ctx: &egui::Context, items: Vec<(usize, String)>) {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Ok(mut r) = state().lock() {
        *r = Report::default();
    }
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        use std::collections::HashMap;
        let total = items.len();
        // prefix -> [(index, suffix)]
        let mut by_prefix: HashMap<String, Vec<(usize, String)>> = HashMap::new();
        for (i, pw) in &items {
            let h = sha1_hex(pw);
            by_prefix.entry(h[..5].to_owned()).or_default().push((*i, h[5..].to_owned()));
        }
        let mut pwned: Vec<(usize, u32)> = Vec::new();
        let mut err = None;
        for (prefix, group) in by_prefix {
            match fetch(&prefix) {
                Ok(body) => {
                    for (i, suffix) in group {
                        let n = count_in(&body, &suffix);
                        if n > 0 {
                            pwned.push((i, n));
                        }
                    }
                }
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
            ctx.request_repaint();
        }
        pwned.sort_by_key(|e| std::cmp::Reverse(e.1));
        if let Ok(mut r) = state().lock() {
            *r = Report { done: err.is_none(), err, pwned, checked: total };
        }
        RUNNING.store(false, Ordering::SeqCst);
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_and_prefix_are_the_known_values() {
        // "password" -> 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (the canonical HIBP example).
        let h = sha1_hex("password");
        assert_eq!(h, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(&h[..5], "5BAA6", "only this 5-char prefix is ever sent");
    }

    #[test]
    fn count_parsing_is_case_insensitive_and_exact() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\nABCDEF0000000000000000000000000000000:7";
        assert_eq!(count_in(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 12345);
        assert_eq!(count_in(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"), 12345);
        assert_eq!(count_in(body, "0000000000000000000000000000000000000"), 0);
        assert_eq!(count_in("", "ABC"), 0);
    }
}
