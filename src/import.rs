//! CSV import from Chrome/Edge/Firefox, Bitwarden, KeePass and 1Password exports.

use std::collections::HashMap;

use crate::otp;
use crate::vault::{Code, Entry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Bitwarden,
    OnePassword,
    KeePass,
    Browser,
    Generic,
}

pub struct Imported {
    pub entries: Vec<Entry>,
    pub source: Source,
    pub skipped: usize,
}

const SITE: &[&str] = &["name", "title"];
const URL: &[&str] = &["url", "login_uri", "website", "web site", "login uri"];
const USER: &[&str] = &["username", "login_username", "user", "login", "login username"];
const PASS: &[&str] = &["password", "login_password", "login password"];
const NOTES: &[&str] = &["note", "notes"];
const TOTP: &[&str] = &["login_totp", "otpauth", "totp", "one-time password"];
const CATEGORY: &[&str] = &["folder", "group", "grouping"];

fn col(headers: &HashMap<String, usize>, names: &[&str]) -> Option<usize> {
    names.iter().find_map(|n| headers.get(*n).copied())
}

fn host(url: &str) -> String {
    let s = url.trim().split("://").last().unwrap_or("");
    s.split(['/', '?', '#']).next().unwrap_or("").trim_start_matches("www.").to_owned()
}

pub fn parse(data: &[u8]) -> Result<Imported, &'static str> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(data);
    let headers: HashMap<String, usize> = rdr
        .headers()
        .map_err(|_| "Fichier CSV illisible.")?
        .iter()
        .enumerate()
        .map(|(i, h)| (h.trim().trim_start_matches('\u{feff}').to_lowercase(), i))
        .collect();

    let (site_c, url_c, user_c, pass_c) = (col(&headers, SITE), col(&headers, URL), col(&headers, USER), col(&headers, PASS));
    if pass_c.is_none() || (site_c.is_none() && url_c.is_none()) {
        return Err("Colonnes non reconnues : il faut au moins un nom/site et un mot de passe.");
    }
    let (notes_c, totp_c, cat_c) = (col(&headers, NOTES), col(&headers, TOTP), col(&headers, CATEGORY));

    let source = if headers.contains_key("login_uri") && headers.contains_key("login_password") {
        Source::Bitwarden
    } else if headers.contains_key("otpauth") || headers.contains_key("archived") {
        Source::OnePassword
    } else if headers.contains_key("group") || headers.contains_key("title") && headers.contains_key("url") {
        Source::KeePass
    } else if headers.contains_key("name") && headers.contains_key("url") {
        Source::Browser
    } else {
        Source::Generic
    };

    let (mut entries, mut skipped) = (Vec::new(), 0);
    for rec in rdr.records() {
        let Ok(rec) = rec else {
            skipped += 1;
            continue;
        };
        let get = |c: Option<usize>| c.and_then(|i| rec.get(i)).map(str::trim).unwrap_or("").to_owned();
        let (name, url, user, pass) = (get(site_c), get(url_c), get(user_c), get(pass_c));
        let site = if !name.is_empty() { name } else { host(&url) };
        if site.is_empty() || (user.is_empty() && pass.is_empty()) {
            skipped += 1;
            continue;
        }
        let mut e = Entry::blank();
        e.site = site;
        e.username = user;
        e.password = pass;
        e.category = get(cat_c);
        let mut notes = get(notes_c);
        if !url.is_empty() {
            notes = if notes.is_empty() { format!("URL : {url}") } else { format!("URL : {url}\n{notes}") };
        }
        e.notes = notes;
        let totp = get(totp_c);
        if !totp.is_empty() && otp::parse(&totp).is_some() {
            e.codes.push(Code { label: "2FA".into(), note: String::new(), secret: totp, totp: true });
        }
        entries.push(e);
    }
    if entries.is_empty() {
        return Err("Aucune entr\u{e9}e exploitable dans ce fichier.");
    }
    Ok(Imported { entries, source, skipped })
}

/// Best-effort secure delete: overwrite with zeros, flush, remove. (On SSDs the controller may
/// keep old blocks, so the exported CSV should also be kept off synced folders.)
pub fn shred(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut left = std::fs::metadata(path)?.len();
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    let zeros = [0u8; 8192];
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        f.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    f.sync_all()?;
    drop(f);
    std::fs::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shred_removes_file() {
        let p = std::env::temp_dir().join(format!("vylt-shred-{}.csv", std::process::id()));
        std::fs::write(&p, vec![b'x'; 20_000]).unwrap();
        shred(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn chrome_export() {
        let csv = "name,url,username,password,note\nGitHub,https://github.com/login,me,pw1,perso\n,https://www.example.org/x,bob,pw2,\n";
        let r = parse(csv.as_bytes()).unwrap();
        assert_eq!(r.source, Source::Browser);
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0].site, "GitHub");
        assert_eq!(r.entries[0].notes, "URL : https://github.com/login\nperso");
        assert_eq!(r.entries[1].site, "example.org"); // derived from the URL
    }

    #[test]
    fn bitwarden_export_with_totp_and_folder() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,Jira,,,0,https://jira.example,al,secret,JBSWY3DPEHPK3PXP\n\
                   ,0,login,Bad,,,0,,,,not-base32!!\n";
        let r = parse(csv.as_bytes()).unwrap();
        assert_eq!(r.source, Source::Bitwarden);
        assert_eq!(r.entries.len(), 1); // second row has no user/password
        assert_eq!(r.skipped, 1);
        let e = &r.entries[0];
        assert_eq!((e.category.as_str(), e.username.as_str()), ("Work", "al"));
        assert_eq!(e.codes.len(), 1);
        assert!(e.codes[0].totp);
    }

    #[test]
    fn keepass_with_bom_and_quotes() {
        let csv = "\u{feff}\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\"Root\",\"Bank, Inc\",\"u\",\"p\",\"\",\"n\"\n";
        let r = parse(csv.as_bytes()).unwrap();
        assert_eq!(r.source, Source::KeePass);
        assert_eq!(r.entries[0].site, "Bank, Inc");
        assert_eq!(r.entries[0].category, "Root");
    }

    #[test]
    fn rejects_unknown_files() {
        assert!(parse(b"a,b,c\n1,2,3\n").is_err());
        assert!(parse(b"").is_err());
        assert!(parse(b"name,url,username,password\n").is_err()); // header only
    }
}
