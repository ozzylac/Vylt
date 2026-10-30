//! App-wide config (profiles list, language, theme). Holds no secrets.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use vylt::destroy::{self, Pending, SealedActions, Targets, Verifier};
use vylt::vault::{SecretKey, VaultError};
use serde::{Deserialize, Serialize};

use crate::i18n::Lang;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Profile {
    pub name: String,
    pub vault_path: PathBuf,
    pub key_path: PathBuf,
    /// False: no secret-key file; protection rests on the master password alone.
    #[serde(default = "yes")]
    pub use_key: bool,
    /// Typed at sign-in instead of the master password: erases this profile.
    #[serde(default)]
    pub destruct: Option<Verifier>,
    /// What to do after `destruct` erased the profile, sealed with the destruction password.
    #[serde(default)]
    pub actions: Option<SealedActions>,
    /// Profile picture (plain PNG next to the config: it is shown before unlock).
    #[serde(default)]
    pub avatar: Option<PathBuf>,
    /// Index into `theme::AVATAR_COLORS`, used when there is no picture.
    #[serde(default)]
    pub color: u8,
    /// Verifier of this profile's link identifier (the identifier itself is in the vault).
    #[serde(default)]
    pub link_check: Option<Verifier>,
    /// Profiles (by `pid`) whose identifier this profile typed: a link exists when both did.
    #[serde(default)]
    pub links: Vec<String>,
}

fn yes() -> bool {
    true
}

impl Profile {
    pub fn secret_key(&self) -> Result<SecretKey, VaultError> {
        if self.use_key { SecretKey::load(&self.key_file()) } else { Ok(SecretKey::empty()) }
    }

    /// The key file, looked up on every USB drive when its drive letter changed since last time.
    pub fn key_file(&self) -> PathBuf {
        if self.key_path.exists() || drive_of(&self.key_path).is_none() {
            return self.key_path.clone();
        }
        let rest = self.key_path.to_string_lossy()[1..].to_owned();
        crate::platform::removable_drives()
            .into_iter()
            .map(|l| PathBuf::from(format!("{l}{rest}")))
            .find(|p| p.exists())
            .unwrap_or_else(|| self.key_path.clone())
    }
}

/// Uppercase drive letter of an absolute `X:\…` path.
pub fn drive_of(p: &Path) -> Option<char> {
    let mut c = p.to_str()?.chars();
    let l = c.next()?;
    (l.is_ascii_alphabetic() && c.next()? == ':').then(|| l.to_ascii_uppercase())
}

pub const PORTABLE_FLAG: &str = "portable.flag";

/// Folder of a portable install (`portable.flag` next to the executable), if this is one.
pub fn portable_root() -> Option<&'static Path> {
    static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
        dir.join(PORTABLE_FLAG).exists().then_some(dir)
    })
    .as_deref()
}

pub fn portable_drive() -> Option<char> {
    portable_root().and_then(drive_of)
}

/// Data folder of an installed (fixed) Vylt on this PC.
pub fn installed_dir() -> PathBuf {
    std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join("Vylt")
}

/// Portable profiles whose secret key stays on the PC keep it here.
pub fn pc_keys_dir() -> PathBuf {
    installed_dir().join("keys")
}

/// Data folder name used before the app was renamed to Vylt; its contents are migrated once.
const LEGACY_APPDATA_DIR: &str = "SecureVault";

/// One-time move of the pre-rename data folder (`%APPDATA%\SecureVault`) to `%APPDATA%\Vylt`.
/// No effect in portable mode, or once the Vylt folder already exists. Best effort: on any
/// failure the original is left untouched, so data is never lost.
pub fn migrate_legacy_appdata() {
    if portable_root().is_some() {
        return;
    }
    if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
        migrate_appdata_in(&appdata);
    }
}

fn migrate_appdata_in(appdata: &Path) {
    let (old, new) = (appdata.join(LEGACY_APPDATA_DIR), appdata.join("Vylt"));
    if new.exists() || !old.exists() {
        return;
    }
    // Same volume (the usual case): an atomic rename. Otherwise a recursive copy that leaves the
    // original in place as a safety net.
    if std::fs::rename(&old, &new).is_err() {
        let _ = copy_dir_all(&old, &new);
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let (from, to) = (e.path(), dst.join(e.file_name()));
        if e.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub last: usize,
    #[serde(default)]
    pub lang: Lang,
    #[serde(default = "yes")]
    pub dark: bool,
    /// Index into `theme::ACCENTS`.
    #[serde(default)]
    pub accent: u8,
    /// Typed at sign-in: erases every profile. Active only once two different profiles set it.
    #[serde(default)]
    pub global_destruct: Option<Verifier>,
    #[serde(default)]
    pub global_pending: Option<Pending>,
    /// The two linked profiles (by `pid`) that armed the global erase; it erases their group.
    #[serde(default)]
    pub global_members: Vec<String>,
    /// The browser extension's native host is registered (re-registered at start: the exe may move).
    #[serde(default)]
    pub extension: bool,
    /// Failed sign-ins per profile folder: a growing delay survives restarts.
    #[serde(default)]
    pub attempts: std::collections::BTreeMap<String, Attempts>,
    // Single-vault layout of the first version, migrated to a profile on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            last: 0,
            lang: Lang::default(),
            dark: true,
            accent: 0,
            global_destruct: None,
            global_pending: None,
            global_members: Vec::new(),
            extension: false,
            attempts: Default::default(),
            vault_path: None,
            key_path: None,
        }
    }
}

pub fn data_dir() -> PathBuf {
    match portable_root() {
        Some(r) => r.join("data"),
        None => installed_dir(),
    }
}

const TAG_DATA: &str = "{data}";
const TAG_APPDATA: &str = "{appdata}";

/// A portable config stores paths under its own folder, or under this PC's %APPDATA%, as tags:
/// it keeps working when the drive letter or the Windows user changes.
fn contract(p: &str, dir: &Path) -> String {
    for (tag, base) in [(TAG_DATA, dir.to_path_buf()), (TAG_APPDATA, installed_dir())] {
        let b = base.to_string_lossy();
        if p.get(..b.len()).is_some_and(|h| h.eq_ignore_ascii_case(&b)) && p[b.len()..].starts_with('\\') {
            return format!("{tag}{}", &p[b.len()..]);
        }
    }
    p.to_owned()
}

/// Tagged paths may not climb out of their folder (`{data}\..\…`).
fn expand(p: &str, dir: &Path) -> String {
    if p.starts_with('{') && p.split(['\\', '/']).any(|c| c == "..") {
        return String::new();
    }
    if let Some(rest) = p.strip_prefix(TAG_DATA) {
        format!("{}{rest}", dir.display())
    } else if let Some(rest) = p.strip_prefix(TAG_APPDATA) {
        format!("{}{rest}", installed_dir().display())
    } else {
        p.to_owned()
    }
}

fn map_paths(v: &mut serde_json::Value, f: impl Fn(&str) -> String) {
    let Some(ps) = v.get_mut("profiles").and_then(|p| p.as_array_mut()) else { return };
    for p in ps {
        for k in ["vault_path", "key_path", "avatar"] {
            if let Some(serde_json::Value::String(s)) = p.get_mut(k) {
                *s = f(s);
            }
        }
    }
}

/// The config lives in a discreet, hidden file whose bytes are obfuscated: no readable profile
/// names or feature keywords (e.g. "destruct") appear on disk. This is camouflage, not encryption
/// (the source is public), but it defeats casual inspection and keyword scanning (cloud backups).
const CONFIG_NAME: &str = "vault.db";
const LEGACY_NAME: &str = "config.json";
const OBF_MAGIC: &[u8] = b"SVC1";

pub(crate) fn cfg_file(dir: &Path) -> PathBuf {
    dir.join(CONFIG_NAME)
}

fn block_ks(block: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"securevault config obfuscation v1");
    h.update(block.to_le_bytes());
    h.finalize().into()
}

fn xor_stream(data: &[u8], out: &mut Vec<u8>) {
    for (bi, chunk) in data.chunks(32).enumerate() {
        let ks = block_ks(bi as u64);
        for (j, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[j]);
        }
    }
}

fn obfuscate(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plain.len() + OBF_MAGIC.len());
    out.extend_from_slice(OBF_MAGIC);
    xor_stream(plain, &mut out);
    out
}

/// Reverse of `obfuscate`; a buffer without the magic is a legacy plaintext config, returned as is.
pub(crate) fn deobfuscate(stored: &[u8]) -> Vec<u8> {
    match stored.strip_prefix(OBF_MAGIC) {
        Some(body) => {
            let mut out = Vec::with_capacity(body.len());
            xor_stream(body, &mut out);
            out
        }
        None => stored.to_vec(),
    }
}

pub fn load_from(dir: &Path) -> Option<Config> {
    read_config(&cfg_file(dir), dir).map(|(c, _)| c)
}

/// Lenient read: a field with an invalid value falls back to its default, and a profile that
/// cannot be read is set aside (counted) instead of making the whole file unreadable.
fn read_config(path: &Path, dir: &Path) -> Option<(Config, usize)> {
    let mut v: serde_json::Value = serde_json::from_slice(&deobfuscate(&std::fs::read(path).ok()?)).ok()?;
    map_paths(&mut v, |s| expand(s, dir));
    let obj = v.as_object_mut()?;
    let mut skipped = 0;
    if let Some(ps) = obj.get_mut("profiles").and_then(|p| p.as_array_mut()) {
        let before = ps.len();
        ps.retain(|p| serde_json::from_value::<Profile>(p.clone()).is_ok_and(|p| !p.vault_path.as_os_str().is_empty()));
        skipped = before - ps.len();
    }
    fn fits<T: serde::de::DeserializeOwned>(x: &serde_json::Value) -> bool {
        serde_json::from_value::<T>(x.clone()).is_ok()
    }
    let bad: Vec<String> = obj
        .iter()
        .filter(|(k, x)| match k.as_str() {
            "last" => !fits::<usize>(x),
            "lang" => !fits::<Lang>(x),
            "dark" | "extension" => !fits::<bool>(x),
            "accent" => !fits::<u8>(x),
            "global_destruct" => !fits::<Option<Verifier>>(x),
            "global_pending" => !fits::<Option<Pending>>(x),
            "global_members" => !fits::<Vec<String>>(x),
            "vault_path" | "key_path" => !fits::<Option<PathBuf>>(x),
            "profiles" => !x.is_array(),
            "attempts" => !fits::<std::collections::BTreeMap<String, Attempts>>(x),
            _ => false,
        })
        .map(|(k, _)| k.clone())
        .collect();
    for k in bad {
        obj.remove(&k);
    }
    serde_json::from_value(v).ok().map(|c| (c, skipped))
}

/// What happened while reading config.json, told to the user once the app is up.
pub enum LoadNote {
    /// The file was unreadable; the previous copy (config.json.bak) was used.
    Restored { kept: PathBuf },
    /// Unreadable and no usable copy: the app starts empty, the file is kept aside.
    Unreadable { kept: PathBuf },
    /// Some profiles could not be read; they are kept in the set-aside copy.
    Skipped { n: usize, kept: PathBuf },
}

static NOTE: std::sync::Mutex<Option<LoadNote>> = std::sync::Mutex::new(None);

pub fn take_load_note() -> Option<LoadNote> {
    NOTE.lock().ok()?.take()
}

/// Keep a damaged config.json next to it (config.json.broken-<time>) before anything rewrites it.
fn set_aside(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let kept = path.with_file_name(format!("{name}.broken-{}", now_secs()));
    let _ = std::fs::copy(path, &kept);
    kept
}

/// First start: the language chosen in the installer (`install.lang` next to the executable).
fn first_run() -> Config {
    let lang = std::env::current_exe()
        .ok()
        .and_then(|e| std::fs::read_to_string(e.with_file_name("install.lang")).ok())
        .and_then(|l| match l.trim() {
            "fr" => Some(Lang::Fr),
            "en" => Some(Lang::En),
            "es" => Some(Lang::Es),
            _ => None,
        });
    Config { lang: lang.unwrap_or_default(), ..Config::default() }
}

pub fn load() -> Config {
    let dir = data_dir();
    let (path, bak) = (cfg_file(&dir), cfg_file(&dir).with_file_name(format!("{CONFIG_NAME}.bak")));
    // One-time migration from the old plaintext config.json to the hidden, obfuscated file.
    let legacy = dir.join(LEGACY_NAME);
    if !path.exists() && !bak.exists() && legacy.exists() && let Some((c, _)) = read_config(&legacy, &dir) {
        save_to(&c, &dir);
        let _ = vylt::import::shred(&legacy);
        let _ = vylt::import::shred(&dir.join(format!("{LEGACY_NAME}.bak")));
    }
    let note = |n: LoadNote| {
        if let Ok(mut g) = NOTE.lock() {
            *g = Some(n);
        }
    };
    let mut c = if !path.exists() && !bak.exists() {
        first_run()
    } else {
        match read_config(&path, &dir) {
            Some((c, 0)) => c,
            Some((c, n)) => {
                note(LoadNote::Skipped { n, kept: set_aside(&path) });
                c
            }
            None => {
                let kept = if path.exists() { set_aside(&path) } else { bak.clone() };
                match read_config(&bak, &dir) {
                    Some((c, _)) => {
                        note(LoadNote::Restored { kept });
                        c
                    }
                    None => {
                        note(LoadNote::Unreadable { kept });
                        first_run()
                    }
                }
            }
        }
    };
    if let (Some(v), Some(k)) = (c.vault_path.take(), c.key_path.take())
        && v.exists()
        && c.profiles.is_empty()
    {
        c.profiles.push(Profile { name: "Principal".into(), vault_path: v, key_path: k, use_key: true, ..Default::default() });
    }
    c.last = c.last.min(c.profiles.len().saturating_sub(1));
    c
}

pub fn save(c: &Config) {
    save_to(c, &data_dir());
}

/// The installed config keeps plain absolute paths (readable by earlier versions).
pub fn save_to(c: &Config, dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let Ok(mut v) = serde_json::to_value(c) else { return };
    if dir != installed_dir() {
        map_paths(&mut v, |s| contract(s, dir));
    }
    let Ok(b) = serde_json::to_vec_pretty(&v) else { return };
    let _ = write_durably(&cfg_file(dir), &b);
}

/// Write to a fresh temporary file, flush it to the disk, keep the previous version as `.bak`
/// when it was readable, then swap the new file in: a crash never leaves a half-written file.
fn write_durably(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut rnd = [0u8; 6];
    let _ = getrandom::fill(&mut rnd);
    let tag: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = path.with_file_name(format!("{}.{tag}.tmp", path.file_name().unwrap_or_default().to_string_lossy()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&obfuscate(data))?;
        f.sync_all()?;
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    if std::fs::read(path).is_ok_and(|b| serde_json::from_slice::<serde_json::Value>(&deobfuscate(&b)).is_ok()) {
        let bak = path.with_file_name(format!("{name}.bak"));
        let _ = std::fs::copy(path, &bak);
        crate::platform::hide_file(&bak);
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    crate::platform::hide_file(path);
    Ok(())
}

/// Irreversibly erase one profile's files (vault, decoy vault, secret key).
pub fn wipe_profile(p: &Profile) {
    destroy::wipe_profile(&Targets { vault: &p.vault_path, key: p.use_key.then_some(p.key_path.as_path()) });
    remove_avatar(p);
}

/// Only a picture Vylt itself stored (a PNG directly in `avatars\`) is ever shredded.
pub fn remove_avatar(p: &Profile) {
    let Some(a) = &p.avatar else { return };
    let dir = data_dir().join("avatars");
    let own = a.parent().is_some_and(|d| crate::portable::same(d, &dir))
        && a.extension().is_some_and(|x| x.eq_ignore_ascii_case("png"))
        && std::fs::read(a).is_ok_and(|b| b.starts_with(b"\x89PNG"));
    if own {
        let _ = vylt::import::shred(a);
    }
}

/// Center-crop `src` to a square, scale it to 128 px and store it as PNG under `avatars/`.
pub fn save_avatar(src: &Path, name: &str) -> Result<PathBuf, String> {
    let img = image::open(src).map_err(|e| e.to_string())?;
    let side = img.width().min(img.height());
    if side == 0 {
        return Err("empty image".into());
    }
    let square = img.crop_imm((img.width() - side) / 2, (img.height() - side) / 2, side, side).thumbnail_exact(128, 128);
    let dir = data_dir().join("avatars");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut rnd = [0u8; 6];
    getrandom::fill(&mut rnd).map_err(|e| e.to_string())?;
    let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let out = dir.join(format!("{}-{hex}.png", folder_name(name)));
    square.save_with_format(&out, image::ImageFormat::Png).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Stable identifier of a profile: its folder (unchanged when the profile is renamed).
pub fn pid(p: &Profile) -> String {
    p.vault_path.parent().and_then(|d| d.file_name()).map(|f| f.to_string_lossy().to_lowercase()).unwrap_or_else(|| folder_name(&p.name))
}

/// Normalised link identifier: letters and digits only, upper case ("sv-7k3q…" == "SV7K3Q…").
pub fn link_code(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_uppercase()
}

/// A fresh identifier, shown as SV-XXXX-XXXX-XXXX (60 random bits, no look-alike characters).
pub fn new_link_id() -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut b = [0u8; 12];
    let _ = getrandom::fill(&mut b);
    let c: String = b.iter().map(|x| ALPHABET[(*x & 31) as usize] as char).collect();
    format!("SV-{}-{}-{}", &c[..4], &c[4..8], &c[8..])
}

/// Both profiles typed each other's identifier.
pub fn linked(cfg: &Config, a: &str, b: &str) -> bool {
    let has = |x: &str, y: &str| cfg.profiles.iter().find(|p| pid(p) == x).is_some_and(|p| p.links.iter().any(|l| l == y));
    a != b && has(a, b) && has(b, a)
}

/// `start` and every profile reachable from it through mutual links.
pub fn group(cfg: &Config, start: &str) -> Vec<String> {
    let mut seen = vec![start.to_owned()];
    let mut i = 0;
    while i < seen.len() {
        let cur = seen[i].clone();
        for p in &cfg.profiles {
            let id = pid(p);
            if !seen.contains(&id) && linked(cfg, &cur, &id) {
                seen.push(id);
            }
        }
        i += 1;
    }
    seen
}

/// The global erase key was typed: erase the linked group that armed it, nothing else. An erase
/// armed before linked profiles existed (no members) is simply disarmed.
pub fn wipe_global(cfg: &mut Config) {
    wipe_global_in(cfg, &data_dir());
}

fn wipe_global_in(cfg: &mut Config, data: &Path) {
    let mut doomed: Vec<String> = Vec::new();
    for m in cfg.global_members.clone() {
        for id in group(cfg, &m) {
            if !doomed.contains(&id) {
                doomed.push(id);
            }
        }
    }
    let (gone, kept): (Vec<Profile>, Vec<Profile>) = cfg.profiles.drain(..).partition(|p| doomed.contains(&pid(p)));
    for p in &gone {
        wipe_profile(p);
    }
    cfg.profiles = kept;
    for p in &mut cfg.profiles {
        p.links.retain(|l| !doomed.contains(l));
    }
    cfg.last = 0;
    cfg.global_destruct = None;
    cfg.global_pending = None;
    cfg.global_members.clear();
    save_to(cfg, data);
}

#[derive(Debug, PartialEq, Eq)]
pub enum Erase {
    /// The shared global key was typed: erase every profile.
    All,
    /// The selected profile's own destruction password was typed.
    Profile,
    None,
}

/// What typing `typed` at sign-in on profile `sel` does. The global key always wins; a profile's
/// destruction password only counts for that profile.
pub fn erase_decision(cfg: &Config, sel: usize, typed: &str) -> Erase {
    if cfg.global_destruct.as_ref().is_some_and(|v| v.check(typed)) {
        return Erase::All;
    }
    if cfg.profiles.get(sel).and_then(|p| p.destruct.as_ref()).is_some_and(|v| v.check(typed)) {
        return Erase::Profile;
    }
    Erase::None
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct Attempts {
    pub fails: u32,
    pub retry_at: u64,
}

const FREE_TRIES: u32 = 3;
const MAX_DELAY_SECS: u64 = 15 * 60;

/// Seconds to wait before profile `name` may try to sign in again.
pub fn wait_secs(cfg: &Config, name: &str) -> u64 {
    cfg.attempts.get(&folder_name(name)).map_or(0, |a| a.retry_at.saturating_sub(now_secs()))
}

/// A wrong master password or 2FA code: after 3 in a row, 30 s, then doubling up to 15 min.
pub fn note_failure(cfg: &mut Config, name: &str) {
    note_failure_in(cfg, name, &data_dir());
}

fn note_failure_in(cfg: &mut Config, name: &str, dir: &Path) {
    let a = cfg.attempts.entry(folder_name(name)).or_default();
    a.fails = a.fails.saturating_add(1);
    if a.fails >= FREE_TRIES {
        let delay = (30u64 << (a.fails - FREE_TRIES).min(10)).min(MAX_DELAY_SECS);
        a.retry_at = now_secs() + delay;
    }
    save_to(cfg, dir);
}

pub fn note_success(cfg: &mut Config, name: &str) {
    if cfg.attempts.remove(&folder_name(name)).is_some() {
        save(cfg);
    }
}

/// `pw` is this profile's destruction password or the global erase key: such a secret must never
/// also be a password that opens a vault.
pub fn is_erase_secret(cfg: &Config, profile: &str, pw: &str) -> bool {
    cfg.global_destruct.as_ref().is_some_and(|v| v.check(pw))
        || cfg.profiles.iter().find(|p| p.name == profile).and_then(|p| p.destruct.as_ref()).is_some_and(|v| v.check(pw))
}

#[derive(Debug, PartialEq)]
pub enum NameIssue {
    Empty,
    TooLong,
    /// CON, NUL, COM1… cannot be folder names on Windows.
    Reserved,
}

pub fn name_issue(name: &str) -> Option<NameIssue> {
    let n = name.trim();
    if n.is_empty() {
        return Some(NameIssue::Empty);
    }
    if n.chars().count() > 64 {
        return Some(NameIssue::TooLong);
    }
    let folder = folder_name(n).to_ascii_uppercase();
    let stem = folder.split(['.', '_']).next().unwrap_or("");
    let reserved = matches!(stem, "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.as_bytes()[3].is_ascii_digit());
    reserved.then_some(NameIssue::Reserved)
}

pub fn folder_name(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect::<String>().to_lowercase()
}

pub fn profile_dir(name: &str) -> PathBuf {
    data_dir().join("profiles").join(folder_name(name))
}

/// Portable: on the PC, never on the USB drive that holds the vault.
pub fn default_key_path(name: &str) -> PathBuf {
    match portable_root() {
        Some(_) => pc_keys_dir().join(format!("{}.key", folder_name(name))),
        None => profile_dir(name).join("secret.key"),
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)] // tests build fixtures field by field for readability
mod tests {
    use super::*;

    const GLOBAL: &str = "Alpha2026Bravo77";
    const OWN: &str = "own-destruct-password";

    fn profile(dir: &Path, name: &str, destruct: Option<&str>) -> Profile {
        let pdir = dir.join("profiles").join(name);
        std::fs::create_dir_all(&pdir).unwrap();
        let p = Profile {
            name: name.into(),
            vault_path: pdir.join("vault.svault"),
            key_path: pdir.join("secret.key"),
            use_key: true,
            destruct: destruct.map(|d| Verifier::new(d).unwrap()),
            actions: None,
            avatar: None,
            color: 0,
            ..Default::default()
        };
        std::fs::write(&p.vault_path, [b"SVLT\x01".as_slice(), &[1u8; 300]].concat()).unwrap();
        std::fs::write(&p.key_path, [2u8; 32]).unwrap();
        p
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vylt-cfg-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn legacy_appdata_folder_is_moved_to_vylt() {
        let base = tmp("migrate");
        let old = base.join(LEGACY_APPDATA_DIR);
        std::fs::create_dir_all(old.join("profiles").join("alice")).unwrap();
        std::fs::write(old.join("vault.db"), b"cfg").unwrap();
        std::fs::write(old.join("profiles").join("alice").join("vault.svault"), b"v").unwrap();

        migrate_appdata_in(&base);

        let new = base.join("Vylt");
        assert_eq!(std::fs::read(new.join("vault.db")).unwrap(), b"cfg");
        assert!(new.join("profiles").join("alice").join("vault.svault").exists());
        assert!(!old.exists(), "same-volume rename moves the folder, nothing left behind");

        // Idempotent: nothing to do once Vylt exists, and no panic when the old folder is gone.
        migrate_appdata_in(&base);
        assert!(new.join("vault.db").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn erase_decision_priorities_and_exactness() {
        let d = tmp("decide");
        let mut cfg = Config::default();
        cfg.profiles = vec![profile(&d, "alice", Some(OWN)), profile(&d, "bob", None)];
        cfg.global_destruct = Some(Verifier::new(GLOBAL).unwrap());

        assert_eq!(erase_decision(&cfg, 0, GLOBAL), Erase::All);
        assert_eq!(erase_decision(&cfg, 1, GLOBAL), Erase::All, "any profile can trigger it");
        assert_eq!(erase_decision(&cfg, 0, OWN), Erase::Profile);
        assert_eq!(erase_decision(&cfg, 1, OWN), Erase::None, "another profile's password does nothing");
        assert_eq!(erase_decision(&cfg, 0, "alice-master-password"), Erase::None);
        assert_eq!(erase_decision(&cfg, 0, ""), Erase::None);
        assert_eq!(erase_decision(&cfg, 0, "Alpha2026Bravo78"), Erase::None, "a typo does not erase");

        // Not armed yet: the global key means nothing.
        cfg.global_destruct = None;
        assert_eq!(erase_decision(&cfg, 0, GLOBAL), Erase::None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn global_erase_only_reaches_mutually_linked_profiles() {
        let d = tmp("linked");
        let mut cfg = Config::default();
        cfg.profiles = vec![profile(&d, "owner", None), profile(&d, "partner", None), profile(&d, "junk1", None), profile(&d, "junk2", None)];
        let link = |cfg: &mut Config, a: usize, b: &str| cfg.profiles[a].links.push(b.into());
        // owner <-> partner (both typed), junk1 <-> junk2, junk1 -> owner (one side only)
        link(&mut cfg, 0, "partner");
        link(&mut cfg, 1, "owner");
        link(&mut cfg, 2, "junk2");
        link(&mut cfg, 3, "junk1");
        link(&mut cfg, 2, "owner");
        assert!(linked(&cfg, "owner", "partner") && !linked(&cfg, "junk1", "owner"));
        assert_eq!(group(&cfg, "owner"), vec!["owner", "partner"]);

        // Two throwaway profiles arm the key: only they are erased, never the owner's profile.
        cfg.global_destruct = Some(Verifier::new(GLOBAL).unwrap());
        cfg.global_members = vec!["junk1".into(), "junk2".into()];
        let owner_vault = cfg.profiles[0].vault_path.clone();
        wipe_global_in(&mut cfg, &d);
        assert!(owner_vault.exists(), "the owner's vault survives");
        assert_eq!(cfg.profiles.iter().map(pid).collect::<Vec<_>>(), vec!["owner", "partner"]);
        assert!(cfg.global_destruct.is_none() && cfg.global_members.is_empty());

        // Armed by the real pair: both go.
        cfg.global_destruct = Some(Verifier::new(GLOBAL).unwrap());
        cfg.global_members = vec!["owner".into(), "partner".into()];
        wipe_global_in(&mut cfg, &d);
        assert!(cfg.profiles.is_empty() && !owner_vault.exists());

        // An erase armed by the old, unlinked rule wipes nothing.
        let mut old = Config::default();
        old.profiles = vec![profile(&d, "solo", None)];
        old.global_destruct = Some(Verifier::new(GLOBAL).unwrap());
        wipe_global_in(&mut old, &d);
        assert_eq!(old.profiles.len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn link_identifiers() {
        let id = new_link_id();
        assert_eq!(id.len(), 17);
        assert!(id.starts_with("SV-"));
        assert_eq!(link_code(&id.to_lowercase().replace('-', " ")), link_code(&id));
        assert_ne!(new_link_id(), new_link_id());
    }

    #[test]
    fn wipe_profile_leaves_the_other_profiles_alone() {
        let d = tmp("wipeone");
        let (a, b) = (profile(&d, "alice", None), profile(&d, "bob", None));
        wipe_profile(&a);
        assert!(!a.vault_path.exists() && !a.key_path.exists());
        assert!(b.vault_path.exists() && b.key_path.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn one_bad_field_or_profile_does_not_reset_the_config() {
        let d = tmp("lenient");
        let good = profile(&d, "alice", Some(OWN));
        let mut cfg = Config::default();
        cfg.profiles.push(good);
        cfg.global_destruct = Some(Verifier::new(GLOBAL).unwrap());
        save_to(&cfg, &d);
        let mut v: serde_json::Value = serde_json::from_slice(&deobfuscate(&std::fs::read(cfg_file(&d)).unwrap())).unwrap();
        v["lang"] = "Klingon".into();
        v["accent"] = "red".into();
        v["profiles"].as_array_mut().unwrap().push(serde_json::json!({ "name": 3 }));
        std::fs::write(cfg_file(&d), obfuscate(&serde_json::to_vec(&v).unwrap())).unwrap();

        let (c, skipped) = read_config(&cfg_file(&d), &d).unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(c.profiles.len(), 1);
        assert!(c.profiles[0].destruct.is_some() && c.global_destruct.is_some(), "protections survive");
        assert!(c.lang == Lang::default() && c.accent == 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn saving_keeps_the_previous_version_and_no_temp_file() {
        let d = tmp("durable");
        let mut cfg = Config::default();
        cfg.accent = 1;
        save_to(&cfg, &d);
        cfg.accent = 2;
        save_to(&cfg, &d);
        let bak: Config = serde_json::from_slice(&deobfuscate(&std::fs::read(d.join("vault.db.bak")).unwrap())).unwrap();
        assert_eq!(bak.accent, 1);
        assert_eq!(load_from(&d).unwrap().accent, 2);
        assert!(std::fs::read_dir(&d).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tagged_paths_cannot_climb_out() {
        let d = Path::new(r"C:\sv\data");
        assert_eq!(expand(r"{data}\..\victim\report.docx", d), "");
        assert_eq!(expand(r"{data}\profiles\a\vault.svault", d), r"C:\sv\data\profiles\a\vault.svault");
    }

    #[test]
    fn failed_sign_ins_add_a_growing_capped_delay() {
        let d = tmp("attempts");
        let mut cfg = Config::default();
        let tries = |cfg: &mut Config, n: usize| (0..n).for_each(|_| note_failure_in(cfg, "Alice", &d));
        tries(&mut cfg, 2);
        assert_eq!(wait_secs(&cfg, "Alice"), 0, "two mistakes are free");
        tries(&mut cfg, 1);
        assert!((29..=30).contains(&wait_secs(&cfg, "alice")), "same folder, any case");
        tries(&mut cfg, 1);
        assert!((59..=60).contains(&wait_secs(&cfg, "Alice")));
        tries(&mut cfg, 20);
        assert!(wait_secs(&cfg, "Alice") <= MAX_DELAY_SECS);
        assert_eq!(wait_secs(&cfg, "Bob"), 0, "other profiles are not affected");
        cfg.attempts.remove("alice");
        assert_eq!(wait_secs(&cfg, "Alice"), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn erase_secrets_are_recognised() {
        let d = tmp("erase-secret");
        let mut cfg = Config::default();
        cfg.profiles = vec![profile(&d, "alice", Some(OWN))];
        cfg.global_destruct = Some(Verifier::new(GLOBAL).unwrap());
        assert!(is_erase_secret(&cfg, "alice", OWN));
        assert!(is_erase_secret(&cfg, "alice", GLOBAL));
        assert!(!is_erase_secret(&cfg, "alice", "a-new-master-password"));
        assert!(!is_erase_secret(&cfg, "bob", OWN), "another profile's password is not this one's");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn profile_names() {
        assert_eq!(name_issue("  "), Some(NameIssue::Empty));
        assert_eq!(name_issue(&"a".repeat(65)), Some(NameIssue::TooLong));
        for n in ["nul", "NUL", "con", "Aux.txt", "com1", "LPT9", "prn"] {
            assert_eq!(name_issue(n), Some(NameIssue::Reserved), "{n}");
        }
        for n in ["ozzylac", "console", "Nulle", "com", "Bob 2", "COMA"] {
            assert_eq!(name_issue(n), None, "{n}");
        }
    }

    #[test]
    fn old_config_without_destruction_fields_still_loads() {
        let c: Config = serde_json::from_str(r#"{"profiles":[{"name":"x","vault_path":"v","key_path":"k"}],"last":0}"#).unwrap();
        assert_eq!(c.profiles.len(), 1);
        assert!(c.profiles[0].destruct.is_none() && c.global_destruct.is_none() && c.profiles[0].use_key);
    }
}
