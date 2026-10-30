//! Unlocked-session state and the screen state machine.

use std::time::{Duration, Instant};

use vylt::hidden::{self, OpenBox};
use vylt::lock::{Attempt, LockKind};
use vylt::vault::{Entry, Vault};
use zeroize::Zeroizing;

use crate::config::Profile;
use crate::i18n::tr;
use crate::platform;

pub type Secret = Zeroizing<String>;

/// Message shown over every screen (fake error after a destruction, or a preview of it).
#[derive(Clone)]
pub struct Alert {
    pub title: String,
    pub body: String,
    pub close_app: bool,
    /// Confirmation (check mark) rather than an error.
    pub info: bool,
    /// Diagnostic code (SV-Exxx) shown under the message; empty for none.
    pub code: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Section {
    #[default]
    Perso,
    Appearance,
    Session,
    Master,
    Tfa,
    Hidden,
    Decoy,
    Transfer,
    Passkeys,
    Portable,
    Destroy,
}

pub fn secret() -> Secret {
    Zeroizing::new(String::with_capacity(512))
}

pub enum Screen {
    Login { pw: Secret, err: String, show_paths: bool },
    NewProfile(Box<Setup>),
    Import { path: String, pass: Secret, key_path: String, err: String },
    TwoFactor { vault: Option<Box<Vault>>, decoy: bool, code: String, tries: u8, err: String },
    Unlocked(Box<Session>),
}

/// State of the profile-creation wizard.
pub struct Setup {
    pub step: usize,
    pub name: String,
    /// The user typed a name: stop replacing it with the localized default.
    pub name_touched: bool,
    pub color: u8,
    pub photo: Option<std::path::PathBuf>,
    pub pw: Secret,
    pub pw2: Secret,
    pub use_key: bool,
    /// Portable mode: 0 = key on this PC, 1 = key on another removable drive.
    pub key_place: u8,
    /// File name of the secret key (editable in every mode).
    pub key_name: String,
    pub key_name_touched: bool,
    pub key_path: String,
    /// The user edited the key location: stop replacing it with the suggestion.
    pub key_touched: bool,
    pub auto_lock: bool,
    pub tfa: bool,
    pub import: bool,
    pub err: String,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            step: 0,
            name: String::new(),
            name_touched: false,
            color: 0,
            photo: None,
            pw: secret(),
            pw2: secret(),
            use_key: true,
            key_place: 0,
            key_name: String::new(),
            key_name_touched: false,
            key_path: String::new(),
            key_touched: false,
            auto_lock: true,
            tfa: false,
            import: false,
            err: String::new(),
        }
    }
}

pub fn login_screen(err: &str) -> Screen {
    Screen::Login { pw: secret(), err: err.to_owned(), show_paths: false }
}

pub fn new_profile_screen() -> Screen {
    Screen::NewProfile(Box::default())
}

pub fn import_screen() -> Screen {
    Screen::Import { path: String::new(), pass: secret(), key_path: String::new(), err: String::new() }
}

#[derive(PartialEq, Clone, Copy)]
pub enum Tab {
    Vault,
    Health,
    Settings,
}

#[derive(PartialEq, Clone, Copy)]
pub enum View {
    Main,
    Hidden(u64),
}

pub enum LockChoice {
    Keep,
    Off,
    Kind(LockKind),
}

pub struct Edit {
    pub idx: Option<usize>,
    pub entry: Entry,
    pub orig_password: Secret,
    pub reveal: bool,
    pub gen_len: usize,
    pub gen_symbols: bool,
    pub lock_choice: LockChoice,
    pub lock_code: Secret,
    pub lock_code2: Secret,
}

impl Edit {
    pub fn new(idx: Option<usize>, entry: Entry) -> Self {
        let orig_password = Zeroizing::new(entry.password.clone());
        Self {
            idx,
            entry,
            orig_password,
            reveal: false,
            gen_len: 24,
            gen_symbols: true,
            lock_choice: LockChoice::Keep,
            lock_code: secret(),
            lock_code2: secret(),
        }
    }
}

pub struct TfaSetup {
    pub key: Secret,
    pub uri: Secret,
    pub confirm: String,
    pub err: String,
}

pub enum XStep {
    Auth,
    Prepare,
    Wait(Instant),
    Done { path: String, fingerprint: String },
}

/// Migration wizard state. Dropped (aborted) whenever the session locks.
pub struct Xfer {
    pub step: XStep,
    pub pw: Secret,
    pub code: String,
    pub fails: u8,
    pub pass: Secret,
    pub pass2: Secret,
    pub dest: String,
    pub phrase: String,
    pub ack1: bool,
    pub ack2: bool,
    pub err: String,
}

impl Xfer {
    pub fn new() -> Self {
        Self {
            step: XStep::Auth,
            pw: secret(),
            code: String::new(),
            fails: 0,
            pass: secret(),
            pass2: secret(),
            dest: String::new(),
            phrase: String::new(),
            ack1: false,
            ack2: false,
            err: String::new(),
        }
    }
}

#[derive(Default)]
pub struct SettingsState {
    pub new_pw: Secret,
    pub new_pw2: Secret,
    pub kdf_level: usize,
    pub msg: String,
    pub tfa_setup: Option<TfaSetup>,
    pub tfa_code: String,
    pub hid_name: String,
    pub hid_pw: Secret,
    pub hid_pw2: Secret,
    pub hid_msg: String,
    pub decoy_real: Secret,
    pub decoy_pw: Secret,
    pub decoy_pw2: Secret,
    pub decoy_msg: String,
    pub section: Section,
    pub name_edit: Option<String>,
    pub perso_msg: String,
    pub dest_tab: u8,
    pub act: Option<vylt::destroy::Actions>,
    pub act_pw: Secret,
    pub act_msg: String,
    pub preview: Option<Alert>,
    pub dest_auth: Secret,
    pub dest_pw: Secret,
    pub dest_pw2: Secret,
    pub glob_key: Secret,
    pub glob_key2: Secret,
    pub dest_msg: String,
    pub import_path: String,
    pub import_msg: String,
    /// CSV file just imported, offered for secure deletion.
    pub import_done: Option<String>,
    pub xfer: Option<Xfer>,
    /// Portable <-> installed move: target drive, key location (0 PC, 1 USB, 2 other), other path.
    pub mv_drive: Option<char>,
    pub mv_key: u8,
    pub mv_path: String,
    pub mv_pw: Secret,
    pub mv_err: String,
    /// Set once the profile moved: shown after the session closes.
    pub moved: Option<Alert>,
    /// Current master password and 2FA code, asked before changing the master password.
    pub cur_pw: Secret,
    pub cur_code: String,
    /// `kdf_level` was set from the vault's actual parameters.
    pub kdf_synced: bool,
    /// Linked profiles tab: chosen profile (by pid), typed identifier, message.
    pub link_target: String,
    pub link_input: String,
    pub link_msg: String,
    pub link_shown: bool,
    pub pk_msg: String,
}

pub struct Session {
    pub vault: Vault,
    pub profile: Profile,
    pub is_decoy: bool,
    pub tab: Tab,
    pub view: View,
    pub open: Vec<OpenBox>,
    pub search: String,
    pub cat_filter: Option<String>,
    pub selected: Option<usize>,
    pub edit: Option<Edit>,
    pub reveal_pw: bool,
    pub reveal_codes: Vec<bool>,
    /// Entry whose code gate was passed recently, with the time it was passed.
    pub unlocked_entry: Option<(usize, Instant)>,
    pub entry_code: Secret,
    pub entry_fails: u8,
    /// Seconds left before the shown entry accepts a code again (0: no delay).
    pub entry_wait: u64,
    pub special: Secret,
    /// The "special access" field is invisible until Ctrl+Shift+H is pressed.
    pub show_special: bool,
    pub confirm_delete_box: bool,
    pub last_activity: Instant,
    pub clip_clear_at: Option<Instant>,
    pub toast: Option<(String, Instant)>,
    pub st: SettingsState,
}

pub const ENTRY_UNLOCK_TTL: Duration = Duration::from_secs(60);

impl Session {
    pub fn new(vault: Vault, profile: Profile, is_decoy: bool) -> Self {
        Self {
            vault,
            profile,
            is_decoy,
            tab: Tab::Vault,
            view: View::Main,
            open: Vec::new(),
            search: String::new(),
            cat_filter: None,
            selected: None,
            edit: None,
            reveal_pw: false,
            reveal_codes: Vec::new(),
            unlocked_entry: None,
            entry_code: secret(),
            entry_fails: 0,
            entry_wait: 0,
            special: secret(),
            show_special: false,
            confirm_delete_box: false,
            last_activity: Instant::now(),
            clip_clear_at: None,
            toast: None,
            st: SettingsState::default(),
        }
    }

    pub fn say(&mut self, m: impl Into<String>) {
        self.toast = Some((m.into(), Instant::now()));
    }

    pub fn copy(&mut self, text: &str, what: &str) {
        let ttl = self.vault.settings.clipboard_secs;
        if platform::copy_secret(text, Duration::from_secs(ttl)) {
            self.clip_clear_at = Some(Instant::now() + Duration::from_secs(ttl));
            self.say(format!("{what} — {} {ttl} s", tr("effacé dans")));
        }
    }

    pub fn entries(&self) -> &[Entry] {
        match self.view {
            View::Hidden(id) => self.open.iter().find(|b| b.id == id).map_or(&self.vault.entries[..], |b| &b.entries[..]),
            View::Main => &self.vault.entries,
        }
    }

    pub fn entries_mut(&mut self) -> &mut Vec<Entry> {
        if let View::Hidden(id) = self.view
            && let Some(i) = self.open.iter().position(|b| b.id == id)
        {
            return &mut self.open[i].entries;
        }
        &mut self.vault.entries
    }

    pub fn hidden_name(&self) -> Option<&str> {
        match self.view {
            View::Hidden(id) => self.open.iter().find(|b| b.id == id).map(|b| b.name.as_str()),
            View::Main => None,
        }
    }

    /// Re-seal every open hidden category into the vault, then save the vault file.
    pub fn persist(&mut self) {
        let mut err = None;
        for b in &self.open {
            match b.seal() {
                Ok(sb) => hidden::upsert(&mut self.vault.hidden, sb),
                Err(e) => err = Some(e.to_string()),
            }
        }
        if let Err(e) = self.vault.save() {
            err = Some(e.to_string());
        }
        if let Some(e) = err {
            self.say(format!("{} : {e}", tr("Erreur d'enregistrement")));
        }
    }

    pub fn switch_view(&mut self, v: View) {
        self.view = v;
        self.selected = None;
        self.edit = None;
        self.cat_filter = None;
        self.reset_reveal();
    }

    pub fn reset_reveal(&mut self) {
        self.reveal_pw = false;
        self.reveal_codes.clear();
        self.unlocked_entry = None;
        self.entry_code = secret();
        self.entry_fails = 0;
        self.entry_wait = 0;
    }

    /// Try `code` on the gate of entry `i` (counted and saved). Returns true when it opens.
    pub fn try_entry_code(&mut self, i: usize, code: &str) -> bool {
        let now = crate::config::now_secs();
        let r = self.entries_mut().get_mut(i).and_then(|e| e.lock.as_mut()).map(|g| g.attempt(code, now));
        self.persist();
        match r {
            Some(Attempt::Ok) => {
                self.unlocked_entry = Some((i, Instant::now()));
                self.entry_fails = 0;
                self.entry_wait = 0;
                true
            }
            Some(Attempt::Wait(n)) => {
                self.entry_wait = n;
                false
            }
            _ => {
                self.entry_fails += 1;
                self.entry_wait = 0;
                false
            }
        }
    }

    /// Whether the code gate of entry `i` currently blocks access.
    pub fn entry_blocked(&self, i: usize) -> bool {
        let locked = self.entries().get(i).is_some_and(|e| e.lock.is_some());
        locked && !self.unlocked_entry.is_some_and(|(j, t)| j == i && t.elapsed() < ENTRY_UNLOCK_TTL)
    }
}
