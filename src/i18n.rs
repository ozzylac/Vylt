//! Tiny i18n: French source strings are the keys; EN/ES come from `strings::TABLE`.
//! Unknown keys fall back to the French text (a test guards that every `tr("…")` is in the table).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::strings::TABLE;

#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Lang {
    Fr,
    #[default]
    En,
    Es,
}

impl Lang {
    pub const ALL: [Lang; 3] = [Lang::Fr, Lang::En, Lang::Es];

    pub fn name(self) -> &'static str {
        match self {
            Lang::Fr => "Français",
            Lang::En => "English",
            Lang::Es => "Español",
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set(l: Lang) {
    CURRENT.store(l as u8, Ordering::Relaxed);
}

pub fn get() -> Lang {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Lang::En,
        2 => Lang::Es,
        _ => Lang::Fr,
    }
}

fn index() -> &'static HashMap<&'static str, (&'static str, &'static str)> {
    static IDX: OnceLock<HashMap<&'static str, (&'static str, &'static str)>> = OnceLock::new();
    IDX.get_or_init(|| TABLE.iter().map(|(fr, en, es)| (*fr, (*en, *es))).collect())
}

/// Translate a French source string into the current language.
pub fn tr(fr: &'static str) -> &'static str {
    match get() {
        Lang::Fr => fr,
        l => index().get(fr).map_or(fr, |(en, es)| if l == Lang::En { en } else { es }),
    }
}
