//! User-facing diagnostic codes. Every code is stable: a number is never renamed or reused, so a
//! code a person reports always means the same thing. The lib errors carry their own code (see
//! `VaultError::code` / `PasskeyError::code`); this module is the single catalogue and the place
//! that turns a code into a localized sentence.

use crate::i18n::tr;

/// (code, what it means — English reference; the shown text comes from `message`).
/// Consumed by the consistency test below; kept as the single written-down catalogue.
#[cfg_attr(not(test), allow(dead_code))]
pub const CATALOG: &[(&str, &str)] = &[
    ("SV-E10", "wrong password, secret key, or corrupted vault"),
    ("SV-E11", "invalid or unreadable vault file"),
    ("SV-E12", "key derivation failed"),
    ("SV-E13", "system random generator unavailable"),
    ("SV-E14", "vault or secret key file not found"),
    ("SV-E30", "invalid passkey key material"),
    ("SV-E31", "random generator unavailable"),
    ("SV-E40", "configuration file unreadable, no usable copy"),
    ("SV-E41", "configuration restored from the backup copy"),
    ("SV-E42", "some profiles could not be read"),
    ("SV-E50", "copied file does not match the original"),
    ("SV-E51", "a profile of that name already exists at the destination"),
    ("SV-E52", "the copied vault could not be opened"),
    ("SV-E60", "browser-extension installation failed"),
    ("SV-E61", "Windows passkey-provider registration failed"),
    ("SV-E70", "Have I Been Pwned check failed (network)"),
    ("SV-E90", "unexpected error"),
];

/// Localized one-line explanation of a code (falls back to the generic SV-E90 text).
pub fn message(code: &str) -> &'static str {
    match code {
        "SV-E10" => tr("Mot de passe, clé secrète incorrects, ou coffre corrompu."),
        "SV-E11" => tr("Fichier de coffre invalide ou illisible."),
        "SV-E12" => tr("La dérivation de la clé a échoué."),
        "SV-E13" => tr("Le générateur aléatoire du système est indisponible."),
        "SV-E14" => tr("Coffre ou clé secrète introuvable."),
        "SV-E30" => tr("Clé de passe invalide."),
        "SV-E31" => tr("Le générateur aléatoire du système est indisponible."),
        "SV-E40" => tr("Fichier de configuration illisible, aucune copie utilisable."),
        "SV-E41" => tr("Configuration restaurée depuis la copie de secours."),
        "SV-E42" => tr("Certains profils n'ont pas pu être lus."),
        "SV-E50" => tr("La copie ne correspond pas à l'original."),
        "SV-E51" => tr("Un profil de ce nom existe déjà à la destination."),
        "SV-E52" => tr("La copie du coffre n'a pas pu être ouverte."),
        "SV-E60" => tr("Installation de l'extension impossible."),
        "SV-E61" => tr("Enregistrement du fournisseur Windows impossible."),
        "SV-E70" => tr("Vérification des fuites impossible (réseau)."),
        _ => tr("Erreur inattendue."),
    }
}

/// A message with its code appended, e.g. "Identifiants invalides. (SV-E10)". When `msg` is empty
/// the code's own catalogue sentence is used.
pub fn tag(msg: &str, code: &str) -> String {
    if msg.trim().is_empty() {
        format!("{} ({code})", message(code))
    } else {
        format!("{msg} ({code})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn codes_are_unique_well_formed_and_all_have_a_message() {
        let mut seen = HashSet::new();
        for (code, _) in CATALOG {
            assert!(seen.insert(*code), "duplicate code {code}");
            assert!(code.starts_with("SV-E") && code[4..].chars().all(|c| c.is_ascii_digit()), "bad code {code}");
            // Every catalogued code must map to a real message, not the fallback (except SV-E90).
            if *code != "SV-E90" {
                assert_ne!(message(code), message("SV-E90"), "{code} has no message");
            }
        }
    }

    #[test]
    fn lib_errors_use_catalogued_codes() {
        let known: HashSet<&str> = CATALOG.iter().map(|(c, _)| *c).collect();
        use vylt::vault::VaultError;
        for e in [VaultError::Decrypt, VaultError::Format("x"), VaultError::Kdf, VaultError::Random] {
            assert!(known.contains(e.code()), "{}", e.code());
        }
        use vylt::passkey::PasskeyError;
        for e in [PasskeyError::Rng, PasskeyError::Key] {
            assert!(known.contains(e.code()), "{}", e.code());
        }
    }

    #[test]
    fn tag_formats_the_code() {
        crate::i18n::set(crate::i18n::Lang::Fr);
        assert_eq!(tag("Identifiants invalides.", "SV-E10"), "Identifiants invalides. (SV-E10)");
        assert!(tag("", "SV-E14").ends_with("(SV-E14)"));
    }
}
