//! Screens shown before the vault is open: profile picker, new profile, transfer import, 2FA.

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText};
use vylt::vault::{Vault, VaultError};
use vylt::{decoy, destroy, otp, transfer};
use zeroize::Zeroize;

use crate::config::{self, Config, Profile};
use crate::i18n::tr;
use crate::session::*;
use crate::theme;
use crate::ui_common::*;

fn after_open(res: Result<decoy::Opened, VaultError>, profile: &Profile) -> Result<Screen, String> {
    match res {
        // The decoy asks for the same 2FA as the real vault (copied at its creation).
        Ok(o) if o.vault.unlock_totp.is_some() => {
            Ok(Screen::TwoFactor { vault: Some(Box::new(o.vault)), decoy: o.is_decoy, code: String::new(), tries: 0, err: String::new() })
        }
        Ok(o) => Ok(Screen::Unlocked(Box::new(Session::new(o.vault, profile.clone(), o.is_decoy)))),
        // One generic message: never reveal which factor was wrong.
        Err(VaultError::Io(_)) => Err(crate::errcode::tag(tr("Coffre ou clé secrète introuvable."), "SV-E14")),
        Err(e) => Err(crate::errcode::tag(tr("Identifiants invalides."), e.code())),
    }
}

/// Start the configured program (no shell) and turn the rest into an alert for the app to show.
fn run_actions(a: &destroy::Actions) -> Option<Alert> {
    if a.run && !a.program.trim().is_empty() {
        crate::platform::spawn_detached(a.program.trim(), &destroy::split_args(&a.args));
    }
    if a.show_message {
        Some(Alert { title: a.title.clone(), body: a.body.clone(), close_app: a.close_app, info: false, code: String::new() })
    } else if a.close_app {
        Some(Alert { title: String::new(), body: String::new(), close_app: true, info: false, code: String::new() })
    } else {
        None
    }
}

pub fn login_ui(
    ui: &mut egui::Ui,
    cfg: &mut Config,
    sel: &mut usize,
    pw: &mut Secret,
    err: &mut String,
    show_paths: &mut bool,
    alert: &mut Option<Alert>,
) -> Option<Screen> {
    let mut next = None;
    ui.with_layout(egui::Layout::top_down(egui::Align::Max), |ui| appearance_bar(ui, cfg));
    centered(ui, 440.0, |ui| {
        ui.label(theme::bold("Vylt").size(22.0));
        if let Some(d) = config::portable_drive() {
            ui.label(RichText::new(tr("Mode portable · {d}:").replace("{d}", &d.to_string())).size(13.0).color(theme::accent()));
        }
        ui.label(RichText::new(tr("Sélectionnez votre profil. Chaque profil dispose de son propre coffre, mot de passe et clé secrète.")).color(theme::dim()));
        ui.add_space(4.0);

        let mut picked = None;
        for (i, p) in cfg.profiles.iter().enumerate() {
            theme::hline(ui);
            let selected = i == *sel;
            let r = egui::Frame::new()
                .fill(if selected { theme::selected_fill() } else { egui::Color32::TRANSPARENT })
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        theme::avatar(ui, &p.name, p.color, p.avatar.as_deref(), 30.0);
                        ui.label(if selected { theme::bold(&p.name) } else { RichText::new(&p.name) });
                        if selected {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| theme::check(ui, theme::accent()));
                        }
                    });
                })
                .response
                .interact(egui::Sense::click());
            if r.clicked() {
                picked = Some(i);
            }
        }
        theme::hline(ui);
        if let Some(i) = picked {
            *sel = i;
            pw.zeroize();
            err.clear();
        }
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 22.0;
            if theme::link(ui, tr("+ Nouveau profil")).clicked() {
                next = Some(new_profile_screen());
            }
            if theme::link(ui, tr("Importer un transfert")).clicked() {
                next = Some(import_screen());
            }
        });
        ui.add_space(6.0);

        if cfg.profiles.get(*sel).is_none() {
            return;
        }
        theme::label(ui, tr("Mot de passe maître"));
        let r = password_field(ui, pw, "");
        if !*show_paths {
            r.request_focus();
        }
        if cfg.profiles[*sel].use_key {
            ui.checkbox(show_paths, tr("Afficher l'emplacement de la clé secrète"));
        }
        if *show_paths && cfg.profiles[*sel].use_key {
            let mut k = cfg.profiles[*sel].key_path.to_string_lossy().into_owned();
            if ui.text_edit_singleline(&mut k).changed() {
                cfg.profiles[*sel].key_path = PathBuf::from(k);
            }
        }
        theme::error(ui, err);
        let go = theme::primary_wide(ui, tr("Déverrouiller")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter));
        if go && !pw.is_empty() {
            // Irreversible erase passwords are compared with what was typed, before any vault opens.
            let erase = config::erase_decision(cfg, *sel, pw);
            if erase == config::Erase::All {
                config::wipe_global(cfg);
                pw.zeroize();
                *sel = 0;
                if cfg.profiles.is_empty() {
                    next = Some(new_profile_screen());
                } else {
                    *err = tr("Identifiants invalides.").into();
                }
                return;
            }
            if erase == config::Erase::Profile {
                let gone = cfg.profiles.remove(*sel);
                let actions = gone.actions.as_ref().and_then(|a| destroy::open_actions(a, pw));
                config::wipe_profile(&gone);
                *sel = 0;
                cfg.last = 0;
                config::save(cfg);
                pw.zeroize();
                let shown = actions.as_ref().map(run_actions).unwrap_or(None);
                let message = shown.as_ref().is_some_and(|a| !a.title.is_empty());
                *alert = shown;
                if cfg.profiles.is_empty() {
                    next = Some(new_profile_screen());
                } else if !message {
                    *err = tr("Identifiants invalides.").into();
                }
                return;
            }
            let profile = cfg.profiles[*sel].clone();
            let wait = config::wait_secs(cfg, &profile.name);
            if wait > 0 {
                *err = tr("Trop d'essais. Réessayez dans {n} s.").replace("{n}", &wait.to_string());
                pw.zeroize();
                return;
            }
            let res = profile.secret_key().and_then(|sk| decoy::open_either(&profile.vault_path, pw, &sk));
            let wrong = matches!(res, Err(VaultError::Decrypt));
            match after_open(res, &profile) {
                Ok(screen) => {
                    cfg.last = *sel;
                    if profile.use_key {
                        cfg.profiles[*sel].key_path = profile.key_file();
                    }
                    if matches!(screen, Screen::Unlocked(_)) {
                        config::note_success(cfg, &profile.name);
                    }
                    config::save(cfg);
                    next = Some(screen);
                }
                Err(e) => {
                    if wrong {
                        config::note_failure(cfg, &profile.name);
                    }
                    *err = e;
                }
            }
            pw.zeroize();
        }
    });
    next
}

pub fn import_ui(
    ui: &mut egui::Ui,
    cfg: &mut Config,
    sel: &mut usize,
    path: &mut String,
    pass: &mut Secret,
    key_path: &mut String,
    err: &mut String,
) -> Option<Screen> {
    let mut next = None;
    ui.with_layout(egui::Layout::top_down(egui::Align::Max), |ui| appearance_bar(ui, cfg));
    centered(ui, 520.0, |ui| {
        theme::title(ui, tr("Importer un transfert sécurisé"));
        theme::label(ui, tr("À utiliser sur le nouveau PC. Le fichier .svtransfer et sa passphrase de transfert sont nécessaires."));
        theme::label(ui, tr("Fichier de transfert (.svtransfer)"));
        ui.add(egui::TextEdit::singleline(path).desired_width(f32::INFINITY));
        theme::label(ui, tr("Passphrase de transfert"));
        password_field(ui, pass, "");
        theme::label(ui, tr("Où placer la clé secrète (laisser vide = emplacement par défaut)"));
        ui.add(egui::TextEdit::singleline(key_path).desired_width(f32::INFINITY));
        theme::label(ui, tr("Vous vous connecterez ensuite avec votre mot de passe maître habituel."));
        theme::error(ui, err);
        ui.horizontal(|ui| {
            if theme::primary(ui, tr("Importer")).clicked() {
                match do_import(cfg, Path::new(path.trim()), pass, key_path.trim()) {
                    Ok(idx) => {
                        *sel = idx;
                        cfg.last = idx;
                        config::save(cfg);
                        next = Some(login_screen(tr("Profil importé. Saisissez votre mot de passe maître.")));
                    }
                    Err(e) => *err = e,
                }
                pass.zeroize();
            }
            if ui.button(tr("Annuler")).clicked() {
                next = Some(if cfg.profiles.is_empty() { new_profile_screen() } else { login_screen("") });
            }
        });
    });
    next
}

fn do_import(cfg: &mut Config, file: &Path, pass: &str, key: &str) -> Result<usize, String> {
    let pkg = transfer::read(file, pass).map_err(|e| match e {
        VaultError::Io(_) => crate::errcode::tag(tr("Fichier introuvable."), "SV-E14"),
        VaultError::Decrypt => crate::errcode::tag(tr("Passphrase incorrecte ou fichier corrompu."), "SV-E10"),
        e => crate::errcode::tag(tr("Fichier de transfert invalide."), e.code()),
    })?;
    if let Some(i) = config::name_issue(&pkg.profile_name) {
        return Err(name_issue_text(&i).into());
    }
    if cfg.profiles.iter().any(|p| config::folder_name(&p.name) == config::folder_name(&pkg.profile_name)) {
        return Err(tr("Un profil de ce nom existe déjà.").into());
    }
    let dir = config::profile_dir(&pkg.profile_name);
    let key_path = if key.is_empty() { config::default_key_path(&pkg.profile_name) } else { PathBuf::from(key) };
    let profile = Profile {
        name: pkg.profile_name.clone(),
        vault_path: dir.join("vault.svault"),
        key_path,
        use_key: !pkg.key.is_empty(),
        destruct: None,
        actions: None,
        avatar: None,
        color: 0,
        ..Default::default()
    };
    transfer::install(&pkg, &profile.vault_path, &profile.key_path).map_err(|e| e.to_string())?;
    cfg.profiles.push(profile);
    Ok(cfg.profiles.len() - 1)
}

#[allow(clippy::too_many_arguments)]
pub fn two_factor_ui(
    ui: &mut egui::Ui,
    cfg: &mut Config,
    sel: usize,
    vault: &mut Option<Box<Vault>>,
    decoy: bool,
    code: &mut String,
    tries: &mut u8,
    err: &mut String,
) -> Option<Screen> {
    let mut next = None;
    centered(ui, 380.0, |ui| {
        theme::title(ui, tr("Authentification à deux facteurs"));
        theme::label(ui, tr("Saisissez le code à 6 chiffres de votre application d'authentification."));
        let r = ui.add(
            egui::TextEdit::singleline(code)
                .font(egui::FontId::monospace(26.0))
                .char_limit(7)
                .hint_text("000000")
                .desired_width(f32::INFINITY),
        );
        r.request_focus();
        theme::error(ui, err);
        let go = theme::primary(ui, tr("Valider")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter));
        let name = cfg.profiles.get(sel).map(|p| p.name.clone()).unwrap_or_default();
        let wait = config::wait_secs(cfg, &name);
        if go && !code.is_empty() && wait > 0 {
            code.clear();
            *err = tr("Trop d'essais. Réessayez dans {n} s.").replace("{n}", &wait.to_string());
        } else if go && !code.is_empty() {
            // A code is accepted once: the step of the last accepted code is kept in the vault.
            let step = vault.as_ref().and_then(|v| Some((v.unlock_totp.as_ref()?, v.last_totp_step))).and_then(|(k, last)| otp::verify_step(k, code).filter(|&s| s > last));
            code.clear();
            if let Some(step) = step {
                if let (Some(mut v), Some(p)) = (vault.take(), cfg.profiles.get(sel).cloned()) {
                    v.last_totp_step = step;
                    let _ = v.save();
                    config::note_success(cfg, &p.name);
                    next = Some(Screen::Unlocked(Box::new(Session::new(*v, p, decoy))));
                }
            } else {
                config::note_failure(cfg, &name);
                *tries += 1;
                *err = format!("{} ({}/3).", tr("Code invalide"), *tries);
                if *tries >= 3 {
                    next = Some(login_screen(tr("Nombre d'essais 2FA dépassé.")));
                }
            }
        }
        if ui.button(tr("Annuler")).clicked() {
            next = Some(login_screen(""));
        }
    });
    next
}
