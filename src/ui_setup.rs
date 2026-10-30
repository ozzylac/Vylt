//! First-run / new-profile wizard: profile, master password, secret key, options and summary.

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText, Stroke, Vec2};
use vylt::otp;
use vylt::vault::{KdfParams, SecretKey, Vault};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{self, Config, Profile};
use crate::i18n::{self, tr, Lang};
use crate::platform;
use crate::pwgen;
use crate::session::*;
use crate::theme;
use crate::ui_common::*;

const STEPS: usize = 4;

fn step_label(i: usize) -> &'static str {
    match i {
        0 => tr("Profil"),
        1 => tr("Mot de passe maître"),
        2 => tr("Clé secrète"),
        _ => tr("Sécurité et récapitulatif"),
    }
}

/// "Utilisateur 1" / "User 1" / "Usuario 1": first free number in the current language.
fn default_name(cfg: &Config) -> String {
    (1..)
        .map(|n| tr("Utilisateur {n}").replace("{n}", &n.to_string()))
        .find(|c| !cfg.profiles.iter().any(|p| config::folder_name(&p.name) == config::folder_name(c)))
        .unwrap_or_default()
}

fn default_key_name(name: &str) -> String {
    format!("{}.key", config::folder_name(if name.trim().is_empty() { "profil" } else { name.trim() }))
}

/// Suggested key location. Installed: the first removable drive, else next to the vault.
/// Portable: this PC (`on_pc`) or another removable drive, never the vault's own drive.
fn suggested_key(name: &str, file: &str, usb: Option<char>, on_pc: bool) -> String {
    if on_pc {
        return config::pc_keys_dir().join(file).to_string_lossy().into_owned();
    }
    match usb {
        Some(l) => format!("{l}:\\Vylt\\{file}"),
        None if config::portable_root().is_some() => String::new(),
        None => config::profile_dir(name.trim()).join(file).to_string_lossy().into_owned(),
    }
}

fn valid_file_name(n: &str) -> bool {
    !n.trim().is_empty() && !n.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) && n.trim() != "." && n.trim() != ".."
}

fn rail(ui: &mut egui::Ui, w: &mut Setup, cfg: &mut Config) -> Option<Screen> {
    let mut next = None;
    egui::Panel::left("setup-rail")
        .exact_size(280.0)
        .resizable(false)
        .frame(egui::Frame::new().fill(theme::panel()).inner_margin(egui::Margin::symmetric(28, 32)))
        .show(ui, |ui| {
            ui.label(theme::bold("Vylt").size(18.0));
            ui.label(RichText::new(tr("Création d'un profil")).size(13.0).color(theme::dim()));
            if let Some(d) = config::portable_drive() {
                ui.label(RichText::new(tr("Mode portable · {d}:").replace("{d}", &d.to_string())).size(13.0).color(theme::accent()));
            }
            ui.add_space(28.0);
            for i in 0..STEPS {
                let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 52.0), egui::Sense::hover());
                let c = egui::pos2(rect.left() + 11.0, rect.center().y);
                let p = ui.painter();
                if i + 1 < STEPS {
                    p.line_segment([c + Vec2::new(0.0, 13.0), c + Vec2::new(0.0, 39.0)], Stroke::new(2.0, theme::line()));
                }
                let (txt, font) = if i < w.step {
                    p.circle_filled(c, 11.0, theme::accent());
                    let s = Stroke::new(2.0, theme::on_accent());
                    p.line_segment([c + Vec2::new(-4.5, 0.5), c + Vec2::new(-1.5, 3.5)], s);
                    p.line_segment([c + Vec2::new(-1.5, 3.5), c + Vec2::new(4.5, -3.5)], s);
                    (theme::dim(), egui::FontId::proportional(14.0))
                } else if i == w.step {
                    p.circle_stroke(c, 10.0, Stroke::new(2.0, theme::accent()));
                    p.text(c, egui::Align2::CENTER_CENTER, (i + 1).to_string(), egui::FontId::new(12.0, theme::semibold()), theme::accent());
                    (theme::text(), egui::FontId::new(14.0, theme::semibold()))
                } else {
                    p.circle_stroke(c, 10.25, Stroke::new(1.5, theme::line()));
                    p.text(c, egui::Align2::CENTER_CENTER, (i + 1).to_string(), egui::FontId::proportional(12.0), theme::dim());
                    (theme::dim(), egui::FontId::proportional(14.0))
                };
                p.text(c + Vec2::new(24.0, 0.0), egui::Align2::LEFT_CENTER, step_label(i), font, txt);
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 14.0;
                    if theme::link(ui, tr("Importer un transfert")).clicked() {
                        next = Some(import_screen());
                    }
                    if !cfg.profiles.is_empty() && theme::link(ui, tr("Annuler")).clicked() {
                        next = Some(login_screen(""));
                    }
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("setup-lang").selected_text(i18n::get().name()).show_ui(ui, |ui| {
                        for l in Lang::ALL {
                            if ui.selectable_label(i18n::get() == l, l.name()).clicked() {
                                cfg.lang = l;
                                i18n::set(l);
                                config::save(cfg);
                            }
                        }
                    });
                    if ui.button(if cfg.dark { tr("Thème clair") } else { tr("Thème sombre") }).clicked() {
                        cfg.dark = !cfg.dark;
                        theme::apply(ui.ctx(), cfg.dark);
                        config::save(cfg);
                    }
                });
                ui.add_space(10.0);
                let note = match config::portable_drive() {
                    Some(d) => tr("Le programme et les coffres sont sur la clé USB {d}:. Par défaut, aucune donnée n'est envoyée sur Internet.").replace("{d}", &d.to_string()),
                    None => tr("Tout reste sur cet ordinateur. Par défaut, aucune donnée n'est envoyée sur Internet.").to_owned(),
                };
                ui.label(RichText::new(note).size(12.0).color(theme::dim()));
            });
        });
    next
}

fn strength_bar(ui: &mut egui::Ui, pw: &str) {
    let sc = pwgen::score(pw);
    let (txt, col) = strength(sc);
    let filled = (sc as usize).max(1); // even the weakest shows one lit segment
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 4.0), egui::Sense::hover());
    let seg = (rect.width() - 12.0) / 4.0;
    for i in 0..4 {
        let r = egui::Rect::from_min_size(rect.min + Vec2::new(i as f32 * (seg + 4.0), 0.0), Vec2::new(seg, 4.0));
        ui.painter().rect_filled(r, 2, if pw.is_empty() || i >= filled { theme::line() } else { col });
    }
    if !pw.is_empty() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} {txt}", tr("Robustesse"))).size(12.0).color(col));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                theme::label(ui, &tr("{n} caractères").replace("{n}", &pw.chars().count().to_string()));
            });
        });
    }
}

fn criterion(ui: &mut egui::Ui, ok: bool, text: &str) {
    ui.horizontal(|ui| {
        if ok { theme::check(ui, theme::ok()) } else { theme::cross(ui, theme::dim()) }
        ui.label(RichText::new(text).size(13.0).color(if ok { theme::text() } else { theme::dim() }));
    });
}

fn choice(ui: &mut egui::Ui, on: bool, title: &str, badge: &str, desc: &str) -> bool {
    theme::hline(ui);
    let r = egui::Frame::new()
        .fill(if on { theme::selected_fill() } else { egui::Color32::TRANSPARENT })
        .inner_margin(egui::Margin::symmetric(12, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(20.0), egui::Sense::hover());
                if on {
                    ui.painter().circle_stroke(rect.center(), 8.0, Stroke::new(2.0, theme::accent()));
                    ui.painter().circle_filled(rect.center(), 4.0, theme::accent());
                } else {
                    ui.painter().circle_stroke(rect.center(), 8.25, Stroke::new(1.5, theme::dim()));
                }
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.horizontal(|ui| {
                        ui.label(theme::bold(title));
                        if !badge.is_empty() {
                            ui.label(RichText::new(badge).color(theme::accent()));
                        }
                    });
                    ui.label(RichText::new(desc).size(13.0).color(theme::dim()));
                });
            });
        })
        .response
        .interact(egui::Sense::click());
    r.clicked()
}

fn option(ui: &mut egui::Ui, on: &mut bool, title: &str, desc: &str) {
    theme::hline(ui);
    ui.add_space(4.0);
    ui.horizontal_top(|ui| {
        ui.checkbox(on, "");
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(theme::bold(title));
            ui.label(RichText::new(desc).size(13.0).color(theme::dim()));
        });
    });
    ui.add_space(4.0);
}

fn summary_row(ui: &mut egui::Ui, k: &str, v: RichText) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(Vec2::new(170.0, 20.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.set_min_width(170.0);
            ui.label(RichText::new(k).size(13.0).color(theme::dim()));
        });
        ui.label(v.size(13.0));
    });
}

/// Validate the current step; returns an error message to show, if any.
fn validate(w: &Setup, cfg: &Config) -> Option<&'static str> {
    match w.step {
        0 => {
            let n = w.name.trim();
            if let Some(i) = config::name_issue(n) {
                Some(name_issue_text(&i))
            } else if cfg.profiles.iter().any(|p| config::folder_name(&p.name) == config::folder_name(n)) {
                Some(tr("Un profil de ce nom existe déjà."))
            } else {
                None
            }
        }
        1 => {
            if w.pw.chars().count() < 12 {
                Some(tr("12 caractères minimum."))
            } else if *w.pw != *w.pw2 {
                Some(tr("Les mots de passe diffèrent."))
            } else {
                None
            }
        }
        2 => {
            if !w.use_key && w.pw.chars().count() < 16 {
                Some(tr("Sans clé secrète, le mot de passe maître doit comporter 16 caractères minimum. Revenez à l'étape précédente pour l'allonger."))
            } else if w.use_key && !valid_file_name(&w.key_name) {
                Some(tr("Nom de fichier de clé invalide."))
            } else if w.use_key && w.key_path.trim().is_empty() {
                Some(tr("Veuillez choisir un emplacement pour la clé secrète."))
            } else if w.use_key && config::portable_drive().is_some_and(|d| config::drive_of(Path::new(w.key_path.trim())) == Some(d)) {
                Some(tr("La clé secrète doit être sur un autre support que la clé USB du coffre."))
            } else if w.use_key && PathBuf::from(w.key_path.trim()).exists() {
                Some(tr("Un fichier existe déjà à cet emplacement."))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn create(w: &mut Setup, cfg: &mut Config, sel: &mut usize) -> Result<Screen, String> {
    let name = w.name.trim().to_owned();
    let dir = config::profile_dir(&name);
    let key_path = if w.use_key { PathBuf::from(w.key_path.trim()) } else { config::default_key_path(&name) };
    let mut profile = Profile {
        name: name.clone(),
        vault_path: dir.join("vault.svault"),
        key_path,
        use_key: w.use_key,
        destruct: None,
        actions: None,
        avatar: None,
        color: w.color,
        ..Default::default()
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let vault = if w.use_key {
        if let Some(parent) = profile.key_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let sk = SecretKey::generate().map_err(|e| e.to_string())?;
        sk.save(&profile.key_path).map_err(|e| e.to_string())?;
        Vault::create(&profile.vault_path, &w.pw, &sk, KdfParams::DEFAULT)
    } else {
        Vault::create(&profile.vault_path, &w.pw, &SecretKey::empty(), KdfParams::DEFAULT)
    }
    .map_err(|e| e.to_string())?;
    if let Some(src) = &w.photo {
        profile.avatar = config::save_avatar(src, &name).ok();
    }
    w.pw.zeroize();
    w.pw2.zeroize();

    cfg.profiles.push(profile.clone());
    *sel = cfg.profiles.len() - 1;
    cfg.last = *sel;
    config::save(cfg);

    let mut s = Session::new(vault, profile, false);
    s.vault.settings.auto_lock_secs = if w.auto_lock { 120 } else { 1800 };
    s.persist();
    if w.tfa {
        s.tab = Tab::Settings;
        s.st.section = Section::Tfa;
        let key = otp::new_unlock_key();
        if let Some(uri) = otp::provisioning_uri(&key, &s.profile.name) {
            s.st.tfa_setup = Some(TfaSetup { key: Zeroizing::new(key), uri: Zeroizing::new(uri), confirm: String::new(), err: String::new() });
        }
    } else if w.import {
        s.tab = Tab::Settings;
        s.st.section = Section::Transfer;
    }
    Ok(Screen::Unlocked(Box::new(s)))
}

pub fn setup_ui(ui: &mut egui::Ui, cfg: &mut Config, sel: &mut usize, w: &mut Setup) -> Option<Screen> {
    let mut next = rail(ui, w, cfg);
    if !w.name_touched {
        w.name = default_name(cfg);
    }
    let portable = config::portable_drive();
    let usb = if w.step >= 2 { platform::removable_drives().into_iter().find(|&d| Some(d) != portable) } else { None };
    if !w.key_name_touched {
        w.key_name = default_key_name(&w.name);
    }
    let on_pc = portable.is_some() && w.key_place == 0;
    if w.step >= 2 && !w.key_touched {
        w.key_path = suggested_key(&w.name, w.key_name.trim(), usb, on_pc);
    }

    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(theme::bg()).inner_margin(egui::Margin { left: 56, right: 56, top: 40, bottom: 28 }))
        .show(ui, |ui| {
            let (title, sub) = match w.step {
                0 => (tr("Votre profil"), tr("Chaque personne qui utilise cet ordinateur peut avoir son propre profil, avec son coffre et son mot de passe.")),
                1 => (tr("Mot de passe maître"), tr("Il ouvre votre coffre. Personne ne peut le récupérer à votre place : notez-le dans un endroit sûr.")),
                2 if portable.is_some() => (tr("Clé secrète"), tr("En mode portable, la clé secrète doit être séparée de la clé USB : c'est ce qui protège le coffre si la clé USB est perdue.")),
                2 => (tr("Clé secrète"), tr("Un fichier aléatoire qui s'ajoute au mot de passe maître. Sans lui, un coffre volé reste fermé même si le mot de passe est découvert.")),
                _ => (tr("Sécurité et récapitulatif"), tr("Ces options se modifient ensuite dans les Paramètres.")),
            };
            theme::label(ui, &tr("Étape {n} sur 4").replace("{n}", &(w.step + 1).to_string()));
            ui.label(theme::bold(title).size(24.0));
            ui.label(RichText::new(sub).color(theme::dim()));
            ui.add_space(20.0);

            let footer_h = 60.0;
            let body_h = (ui.available_height() - footer_h).max(120.0);
            ui.allocate_ui_with_layout(Vec2::new(ui.available_width(), body_h), egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.set_min_height(body_h);
                ui.set_max_width(520.0);
                egui::ScrollArea::vertical().max_height(body_h).show(ui, |ui| match w.step {
                    0 => {
                        theme::label(ui, tr("Nom du profil"));
                        let r = ui.add(egui::TextEdit::singleline(&mut w.name).desired_width(f32::INFINITY));
                        if r.changed() {
                            w.name_touched = true;
                        }
                        ui.add_space(14.0);
                        theme::label(ui, tr("Image du profil (facultative)"));
                        ui.horizontal(|ui| {
                            theme::avatar(ui, if w.name.trim().is_empty() { "?" } else { w.name.trim() }, w.color, w.photo.as_deref(), 64.0);
                            ui.add_space(12.0);
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    if ui.button(tr("Choisir une photo…")).clicked()
                                        && let Some(p) = rfd::FileDialog::new().add_filter("Image", &["png", "jpg", "jpeg"]).pick_file()
                                    {
                                        if image::image_dimensions(&p).is_ok() {
                                            w.photo = Some(p);
                                        } else {
                                            w.err = tr("Image illisible.").into();
                                        }
                                    }
                                    if w.photo.is_some() && theme::danger_button(ui, tr("Retirer")).clicked() {
                                        w.photo = None;
                                    }
                                });
                                ui.horizontal(|ui| {
                                    for i in 0..theme::AVATAR_COLORS.len() as u8 {
                                        let (rect, r) = ui.allocate_exact_size(Vec2::splat(26.0), egui::Sense::click());
                                        ui.painter().circle_filled(rect.center(), 10.0, theme::avatar_colors(i).0);
                                        if w.color == i {
                                            ui.painter().circle_stroke(rect.center(), 12.5, Stroke::new(2.0, theme::accent()));
                                        }
                                        if r.clicked() {
                                            w.color = i;
                                        }
                                    }
                                });
                            });
                        });
                        ui.add_space(12.0);
                        theme::label(ui, tr("Images proposées (fonds d'écran Bing de ce PC)"));
                        if let Some(p) = crate::gallery::picker(ui, w.photo.as_deref()) {
                            w.photo = Some(p);
                        }
                    }
                    1 => {
                        theme::label(ui, tr("Mot de passe maître"));
                        password_field(ui, &mut w.pw, "");
                        strength_bar(ui, &w.pw);
                        ui.add_space(4.0);
                        theme::label(ui, tr("Confirmation"));
                        password_field(ui, &mut w.pw2, "");
                        ui.add_space(10.0);
                        theme::hline(ui);
                        ui.add_space(6.0);
                        criterion(ui, w.pw.chars().count() >= 12, tr("Au moins 12 caractères"));
                        criterion(ui, !w.pw.is_empty() && *w.pw == *w.pw2, tr("Les deux saisies sont identiques"));
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(tr("Conseil : une phrase de 4 à 6 mots sans rapport entre eux est facile à retenir et difficile à deviner."))
                                .size(13.0)
                                .color(theme::dim()),
                        );
                    }
                    2 => {
                        if portable.is_some() {
                            for (place, title, badge, desc) in [
                                (0, tr("Clé sur cet ordinateur"), tr("· recommandé"), tr("Le coffre est sur la clé USB, la clé secrète reste sur ce PC. Une clé USB perdue ou volée ne peut pas être ouverte. Pour un autre PC, copiez-y le fichier de clé dans %APPDATA%\\Vylt\\keys.")),
                                (1, tr("Clé sur un autre support"), "", tr("Un second support (autre clé USB, carte SD). Il est demandé à chaque connexion, sur n'importe quel PC.")),
                            ] {
                                if choice(ui, w.use_key && w.key_place == place, title, badge, desc) && !(w.use_key && w.key_place == place) {
                                    w.use_key = true;
                                    w.key_place = place;
                                    w.key_touched = false;
                                }
                            }
                            if choice(ui, !w.use_key, tr("Mot de passe maître seul"), "", tr("Utilisable sur tout PC sans rien d'autre. Toute la sécurité repose sur le mot de passe (16 caractères minimum).")) {
                                w.use_key = false;
                            }
                        } else {
                            if choice(ui, w.use_key, tr("Utiliser une clé secrète"), tr("· recommandé"), tr("Protection maximale. Le fichier sera demandé à chaque connexion ; gardez-le sur une clé USB.")) {
                                w.use_key = true;
                            }
                            if choice(ui, !w.use_key, tr("Mot de passe maître seul"), "", tr("Plus simple, mais toute la sécurité repose sur le mot de passe (16 caractères minimum).")) {
                                w.use_key = false;
                            }
                        }
                        theme::hline(ui);
                        if w.use_key {
                            ui.add_space(14.0);
                            theme::label(ui, tr("Nom du fichier de la clé"));
                            let r = ui.add(egui::TextEdit::singleline(&mut w.key_name).font(egui::TextStyle::Monospace).desired_width(260.0));
                            if r.changed() {
                                w.key_name_touched = true;
                                if w.key_touched && valid_file_name(&w.key_name) {
                                    w.key_path = Path::new(w.key_path.trim()).with_file_name(w.key_name.trim()).to_string_lossy().into_owned();
                                }
                            }
                            ui.add_space(8.0);
                            theme::label(ui, tr("Emplacement de la clé"));
                        }
                        if w.use_key && on_pc {
                            ui.label(RichText::new(w.key_path.trim()).monospace());
                            theme::label(ui, tr("Ce PC uniquement. Rien d'autre que ce fichier n'est écrit sur l'ordinateur."));
                        } else if w.use_key {
                            ui.horizontal(|ui| {
                                let r = ui.add(egui::TextEdit::singleline(&mut w.key_path).font(egui::TextStyle::Monospace).desired_width(400.0));
                                if r.changed() {
                                    w.key_touched = true;
                                }
                                if ui.button(tr("Choisir…")).clicked()
                                    && let Some(p) = rfd::FileDialog::new().set_file_name(w.key_name.trim()).add_filter("Clé", &["key"]).save_file()
                                {
                                    if let Some(f) = p.file_name() {
                                        w.key_name = f.to_string_lossy().into_owned();
                                        w.key_name_touched = true;
                                    }
                                    w.key_path = p.to_string_lossy().into_owned();
                                    w.key_touched = true;
                                }
                            });
                            match usb {
                                Some(l) => {
                                    let on_usb = w.key_path.to_uppercase().starts_with(&format!("{l}:"));
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(tr("Clé USB détectée ({l}:)").replace("{l}", &l.to_string())).size(12.0).color(theme::ok()));
                                        if !on_usb && theme::link(ui, tr("Utiliser la clé USB")).clicked() {
                                            w.key_path = suggested_key(&w.name, w.key_name.trim(), Some(l), false);
                                            w.key_touched = true;
                                        }
                                    });
                                }
                                None if portable.is_some() => {
                                    theme::label(ui, tr("Aucun second support détecté. Branchez-en un ou choisissez un emplacement."));
                                }
                                None => {
                                    theme::label(ui, tr("Aucune clé USB détectée : la clé sera enregistrée sur cet ordinateur. Vous pourrez la déplacer ensuite."));
                                }
                            }
                        }
                        if w.use_key {
                            if portable.is_some() {
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(tr("Une clé secrète enregistrée sur la même clé USB que le coffre n'apporterait aucune protection : cette option n'est pas proposée."))
                                        .size(12.0)
                                        .color(theme::dim()),
                                );
                            }
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(tr("Si ce fichier est perdu, le coffre est définitivement inaccessible. Conservez-en une copie hors ligne."))
                                    .size(12.0)
                                    .color(theme::accent()),
                            );
                        }
                    }
                    _ => {
                        option(ui, &mut w.auto_lock, tr("Verrouillage automatique après 2 minutes"), tr("Et dès que Windows se verrouille ou se met en veille. Sinon : après 30 minutes."));
                        option(ui, &mut w.tfa, tr("Activer la double authentification maintenant"), tr("Un code à 6 chiffres de votre téléphone sera demandé à chaque connexion."));
                        option(ui, &mut w.import, tr("Importer des mots de passe existants"), tr("Depuis un export CSV de Chrome, Bitwarden, KeePass ou 1Password."));
                        theme::hline(ui);
                        ui.add_space(16.0);
                        ui.label(theme::bold(tr("Récapitulatif")));
                        ui.add_space(4.0);
                        summary_row(ui, tr("Profil"), RichText::new(w.name.trim()));
                        let (txt, _) = strength(pwgen::score(&w.pw));
                        summary_row(
                            ui,
                            tr("Mot de passe maître"),
                            RichText::new(format!("{} · {} {txt}", tr("{n} caractères").replace("{n}", &w.pw.chars().count().to_string()), tr("robustesse"))),
                        );
                        summary_row(
                            ui,
                            tr("Clé secrète"),
                            if w.use_key { RichText::new(w.key_path.trim()).monospace() } else { RichText::new(tr("Aucune (mot de passe seul)")) },
                        );
                        summary_row(ui, tr("Protection"), RichText::new("Argon2id 64 Mo · XChaCha20-Poly1305"));
                    }
                });
            });

            theme::hline(ui);
            ui.add_space(12.0);
            theme::error(ui, &w.err);
            ui.horizontal(|ui| {
                if w.step > 0 && ui.add(egui::Button::new(tr("Retour")).min_size(Vec2::new(0.0, 40.0))).clicked() {
                    w.step -= 1;
                    w.err.clear();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let last = w.step + 1 == STEPS;
                    let label = if last { tr("Créer le coffre") } else { tr("Continuer") };
                    let go = ui
                        .add(egui::Button::new(theme::bold(label).color(theme::on_accent())).fill(theme::accent()).stroke(Stroke::NONE).min_size(Vec2::new(140.0, 40.0)))
                        .clicked()
                        || ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if go {
                        match validate(w, cfg) {
                            Some(e) => w.err = e.into(),
                            None if last => match create(w, cfg, sel) {
                                Ok(screen) => next = Some(screen),
                                Err(e) => w.err = e,
                            },
                            None => {
                                w.err.clear();
                                w.step += 1;
                            }
                        }
                    }
                });
            });
        });
    next
}
