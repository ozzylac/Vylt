//! The "Paramètres" tab.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use vylt::hidden::{self, OpenBox};
use vylt::vault::{KdfParams, SecretKey, Vault};
use vylt::destroy::{self, Arm, Verifier};
use vylt::{decoy, import, otp, transfer};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{self, now_secs, Config};
use crate::i18n::tr;
use crate::platform;
use crate::pwgen;
use crate::session::*;
use crate::theme;
use crate::ui_common::*;

const LOCK_CHOICES: [(u64, &str); 7] = [
    (30, "30 secondes"),
    (60, "1 minute"),
    (120, "2 minutes"),
    (300, "5 minutes"),
    (600, "10 minutes"),
    (1800, "30 minutes"),
    (3600, "1 heure"),
];
const CLIP_CHOICES: [(u64, &str); 5] = [(5, "5 s"), (10, "10 s"), (15, "15 s"), (30, "30 s"), (60, "60 s")];
const KDF_LEVELS: [(&str, KdfParams); 3] = [
    ("Standard — 64 Mo, 3 passes", KdfParams { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 1 }),
    ("Élevé — 256 Mo, 4 passes", KdfParams { m_cost_kib: 256 * 1024, t_cost: 4, p_cost: 1 }),
    ("Maximum — 512 Mo, 5 passes", KdfParams { m_cost_kib: 512 * 1024, t_cost: 5, p_cost: 1 }),
];

const TRANSFER_DELAY: Duration = Duration::from_secs(30);

const ALL: [Section; 11] = [
    Section::Perso,
    Section::Appearance,
    Section::Session,
    Section::Master,
    Section::Tfa,
    Section::Hidden,
    Section::Decoy,
    Section::Transfer,
    Section::Passkeys,
    Section::Portable,
    Section::Destroy,
];
/// A decoy session only exposes harmless settings.
const DECOY: [Section; 2] = [Section::Appearance, Section::Session];

fn section_label(sec: Section) -> &'static str {
    match sec {
        Section::Perso => tr("Personnalisation"),
        Section::Appearance => tr("Apparence"),
        Section::Session => tr("Sécurité de session"),
        Section::Master => tr("Mot de passe maître"),
        Section::Tfa => tr("Double authentification"),
        Section::Hidden => tr("Catégories cachées"),
        Section::Decoy => tr("Mode contrainte"),
        Section::Transfer => tr("Import et transfert"),
        Section::Passkeys => tr("Clés d'accès"),
        Section::Portable => if config::portable_root().is_some() { tr("Mode fixe") } else { tr("Mode portable") },
        Section::Destroy => tr("Destruction des données"),
    }
}

pub fn settings_tab(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config, lock: &mut bool) {
    let sections: &[Section] = if s.is_decoy { &DECOY } else { &ALL };
    if !sections.contains(&s.st.section) {
        s.st.section = sections[0];
    }

    egui::Panel::left("settings-nav")
        .exact_size(220.0)
        .resizable(false)
        .frame(egui::Frame::new().fill(theme::panel()).inner_margin(egui::Margin::symmetric(10, 16)))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for &sec in sections {
                let danger = sec == Section::Destroy;
                if danger {
                    ui.add_space(6.0);
                    theme::hline(ui);
                    ui.add_space(6.0);
                }
                let on = s.st.section == sec;
                let color = if danger { theme::danger() } else if on { theme::text() } else { theme::dim() };
                let text = if on { theme::bold(section_label(sec)).color(color) } else { RichText::new(section_label(sec)).color(color) };
                let fill = if !on { egui::Color32::TRANSPARENT } else if danger { theme::danger().linear_multiply(0.12) } else { theme::selected_fill() };
                let r = egui::Frame::new()
                    .fill(fill)
                    .corner_radius(8)
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(text);
                    })
                    .response
                    .interact(egui::Sense::click());
                if r.clicked() {
                    s.st.section = sec;
                }
            }
        });

    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(theme::bg()).inner_margin(egui::Margin::symmetric(36, 24)))
        .show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.set_max_width(760.0);
                theme::title(ui, section_label(s.st.section));
                theme::label(
                    ui,
                    &format!("{} : {} — {}", tr("Profil"), s.profile.name, tr("ces réglages sont propres à ce profil et stockés dans son coffre chiffré.")),
                );
                ui.add_space(6.0);
                match s.st.section {
                    Section::Perso => perso_card(ui, s, cfg),
                    Section::Appearance => appearance_card(ui, cfg),
                    Section::Session => timers_card(ui, s),
                    Section::Master => {
                        password_card(ui, s, cfg);
                        info_card(ui, s, lock);
                        update_card(ui);
                    }
                    Section::Tfa => tfa_card(ui, s),
                    Section::Hidden => hidden_card(ui, s),
                    Section::Decoy => decoy_card(ui, s, cfg),
                    Section::Transfer => {
                        import_card(ui, s);
                        transfer_card(ui, s, lock);
                    }
                    Section::Passkeys => passkeys_card(ui, s, cfg),
                    Section::Portable => portable_card(ui, s, cfg),
                    Section::Destroy => {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 22.0;
                            if theme::tab(ui, s.st.dest_tab == 0, tr("Mots de passe")).clicked() {
                                s.st.dest_tab = 0;
                            }
                            if theme::tab(ui, s.st.dest_tab == 1, tr("Profils liés")).clicked() {
                                s.st.dest_tab = 1;
                            }
                            if theme::tab(ui, s.st.dest_tab == 2, tr("Actions après effacement")).clicked() {
                                s.st.dest_tab = 2;
                            }
                        });
                        match s.st.dest_tab {
                            0 => destroy_card(ui, s, cfg),
                            1 => links_card(ui, s, cfg),
                            _ => actions_card(ui, s, cfg),
                        }
                    }
                }
            });
        });

    if let Some(a) = s.st.preview.clone()
        && crate::show_alert(ui.ctx(), &a)
    {
        s.st.preview = None;
    }
}

fn appearance_card(ui: &mut egui::Ui, cfg: &mut Config) {
    row(ui, tr("Langue et thème"), "", |ui| appearance_bar(ui, cfg));
    row(ui, tr("Couleur d'accent"), tr("Boutons principaux, sélection et éléments actifs. Commune à tous les profils."), |ui| {
        ui.horizontal(|ui| {
            for i in 0..theme::ACCENTS.len() as u8 {
                let (rect, r) = ui.allocate_exact_size(egui::vec2(32.0, 32.0), egui::Sense::click());
                ui.painter().circle_filled(rect.center(), 12.0, theme::accent_of(i));
                if theme::accent_index() == i {
                    ui.painter().circle_stroke(rect.center(), 15.0, egui::Stroke::new(2.0, theme::text()));
                }
                if r.clicked() {
                    cfg.accent = i;
                    theme::set_accent(i);
                    theme::apply(ui.ctx(), cfg.dark);
                    config::save(cfg);
                }
            }
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let _ = theme::primary(ui, tr("Aperçu du bouton"));
            theme::check(ui, theme::accent());
            ui.label(RichText::new(tr("Élément actif")).color(theme::accent()));
        });
    });
    theme::hline(ui);
}

/// Left column: title + description; right: the control.
fn row(ui: &mut egui::Ui, title: &str, desc: &str, add: impl FnOnce(&mut egui::Ui)) {
    theme::hline(ui);
    ui.add_space(6.0);
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(egui::vec2(220.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.set_width(220.0);
            ui.label(theme::bold(title));
            if !desc.is_empty() {
                theme::label(ui, desc);
            }
        });
        ui.add_space(20.0);
        ui.vertical(|ui| add(ui));
    });
    ui.add_space(8.0);
}

fn profile_index(s: &Session, cfg: &Config) -> Option<usize> {
    cfg.profiles.iter().position(|p| p.vault_path == s.profile.vault_path)
}

fn perso_card(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config) {
    let Some(idx) = profile_index(s, cfg) else { return };
    theme::label(ui, tr("Apparence du profil sur l'écran de connexion et dans la barre supérieure."));
    ui.add_space(6.0);

    let mut changed = false;
    row(
        ui,
        tr("Photo de profil"),
        tr("PNG ou JPG, recadrée en carré. Stockée en clair à côté de la configuration, car elle s'affiche avant le déverrouillage."),
        |ui| {
            ui.horizontal(|ui| {
                let p = &cfg.profiles[idx];
                theme::avatar(ui, &p.name, p.color, p.avatar.as_deref(), 72.0);
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        if ui.button(tr("Choisir une image…")).clicked() {
                            let pick = rfd::FileDialog::new().add_filter("Image", &["png", "jpg", "jpeg"]).pick_file();
                            if let Some(src) = pick {
                                match config::save_avatar(&src, &cfg.profiles[idx].name) {
                                    Ok(out) => {
                                        config::remove_avatar(&cfg.profiles[idx]);
                                        if let Some(old) = cfg.profiles[idx].avatar.replace(out) {
                                            theme::forget_avatar(&old);
                                        }
                                        changed = true;
                                        s.st.perso_msg = tr("Photo enregistrée.").into();
                                    }
                                    Err(_) => s.st.perso_msg = tr("Image illisible.").into(),
                                }
                            }
                        }
                        if cfg.profiles[idx].avatar.is_some() && theme::danger_button(ui, tr("Retirer")).clicked() {
                            config::remove_avatar(&cfg.profiles[idx]);
                            if let Some(old) = cfg.profiles[idx].avatar.take() {
                                theme::forget_avatar(&old);
                            }
                            changed = true;
                        }
                    });
                    theme::label(ui, tr("Sans photo, les initiales sont affichées."));
                });
            });
            ui.add_space(8.0);
            theme::label(ui, tr("Images proposées (fonds d'écran Bing de ce PC)"));
            if let Some(src) = crate::gallery::picker(ui, None) {
                match config::save_avatar(&src, &cfg.profiles[idx].name) {
                    Ok(out) => {
                        config::remove_avatar(&cfg.profiles[idx]);
                        if let Some(old) = cfg.profiles[idx].avatar.replace(out) {
                            theme::forget_avatar(&old);
                        }
                        changed = true;
                        s.st.perso_msg = tr("Photo enregistrée.").into();
                    }
                    Err(_) => s.st.perso_msg = tr("Image illisible.").into(),
                }
            }
        },
    );

    row(ui, tr("Nom affiché"), tr("Visible sur l'écran de connexion."), |ui| {
        let current = cfg.profiles[idx].name.clone();
        let name = s.st.name_edit.get_or_insert(current.clone());
        ui.add(egui::TextEdit::singleline(name).desired_width(320.0));
        if ui.add_enabled(name.trim() != current, egui::Button::new(tr("Enregistrer"))).clicked() {
            let clean = name.trim().to_owned();
            let taken = cfg
                .profiles
                .iter()
                .enumerate()
                .any(|(i, p)| i != idx && config::folder_name(&p.name) == config::folder_name(&clean));
            s.st.perso_msg = if let Some(i) = config::name_issue(&clean) {
                name_issue_text(&i).into()
            } else if taken {
                tr("Un profil de ce nom existe déjà.").into()
            } else {
                cfg.profiles[idx].name = clean.clone();
                s.profile.name = clean.clone();
                *name = clean;
                changed = true;
                tr("Nom enregistré.").into()
            };
        }
    });

    row(ui, tr("Couleur des initiales"), tr("Utilisée sans photo."), |ui| {
        ui.horizontal(|ui| {
            for i in 0..theme::AVATAR_COLORS.len() as u8 {
                let (rect, r) = ui.allocate_exact_size(egui::vec2(30.0, 30.0), egui::Sense::click());
                let (bg, _) = theme::avatar_colors(i);
                ui.painter().circle_filled(rect.center(), 12.0, bg);
                if cfg.profiles[idx].color == i {
                    ui.painter().circle_stroke(rect.center(), 14.5, egui::Stroke::new(2.0, theme::accent()));
                }
                if r.clicked() {
                    cfg.profiles[idx].color = i;
                    changed = true;
                }
            }
        });
    });

    row(ui, tr("Aperçu"), "", |ui| {
        let p = &cfg.profiles[idx];
        egui::Frame::new().fill(theme::selected_fill()).inner_margin(egui::Margin::symmetric(10, 8)).show(ui, |ui| {
            ui.set_width(320.0);
            ui.horizontal(|ui| {
                theme::avatar(ui, &p.name, p.color, p.avatar.as_deref(), 30.0);
                ui.label(theme::bold(&p.name));
            });
        });
    });
    theme::hline(ui);

    if changed {
        s.profile = cfg.profiles[idx].clone();
        config::save(cfg);
    }
    if !s.st.perso_msg.is_empty() {
        ui.add_space(6.0);
        ui.label(RichText::new(&s.st.perso_msg).color(theme::accent()));
    }
}

/// (template label, title, body) — the pre-written messages.
fn templates() -> [(&'static str, &'static str, &'static str); 3] {
    [
        (
            tr("Session corrompue"),
            tr("Erreur de lecture du profil"),
            tr("Le fichier de session est corrompu (code 0x8007045D). Les données n'ont pas pu être chargées."),
        ),
        (tr("Profil introuvable"), tr("Profil introuvable"), tr("Le profil sélectionné n'existe plus sur cet ordinateur ou a été déplacé.")),
        (
            tr("Mise à jour requise"),
            tr("Mise à jour requise"),
            tr("Cette version de Vylt n'est plus compatible avec le format du profil. Installez la dernière version pour continuer."),
        ),
    ]
}

fn default_actions() -> destroy::Actions {
    let (_, title, body) = templates()[0];
    destroy::Actions { show_message: true, title: title.into(), body: body.into(), ..Default::default() }
}

fn actions_card(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config) {
    let Some(idx) = profile_index(s, cfg) else { return };
    ui.add_space(8.0);
    theme::label(ui, tr("Exécutées immédiatement après l'effacement par le mot de passe de destruction de ce profil, dans cet ordre."));
    let Some(verifier) = cfg.profiles[idx].destruct.clone() else {
        ui.add_space(6.0);
        ui.label(RichText::new(tr("Définissez d'abord un mot de passe de destruction dans l'onglet « Mots de passe ».")).color(theme::accent()));
        return;
    };

    if s.st.act.is_none() {
        ui.add_space(6.0);
        theme::label(ui, tr("Mot de passe de destruction"));
        let r = ui.add(egui::TextEdit::singleline(&mut *s.st.act_pw).password(true).desired_width(320.0));
        no_history(ui, &r);
        if theme::primary(ui, tr("Afficher les actions")).clicked() {
            if verifier.check(&s.st.act_pw) {
                let saved = cfg.profiles[idx].actions.as_ref().and_then(|a| destroy::open_actions(a, &s.st.act_pw));
                s.st.act = Some(saved.unwrap_or_else(default_actions));
                s.st.act_msg.clear();
            } else {
                s.st.act_pw.zeroize();
                s.st.act_msg = tr("Mot de passe de destruction incorrect.").into();
            }
        }
        if !s.st.act_msg.is_empty() {
            ui.label(RichText::new(&s.st.act_msg).color(theme::danger()));
        }
        return;
    }

    let mut save = false;
    let mut clear = false;
    let mut preview = None;
    if let Some(a) = s.st.act.as_mut() {
        row(ui, tr("Afficher un message"), tr("Fenêtre d'erreur affichée à la place de l'écran de connexion."), |ui| {
            ui.checkbox(&mut a.show_message, tr("Activé"));
            if a.show_message {
                theme::label(ui, tr("Modèle"));
                let current = templates().iter().find(|t| t.1 == a.title && t.2 == a.body).map_or(tr("Message personnalisé"), |t| t.0);
                egui::ComboBox::from_id_salt("tpl").selected_text(current).width(320.0).show_ui(ui, |ui| {
                    for (label, title, body) in templates() {
                        if ui.selectable_label(current == label, label).clicked() {
                            a.title = title.into();
                            a.body = body.into();
                        }
                    }
                });
                theme::label(ui, tr("Titre"));
                ui.add(egui::TextEdit::singleline(&mut a.title).desired_width(f32::INFINITY));
                theme::label(ui, tr("Texte"));
                ui.add(egui::TextEdit::multiline(&mut a.body).desired_rows(3).desired_width(f32::INFINITY));
            }
        });
        row(ui, tr("Lancer une commande"), tr("Programme exécuté en arrière-plan, sans fenêtre ni interpréteur de commandes."), |ui| {
            ui.checkbox(&mut a.run, tr("Activé"));
            if a.run {
                theme::label(ui, tr("Programme"));
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut a.program).font(egui::TextStyle::Monospace).desired_width(360.0));
                    if ui.button(tr("Parcourir…")).clicked()
                        && let Some(p) = rfd::FileDialog::new().add_filter("Programme", &["exe"]).pick_file()
                    {
                        a.program = p.to_string_lossy().into_owned();
                    }
                });
                theme::label(ui, tr("Arguments"));
                ui.add(egui::TextEdit::singleline(&mut a.args).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                ui.label(RichText::new(tr("Chiffrée avec le mot de passe de destruction : illisible et non modifiable sans lui.")).size(12.0).color(theme::accent()));
            }
        });
        row(ui, tr("Fermer l'application"), tr("Après le message, ou immédiatement s'il n'y en a pas."), |ui| {
            ui.checkbox(&mut a.close_app, tr("Activé"));
        });
        theme::hline(ui);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            save = theme::primary(ui, tr("Enregistrer")).clicked();
            if a.show_message && ui.button(tr("Aperçu du message")).clicked() {
                preview = Some(Alert { title: a.title.clone(), body: a.body.clone(), close_app: false, info: false, code: String::new() });
            }
            if cfg.profiles[idx].actions.is_some() {
                clear = theme::danger_button(ui, tr("Supprimer les actions")).clicked();
            }
        });
    }
    if preview.is_some() {
        s.st.preview = preview;
    }
    if save {
        let sealed = s.st.act.as_ref().filter(|_| verifier.check(&s.st.act_pw)).and_then(|a| destroy::seal_actions(a, &s.st.act_pw).ok());
        s.st.act_msg = match sealed {
            Some(x) => {
                cfg.profiles[idx].actions = Some(x);
                config::save(cfg);
                tr("Actions enregistrées.").into()
            }
            None => tr("Échec").into(),
        };
    } else if clear {
        cfg.profiles[idx].actions = None;
        config::save(cfg);
        s.st.act = None;
        s.st.act_pw.zeroize();
        s.st.act_msg = tr("Actions supprimées.").into();
    }
    if s.st.act.is_some() && !s.st.act_msg.is_empty() {
        ui.label(RichText::new(&s.st.act_msg).color(theme::accent()));
    }
}

fn timers_card(ui: &mut egui::Ui, s: &mut Session) {
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Sécurité de session"));
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label(tr("Verrouillage automatique après"));
            let cur = LOCK_CHOICES.iter().find(|c| c.0 == s.vault.settings.auto_lock_secs).map_or(tr("personnalisé"), |c| tr(c.1));
            egui::ComboBox::from_id_salt("autolock").selected_text(cur).show_ui(ui, |ui| {
                for (v, name) in LOCK_CHOICES {
                    changed |= ui.selectable_value(&mut s.vault.settings.auto_lock_secs, v, tr(name)).changed();
                }
            });
            ui.label(tr("d'inactivité"));
        });
        ui.horizontal(|ui| {
            ui.label(tr("Effacer le presse-papier après"));
            let cur = CLIP_CHOICES.iter().find(|c| c.0 == s.vault.settings.clipboard_secs).map_or(tr("personnalisé"), |c| c.1);
            egui::ComboBox::from_id_salt("clip").selected_text(cur).show_ui(ui, |ui| {
                for (v, name) in CLIP_CHOICES {
                    changed |= ui.selectable_value(&mut s.vault.settings.clipboard_secs, v, name).changed();
                }
            });
        });
        theme::label(ui, tr("Le coffre se verrouille aussi quand Windows verrouille la session ou passe en veille."));
        if changed {
            s.persist();
            s.say(tr("Réglage enregistré"));
        }
    });
}

fn tfa_card(ui: &mut egui::Ui, s: &mut Session) {
    theme::card(ui, |ui| {
        if decoy::has_decoy(&s.profile.vault_path) {
            theme::label(ui, tr("Le mode contrainte est actif : recréez-le après avoir modifié la double authentification, pour qu'il demande le même code."));
        }
        theme::heading(ui, tr("Authentification à deux facteurs (2FA) au déverrouillage"));
        theme::label(ui, tr("Compatible Google Authenticator, Microsoft Authenticator, Authy, 2FAS, Aegis… sur iPhone et Android."));
        if s.vault.unlock_totp.is_some() {
            ui.label(RichText::new(tr("2FA activée")).color(theme::ok()));
            theme::label(ui, tr("Code actuel requis pour la désactiver"));
            ui.add(egui::TextEdit::singleline(&mut s.st.tfa_code).char_limit(7).desired_width(160.0));
            if theme::danger_button(ui, tr("Désactiver la 2FA")).clicked() {
                let ok = s.vault.unlock_totp.as_ref().is_some_and(|k| otp::verify(k, &s.st.tfa_code));
                s.st.tfa_code.clear();
                if ok {
                    s.vault.unlock_totp = None;
                    s.persist();
                    s.say(tr("2FA désactivée"));
                } else {
                    s.say(tr("Code invalide"));
                }
            }
        } else if let Some(t) = s.st.tfa_setup.as_mut() {
            ui.label(tr("1. Scannez ce QR code avec votre application, ou saisissez la clé manuellement :"));
            if let Some((w, dark)) = otp::qr_matrix(&t.uri) {
                theme::qr(ui, w, &dark, 5.0);
            }
            let grouped: Vec<String> = t.key.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
            ui.label(RichText::new(grouped.join(" ")).monospace().size(15.0).color(theme::accent()));
            ui.label(tr("2. Saisissez le code affiché par l'application pour confirmer :"));
            ui.add(egui::TextEdit::singleline(&mut t.confirm).char_limit(7).desired_width(160.0));
            theme::error(ui, &t.err);
            let (mut done, mut cancel) = (false, false);
            ui.horizontal(|ui| {
                if theme::primary(ui, tr("Confirmer et activer")).clicked() {
                    if otp::verify(&t.key, &t.confirm) {
                        done = true;
                    } else {
                        t.err = tr("Code invalide, veuillez réessayer.").into();
                    }
                }
                cancel = ui.button(tr("Annuler")).clicked();
            });
            if done {
                if let Some(t) = s.st.tfa_setup.take() {
                    s.vault.unlock_totp = Some(t.key.clone());
                    s.persist();
                    s.say(tr("2FA activée"));
                }
            } else if cancel {
                s.st.tfa_setup = None;
            }
        } else if theme::primary(ui, tr("Activer la 2FA")).clicked() {
            let key = otp::new_unlock_key();
            if let Some(uri) = otp::provisioning_uri(&key, &s.profile.name) {
                s.st.tfa_setup =
                    Some(TfaSetup { key: Zeroizing::new(key), uri: Zeroizing::new(uri), confirm: String::new(), err: String::new() });
            }
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new(tr("Important : le code 2FA est une barrière de l'application. Le chiffrement du coffre repose sur le mot de passe maître + la clé secrète (fichier)."))
                .size(12.0)
                .color(theme::dim()),
        );
    });
}

/// The typed secret opens this profile's vault or its decoy.
fn opens_this_profile(s: &Session, pw: &str) -> bool {
    s.profile.secret_key().is_ok_and(|sk| decoy::open_either(&s.profile.vault_path, pw, &sk).is_ok())
}

fn password_card(ui: &mut egui::Ui, s: &mut Session, cfg: &Config) {
    if !s.st.kdf_synced {
        let m = s.vault.kdf().m_cost_kib;
        s.st.kdf_level = KDF_LEVELS.iter().rposition(|(_, k)| k.m_cost_kib <= m).unwrap_or(0);
        s.st.kdf_synced = true;
    }
    let tfa = s.vault.unlock_totp.clone();
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Mot de passe maître et protection"));
        theme::label(ui, tr("Mot de passe maître actuel"));
        password_field(ui, &mut s.st.cur_pw, "");
        if tfa.is_some() {
            theme::label(ui, tr("Code de double authentification"));
            ui.add(egui::TextEdit::singleline(&mut s.st.cur_code).char_limit(7).hint_text("000000").desired_width(140.0));
        }
        theme::label(ui, tr("Nouveau mot de passe maître (12 caractères minimum)"));
        password_field(ui, &mut s.st.new_pw, "");
        theme::label(ui, tr("Confirmation"));
        password_field(ui, &mut s.st.new_pw2, "");
        theme::label(ui, tr("Niveau de protection contre le craquage (plus élevé = déverrouillage plus lent)"));
        egui::ComboBox::from_id_salt("kdf").selected_text(tr(KDF_LEVELS[s.st.kdf_level].0)).show_ui(ui, |ui| {
            for (i, (name, _)) in KDF_LEVELS.iter().enumerate() {
                ui.selectable_value(&mut s.st.kdf_level, i, tr(name));
            }
        });
        if !s.st.msg.is_empty() {
            ui.label(RichText::new(&s.st.msg).color(theme::accent()));
        }
        if theme::primary(ui, tr("Appliquer")).clicked() {
            let cur = s.st.cur_pw.clone();
            s.st.cur_pw.zeroize();
            let step = tfa.as_ref().map(|k| otp::verify_step(k, &s.st.cur_code).filter(|&st| st > s.vault.last_totp_step));
            s.st.cur_code.clear();
            s.st.msg = if verify_master(s, &cur).is_none() {
                tr("Mot de passe maître incorrect.").into()
            } else if step.is_some_and(|st| st.is_none()) {
                tr("Code invalide").into()
            } else if s.st.new_pw.chars().count() < 12 {
                tr("12 caractères minimum.").into()
            } else if *s.st.new_pw != *s.st.new_pw2 {
                tr("Les mots de passe diffèrent.").into()
            } else if config::is_erase_secret(cfg, &s.profile.name, &s.st.new_pw) {
                tr("Ce mot de passe est déjà un mot de passe de destruction ou la clé globale.").into()
            } else if decoy::has_decoy(&s.profile.vault_path)
                && s.profile.secret_key().is_ok_and(|sk| Vault::open(&decoy::decoy_path(&s.profile.vault_path), &s.st.new_pw, &sk).is_ok())
            {
                tr("Ce mot de passe ouvre déjà le faux coffre.").into()
            } else {
                if let Some(Some(st)) = step {
                    s.vault.last_totp_step = st;
                }
                let kdf = KDF_LEVELS[s.st.kdf_level].1;
                let pw = s.st.new_pw.clone();
                match s.profile.secret_key().and_then(|sk| {
                    s.vault.set_kdf(kdf)?;
                    s.vault.change_password(&pw, &sk)
                }) {
                    Ok(()) => {
                        s.st.new_pw.zeroize();
                        s.st.new_pw2.zeroize();
                        s.say(tr("Mot de passe maître modifié"));
                        String::new()
                    }
                    Err(e) => format!("{} : {e}", tr("Échec")),
                }
            };
        }
    });
}

fn hidden_card(ui: &mut egui::Ui, s: &mut Session) {
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Catégories cachées"));
        theme::label(
            ui,
            tr("Un ensemble d'entrées chiffré avec son propre mot de passe. Même avec le mot de passe maître, il reste invisible et illisible."),
        );
        theme::label(ui, tr("Pour en ouvrir une : Ctrl+Maj+H dans l'onglet Coffre, puis saisissez son mot de passe. Aucune liste n'est affichée."));
        theme::label(ui, tr("En cas d'oubli de son mot de passe, son contenu est définitivement perdu."));
        theme::label(ui, tr("Nom de la catégorie"));
        ui.add(egui::TextEdit::singleline(&mut s.st.hid_name).desired_width(f32::INFINITY));
        theme::label(ui, tr("Mot de passe de la catégorie (12 caractères minimum)"));
        password_field(ui, &mut s.st.hid_pw, "");
        theme::label(ui, tr("Confirmation"));
        password_field(ui, &mut s.st.hid_pw2, "");
        if !s.st.hid_msg.is_empty() {
            ui.label(RichText::new(&s.st.hid_msg).color(theme::accent()));
        }
        if theme::primary(ui, tr("Créer la catégorie cachée")).clicked() {
            let name = s.st.hid_name.trim().to_owned();
            s.st.hid_msg = if name.is_empty() {
                tr("Veuillez saisir un nom de catégorie.").into()
            } else if s.st.hid_pw.chars().count() < hidden::MIN_PASSWORD_CHARS {
                tr("12 caractères minimum.").into()
            } else if *s.st.hid_pw != *s.st.hid_pw2 {
                tr("Les mots de passe diffèrent.").into()
            } else {
                match OpenBox::create(&name, &s.st.hid_pw, hidden::KDF).and_then(|b| b.seal().map(|sb| (b, sb))) {
                    Ok((b, sealed)) => {
                        let id = b.id;
                        hidden::upsert(&mut s.vault.hidden, sealed);
                        s.open.push(b);
                        s.st.hid_pw.zeroize();
                        s.st.hid_pw2.zeroize();
                        s.st.hid_name.clear();
                        s.switch_view(View::Hidden(id));
                        s.tab = Tab::Vault;
                        s.persist();
                        s.say(tr("Catégorie cachée créée et ouverte"));
                        String::new()
                    }
                    Err(e) => e.to_string(),
                }
            };
        }
    });
}

/// Destruction › Linked profiles: each person types the other's identifier in their own profile.
fn links_card(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config) {
    let me = config::pid(&s.profile);
    let Some(idx) = cfg.profiles.iter().position(|p| config::pid(p) == me) else { return };
    if s.vault.settings.link_id.is_empty() || cfg.profiles[idx].link_check.is_none() {
        if s.vault.settings.link_id.is_empty() {
            s.vault.settings.link_id = config::new_link_id();
            s.persist();
        }
        cfg.profiles[idx].link_check = Verifier::new(&config::link_code(&s.vault.settings.link_id)).ok();
        config::save(cfg);
    }
    theme::label(ui, tr("La destruction globale ne concerne que des profils liés entre eux. Chaque personne communique son identifiant de liaison à l'autre, qui le saisit dans son propre profil : la liaison n'existe que lorsque les deux l'ont fait."));
    ui.add_space(6.0);

    row(ui, tr("Votre identifiant de liaison"), tr("Secret, visible seulement une fois ce profil déverrouillé. À ne donner qu'aux personnes concernées."), |ui| {
        ui.horizontal(|ui| {
            let shown = if s.st.link_shown { s.vault.settings.link_id.clone() } else { "SV-••••-••••-••••".into() };
            ui.label(RichText::new(shown).monospace().size(15.0));
            if ui.button(if s.st.link_shown { tr("Masquer") } else { tr("Afficher") }).clicked() {
                s.st.link_shown = !s.st.link_shown;
            }
            if ui.button(tr("Copier")).clicked() {
                let id = s.vault.settings.link_id.clone();
                s.copy(&id, tr("Identifiant de liaison"));
            }
            if ui.button(tr("Régénérer")).clicked() {
                s.vault.settings.link_id = config::new_link_id();
                s.persist();
                cfg.profiles[idx].link_check = Verifier::new(&config::link_code(&s.vault.settings.link_id)).ok();
                // Old confirmations of this profile no longer count: the others must link again.
                for p in cfg.profiles.iter_mut() {
                    p.links.retain(|l| *l != me);
                }
                config::save(cfg);
                s.st.link_msg = tr("Nouvel identifiant créé. Les profils liés doivent saisir le nouvel identifiant.").into();
            }
        });
    });

    let others: Vec<(String, String)> = cfg.profiles.iter().filter(|p| config::pid(p) != me).map(|p| (config::pid(p), p.name.clone())).collect();
    row(ui, tr("Lier un profil"), tr("Saisissez l'identifiant que l'autre personne vous a communiqué."), |ui| {
        if others.is_empty() {
            theme::label(ui, tr("Aucun autre profil sur cet ordinateur."));
            return;
        }
        if !others.iter().any(|(id, _)| *id == s.st.link_target) {
            s.st.link_target = others[0].0.clone();
        }
        ui.horizontal(|ui| {
            let current = others.iter().find(|(id, _)| *id == s.st.link_target).map(|(_, n)| n.clone()).unwrap_or_default();
            egui::ComboBox::from_id_salt("link-target").selected_text(current).show_ui(ui, |ui| {
                for (id, name) in &others {
                    ui.selectable_value(&mut s.st.link_target, id.clone(), name);
                }
            });
            ui.add(egui::TextEdit::singleline(&mut s.st.link_input).font(egui::TextStyle::Monospace).hint_text("SV-XXXX-XXXX-XXXX").desired_width(200.0));
            if theme::primary(ui, tr("Lier")).clicked() {
                let code = config::link_code(&s.st.link_input);
                let target = s.st.link_target.clone();
                let ok = cfg.profiles.iter().find(|p| config::pid(p) == target).and_then(|p| p.link_check.as_ref()).is_some_and(|v| v.check(&code));
                s.st.link_input.clear();
                s.st.link_msg = if ok {
                    if !cfg.profiles[idx].links.contains(&target) {
                        cfg.profiles[idx].links.push(target);
                    }
                    config::save(cfg);
                    tr("Profil lié de votre côté.").into()
                } else {
                    tr("Identifiant incorrect.").into()
                };
            }
        });
    });

    row(ui, tr("Profils liés"), "", |ui| {
        let mut drop: Option<String> = None;
        let mut any = false;
        for (id, name) in &others {
            let mine = cfg.profiles[idx].links.contains(id);
            let theirs = cfg.profiles.iter().find(|p| config::pid(p) == *id).is_some_and(|p| p.links.contains(&me));
            if !mine && !theirs {
                continue;
            }
            any = true;
            ui.horizontal(|ui| {
                let (color, text) = match (mine, theirs) {
                    (true, true) => (theme::ok(), tr("liaison confirmée des deux côtés").to_owned()),
                    (true, false) => (theme::accent(), tr("en attente : {name} doit saisir votre identifiant dans son profil").replace("{name}", name)),
                    _ => (theme::accent(), tr("{name} vous a lié : saisissez son identifiant pour confirmer").replace("{name}", name)),
                };
                ui.label(RichText::new("●").color(color));
                ui.label(theme::bold(name));
                ui.label(RichText::new(format!("— {text}")).color(theme::dim()));
                if mine && theme::danger_button(ui, if theirs { tr("Délier") } else { tr("Annuler") }).clicked() {
                    drop = Some(id.clone());
                }
            });
        }
        if !any {
            theme::label(ui, tr("Aucun profil lié."));
        }
        if let Some(id) = drop {
            cfg.profiles[idx].links.retain(|l| *l != id);
            config::save(cfg);
        }
    });

    row(ui, tr("Destruction globale"), tr("Activée par deux profils liés qui saisissent la même clé."), |ui| {
        if cfg.global_destruct.is_some() && !cfg.global_members.is_empty() {
            let mut names: Vec<String> = Vec::new();
            for m in &cfg.global_members {
                for id in config::group(cfg, m) {
                    if let Some(p) = cfg.profiles.iter().find(|p| config::pid(p) == id)
                        && !names.contains(&p.name)
                    {
                        names.push(p.name.clone());
                    }
                }
            }
            ui.label(RichText::new(format!("{} — {} {}", tr("Active"), tr("efface :"), names.join(", "))).color(theme::ok()));
        } else {
            ui.label(RichText::new(tr("Inactive")).color(theme::dim()));
        }
        theme::label(ui, tr("Les profils non liés ne sont jamais effacés par cette clé. Un profil créé par quelqu'un d'autre ne peut pas s'y ajouter sans votre identifiant."));
    });
    if !s.st.link_msg.is_empty() {
        ui.label(RichText::new(&s.st.link_msg).color(theme::accent()));
    }
}

fn verify_master(s: &Session, real: &str) -> Option<SecretKey> {
    let sk = s.profile.secret_key().ok()?;
    Vault::open(&s.profile.vault_path, real, &sk).ok().map(|_| sk)
}

fn decoy_card(ui: &mut egui::Ui, s: &mut Session, cfg: &Config) {
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Mode contrainte (faux coffre)"));
        theme::label(
            ui,
            tr("Un second mot de passe ouvre un faux coffre inoffensif, à utiliser en cas de contrainte à déverrouiller devant l'écran. Pour le remplir, connectez-vous avec ce mot de passe."),
        );
        ui.label(
            RichText::new(tr("Limite : le faux coffre est un fichier visible sur le disque (pas de déni plausible face à une analyse du disque). Il demande la même double authentification que le vrai coffre au moment de sa création."))
                .size(12.0)
                .color(theme::dim()),
        );
        let exists = decoy::has_decoy(&s.profile.vault_path);
        theme::label(ui, tr("Mot de passe maître actuel"));
        password_field(ui, &mut s.st.decoy_real, "");
        if !exists {
            theme::label(ui, tr("Mot de passe de contrainte (12 caractères minimum, différent du mot de passe maître)"));
            password_field(ui, &mut s.st.decoy_pw, "");
            theme::label(ui, tr("Confirmation"));
            password_field(ui, &mut s.st.decoy_pw2, "");
        } else {
            ui.label(RichText::new(tr("Mode contrainte activé")).color(theme::ok()));
        }
        if !s.st.decoy_msg.is_empty() {
            ui.label(RichText::new(&s.st.decoy_msg).color(theme::accent()));
        }
        let clicked = if exists { theme::danger_button(ui, tr("Supprimer le faux coffre")).clicked() } else { theme::primary(ui, tr("Activer le mode contrainte")).clicked() };
        if clicked {
            let real = s.st.decoy_real.clone();
            s.st.decoy_msg = match verify_master(s, &real) {
                None => tr("Mot de passe maître incorrect.").into(),
                Some(_) if exists => match decoy::remove_decoy(&s.profile.vault_path) {
                    Ok(()) => tr("Faux coffre supprimé.").into(),
                    Err(e) => e.to_string(),
                },
                Some(sk) => {
                    if s.st.decoy_pw.chars().count() < 12 {
                        tr("12 caractères minimum.").into()
                    } else if *s.st.decoy_pw != *s.st.decoy_pw2 {
                        tr("Les mots de passe diffèrent.").into()
                    } else if *s.st.decoy_pw == *real {
                        tr("Le mot de passe de contrainte doit différer du mot de passe maître.").into()
                    } else if config::is_erase_secret(cfg, &s.profile.name, &s.st.decoy_pw) {
                        tr("Ce mot de passe est déjà un mot de passe de destruction ou la clé globale.").into()
                    } else {
                        match decoy::create_decoy(&s.profile.vault_path, &s.st.decoy_pw, &real, &sk, KdfParams::DEFAULT) {
                            Ok(_) => tr("Mode contrainte activé.").into(),
                            Err(e) => e.to_string(),
                        }
                    }
                }
            };
            s.st.decoy_real.zeroize();
            s.st.decoy_pw.zeroize();
            s.st.decoy_pw2.zeroize();
        }
    });
}

fn destroy_card(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config) {
    theme::card(ui, |ui| {
        ui.label(
            RichText::new(tr("Mots de passe d'effacement irréversible, à saisir à l'écran de connexion à la place du mot de passe maître. L'écran affiche ensuite le message d'erreur habituel."))
                .size(13.0)
                .color(theme::danger()),
        );
        theme::label(ui, tr("Les données effacées ne peuvent pas être récupérées, même avec une copie de la clé secrète."));
        theme::label(ui, tr("Mot de passe maître actuel"));
        password_field(ui, &mut s.st.dest_auth, "");

        // ---- this profile only
        ui.add_space(8.0);
        ui.label(theme::bold(tr("Mot de passe de destruction de ce profil")));
        theme::label(ui, tr("Efface uniquement ce profil : coffre, clé secrète et faux coffre."));
        let has = cfg.profiles.iter().find(|p| p.name == s.profile.name).is_some_and(|p| p.destruct.is_some());
        theme::label(ui, tr("Changer ce mot de passe réinitialise les actions après effacement."));
        ui.label(RichText::new(if has { tr("Défini") } else { tr("Non défini") }).color(if has { theme::ok() } else { theme::dim() }));
        theme::label(ui, tr("Nouveau mot de passe de destruction (12 caractères minimum, différent du mot de passe maître)"));
        password_field(ui, &mut s.st.dest_pw, "");
        theme::label(ui, tr("Confirmation"));
        password_field(ui, &mut s.st.dest_pw2, "");
        let (mut set, mut remove) = (false, false);
        ui.horizontal(|ui| {
            set = theme::primary(ui, tr("Définir")).clicked();
            if has {
                remove = theme::danger_button(ui, tr("Supprimer le mot de passe de destruction")).clicked();
            }
        });
        let auth = s.st.dest_auth.clone();
        if set || remove {
            s.st.dest_msg = if verify_master(s, &auth).is_none() {
                tr("Mot de passe maître incorrect.").into()
            } else if remove {
                if let Some(p) = cfg.profiles.iter_mut().find(|p| p.name == s.profile.name) {
                    p.destruct = None;
                    p.actions = None;
                }
                config::save(cfg);
                tr("Mot de passe de destruction supprimé.").into()
            } else if *s.st.dest_pw != *s.st.dest_pw2 {
                tr("Les mots de passe diffèrent.").into()
            } else {
                match destroy::check_destruct_password(&s.st.dest_pw, &auth) {
                    Err("same as master") => tr("Le mot de passe de destruction doit différer du mot de passe maître.").into(),
                    Err(_) => tr("12 caractères minimum.").into(),
                    Ok(()) if opens_this_profile(s, &s.st.dest_pw) => tr("Ce mot de passe ouvre déjà un coffre de ce profil (mot de passe maître ou de contrainte).").into(),
                    Ok(()) => match Verifier::new(&s.st.dest_pw) {
                        Ok(v) => {
                            if let Some(p) = cfg.profiles.iter_mut().find(|p| p.name == s.profile.name) {
                                p.destruct = Some(v);
                                p.actions = None;
                            }
                            config::save(cfg);
                            tr("Mot de passe de destruction enregistré.").into()
                        }
                        Err(_) => tr("Échec").into(),
                    },
                }
            };
            s.st.dest_pw.zeroize();
            s.st.dest_pw2.zeroize();
            s.st.dest_auth.zeroize();
        }

        // ---- every profile, two-person activation
        ui.add_space(12.0);
        ui.label(theme::bold(tr("Destruction de toutes les sessions")));
        theme::label(
            ui,
            tr("Clé de sécurité commune à des profils liés. Une fois la destruction globale activée, la saisir à l'écran de connexion efface ces profils liés, et eux seuls."),
        );
        theme::label(
            ui,
            tr("Activation en deux temps : deux profils liés (onglet Profils liés) saisissent la même clé (12 caractères alphanumériques minimum, avec lettres et chiffres)."),
        );
        let armed = cfg.global_destruct.is_some();
        let waiting = cfg.global_pending.as_ref().map(|p| p.profile.clone());
        let waiting_name = waiting.as_ref().and_then(|w| cfg.profiles.iter().find(|q| config::pid(q) == *w)).map(|q| q.name.clone());
        if armed {
            ui.label(RichText::new(tr("Destruction globale activée")).color(theme::ok()));
        } else if waiting.is_some() {
            let who = waiting_name.clone().unwrap_or_else(|| tr("un autre profil").to_owned());
            ui.label(RichText::new(format!("{} {who}", tr("En attente d'un second profil — premier profil :"))).color(theme::accent()));
        } else {
            ui.label(RichText::new(tr("Inactive")).color(theme::dim()));
        }
        theme::label(ui, tr("Clé de sécurité commune"));
        password_field(ui, &mut s.st.glob_key, "");
        if !armed {
            theme::label(ui, tr("Confirmation de la clé"));
            password_field(ui, &mut s.st.glob_key2, "");
        }
        let (mut arm_click, mut disarm, mut cancel) = (false, false, false);
        ui.horizontal(|ui| {
            if armed {
                disarm = theme::danger_button(ui, tr("Désactiver la destruction globale")).clicked();
            } else {
                arm_click = theme::primary(ui, tr("Enregistrer la clé de sécurité")).clicked();
                if waiting.is_some() {
                    cancel = ui.button(tr("Annuler l'activation en attente")).clicked();
                }
            }
        });
        let key = s.st.glob_key.clone();
        let auth2 = s.st.dest_auth.clone();
        if arm_click || disarm || cancel {
            let master_ok = verify_master(s, &auth2).is_some();
            s.st.dest_msg = if !master_ok {
                tr("Mot de passe maître incorrect.").into()
            } else if cancel {
                cfg.global_pending = None;
                config::save(cfg);
                tr("Activation en attente annulée.").into()
            } else if disarm {
                if cfg.global_destruct.as_ref().is_some_and(|v| v.check(&key)) {
                    cfg.global_destruct = None;
                    cfg.global_pending = None;
                    cfg.global_members.clear();
                    config::save(cfg);
                    tr("Destruction globale désactivée.").into()
                } else {
                    tr("Clé de sécurité incorrecte.").into()
                }
            } else if cfg.profiles.len() < 2 {
                tr("Au moins deux profils sont nécessaires.").into()
            } else if *s.st.glob_key != *s.st.glob_key2 {
                tr("Les mots de passe diffèrent.").into()
            } else if opens_this_profile(s, &key) {
                tr("Ce mot de passe ouvre déjà un coffre de ce profil (mot de passe maître ou de contrainte).").into()
            } else if !cfg.profiles.iter().any(|p| config::linked(cfg, &config::pid(&s.profile), &config::pid(p))) {
                tr("Liez d'abord ce profil à un autre (onglet Profils liés).").into()
            } else if cfg.global_pending.as_ref().is_some_and(|p| {
                let first = p.profile.clone();
                first != config::pid(&s.profile) && !config::linked(cfg, &first, &config::pid(&s.profile))
            }) {
                tr("Seul un profil lié au premier peut confirmer cette clé.").into()
            } else {
                let me = config::pid(&s.profile);
                let (g, p) = (&mut cfg.global_destruct, &mut cfg.global_pending);
                match destroy::arm(g, p, &me, &key) {
                    Err(_) => tr("La clé doit comporter 12 caractères alphanumériques minimum, avec au moins une lettre et un chiffre.").into(),
                    Ok(Arm::Waiting) => {
                        config::save(cfg);
                        tr("Clé enregistrée. Un second profil doit maintenant saisir la même clé.").into()
                    }
                    Ok(Arm::Armed) => {
                        let first = waiting.clone().unwrap_or_default();
                        cfg.global_members = vec![first, config::pid(&s.profile)];
                        config::save(cfg);
                        tr("Destruction globale activée.").into()
                    }
                    Ok(Arm::Mismatch) => tr("La clé saisie ne correspond pas à celle du premier profil.").into(),
                    Ok(Arm::SameProfile) => tr("Un second profil, différent du premier, doit confirmer la clé.").into(),
                }
            };
            s.st.glob_key.zeroize();
            s.st.glob_key2.zeroize();
            s.st.dest_auth.zeroize();
        }
        if !s.st.dest_msg.is_empty() {
            ui.label(RichText::new(&s.st.dest_msg).color(theme::accent()));
        }
    });
}

fn import_card(ui: &mut egui::Ui, s: &mut Session) {
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Importer des mots de passe (CSV)"));
        theme::label(ui, tr("Export CSV de Chrome/Edge/Firefox, Bitwarden, KeePass ou 1Password. Les entrées arrivent dans la vue actuellement ouverte."));
        ui.label(
            RichText::new(tr("Le fichier CSV contient tous vos mots de passe en clair : supprimez-le immédiatement après l'import."))
                .size(12.0)
                .color(theme::accent()),
        );
        ui.add(egui::TextEdit::singleline(&mut s.st.import_path).hint_text(tr("Chemin du fichier .csv")).desired_width(f32::INFINITY));
        if !s.st.import_msg.is_empty() {
            ui.label(&s.st.import_msg);
        }
        if theme::primary(ui, tr("Importer")).clicked() {
            let path = s.st.import_path.trim().trim_matches('"').to_owned();
            s.st.import_msg = match std::fs::read(&path) {
                Err(_) => tr("Fichier introuvable.").into(),
                Ok(data) => match import::parse(&data) {
                    Err(m) => tr(m).into(),
                    Ok(imp) => {
                        let (mut added, mut dups) = (0, 0);
                        for e in imp.entries.iter() {
                            let exists = s.entries().iter().any(|x| x.site == e.site && x.username == e.username);
                            if exists {
                                dups += 1;
                            } else {
                                s.entries_mut().push(e.clone());
                                added += 1;
                            }
                        }
                        s.persist();
                        s.st.import_done = Some(path.clone());
                        format!("{added} {} — {dups} {} — {} {}", tr("entrées importées"), tr("doublons ignorés"), imp.skipped, tr("lignes ignorées"))
                    }
                },
            };
        }
        if let Some(p) = s.st.import_done.clone()
            && theme::danger_button(ui, tr("Effacer le fichier CSV (écrasement puis suppression)")).clicked()
        {
            s.st.import_msg = match import::shred(Path::new(&p)) {
                Ok(()) => tr("Fichier CSV effacé.").into(),
                Err(e) => e.to_string(),
            };
            s.st.import_done = None;
        }
    });
}

/// Civil date (UTC) from a unix timestamp.
pub fn fmt_date(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", (secs % 86_400) / 3600, (secs % 3600) / 60)
}

fn req(ui: &mut egui::Ui, ok: bool, text: &str) {
    ui.horizontal(|ui| {
        if ok {
            theme::check(ui, theme::ok());
            ui.label(RichText::new(text).size(13.0));
        } else {
            theme::cross(ui, theme::danger());
            ui.label(RichText::new(text).size(13.0).color(theme::danger()));
        }
    });
}

fn transfer_card(ui: &mut egui::Ui, s: &mut Session, lock: &mut bool) {
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Transfert sécurisé (migration vers un autre PC)"));
        let Some(x) = s.st.xfer.as_mut() else {
            theme::label(ui, tr("Crée une copie chiffrée de votre profil (coffre + clé secrète) afin de le restaurer sur un PC réinitialisé."));
            theme::label(ui, tr("Procédure stricte : ré-authentification (mot de passe maître + 2FA), passphrase de transfert très forte, phrase de confirmation, compte à rebours de 30 s, vérification du fichier."));
            if !s.vault.settings.transfer_log.is_empty() {
                theme::label(ui, tr("Transferts déjà effectués :"));
                for t in s.vault.settings.transfer_log.iter().rev().take(5) {
                    ui.label(RichText::new(fmt_date(*t)).monospace());
                }
            }
            if theme::primary(ui, tr("Démarrer la procédure de transfert")).clicked() {
                s.st.xfer = Some(Xfer::new());
            }
            return;
        };

        let mut cancel = false;
        let mut start_export = false;
        match &mut x.step {
            XStep::Auth => {
                theme::label(ui, tr("Étape 1/3 — Confirmez votre identité"));
                theme::label(ui, tr("Mot de passe maître"));
                password_field(ui, &mut x.pw, "");
                if s.vault.unlock_totp.is_some() {
                    theme::label(ui, tr("Code 2FA actuel"));
                    ui.add(egui::TextEdit::singleline(&mut x.code).char_limit(7).desired_width(160.0));
                }
                theme::error(ui, &x.err);
                ui.horizontal(|ui| {
                    if theme::primary(ui, tr("Vérifier")).clicked() {
                        let pw_ok = s.profile.secret_key()
                            .and_then(|sk| Vault::open(&s.profile.vault_path, &x.pw, &sk))
                            .is_ok();
                        let tfa_ok = s.vault.unlock_totp.as_ref().is_none_or(|k| otp::verify(k, &x.code));
                        x.code.clear();
                        if pw_ok && tfa_ok {
                            x.err.clear();
                            x.step = XStep::Prepare;
                        } else {
                            x.fails += 1;
                            x.pw.zeroize();
                            x.err = format!("{} ({}/3)", tr("Identifiants invalides"), x.fails);
                            if x.fails >= 3 {
                                *lock = true;
                            }
                        }
                    }
                    cancel = ui.button(tr("Annuler")).clicked();
                });
            }
            XStep::Prepare => {
                theme::label(ui, tr("Étape 2/3 — Passphrase de transfert et confirmation"));
                theme::label(ui, tr("Passphrase de transfert (elle protège le fichier ; sans elle il est illisible)"));
                password_field(ui, &mut x.pass, "");
                theme::label(ui, tr("Confirmation de la passphrase"));
                password_field(ui, &mut x.pass2, "");
                theme::label(ui, tr("Fichier de destination"));
                let default_dest = default_dest(&s.profile.name);
                ui.add(egui::TextEdit::singleline(&mut x.dest).hint_text(&default_dest).desired_width(f32::INFINITY));
                let phrase = format!("{} {}", tr("TRANSFERER"), s.profile.name);
                theme::label(ui, &format!("{} « {phrase} »", tr("Pour confirmer, saisissez exactement :")));
                ui.add(egui::TextEdit::singleline(&mut x.phrase).desired_width(f32::INFINITY));
                ui.checkbox(&mut x.ack1, tr("Je comprends que ce fichier contient mon coffre ET ma clé secrète, protégés uniquement par la passphrase."));
                ui.checkbox(&mut x.ack2, tr("Je m'engage à supprimer ce fichier après l'import, ou à le garder hors-ligne."));

                let dest = if x.dest.trim().is_empty() { default_dest.clone() } else { x.dest.trim().to_owned() };
                let dest_path = Path::new(&dest);
                let checks = [
                    (x.pass.chars().count() >= transfer::MIN_PASSPHRASE_CHARS, tr("20 caractères minimum")),
                    (pwgen::bits(&x.pass) >= 90.0, tr("Robustesse d'au moins 90 bits")),
                    (!x.pass.is_empty() && *x.pass == *x.pass2, tr("Les deux passphrases sont identiques")),
                    (*x.pass != *x.pw, tr("Différente du mot de passe maître")),
                    (!dest_path.exists() && dest_path.parent().is_some_and(|p| p.as_os_str().is_empty() || p.exists()), tr("Destination valide (le fichier n'existe pas encore)")),
                    (x.phrase == phrase, tr("Phrase de confirmation exacte")),
                    (x.ack1 && x.ack2, tr("Les deux engagements sont cochés")),
                ];
                for (ok, text) in checks {
                    req(ui, ok, text);
                }
                let all_ok = checks.iter().all(|c| c.0);
                theme::error(ui, &x.err);
                ui.horizontal(|ui| {
                    if ui.add_enabled_ui(all_ok, |ui| theme::primary(ui, tr("Lancer le compte à rebours (30 s)"))).inner.clicked() {
                        x.dest = dest.clone();
                        x.err.clear();
                        x.step = XStep::Wait(Instant::now());
                    }
                    cancel = ui.button(tr("Annuler")).clicked();
                });
            }
            XStep::Wait(since) => {
                let left = TRANSFER_DELAY.saturating_sub(since.elapsed());
                theme::label(ui, tr("Étape 3/3 — Délai de sécurité"));
                ui.add(
                    egui::ProgressBar::new(1.0 - left.as_secs_f32() / TRANSFER_DELAY.as_secs_f32())
                        .desired_height(8.0)
                        .text(format!("{} s", left.as_secs() + 1)),
                );
                theme::label(ui, tr("Annulez maintenant si vous n'êtes pas à l'origine de cette demande."));
                if left.is_zero() {
                    start_export = true;
                }
                cancel = ui.button(tr("Annuler")).clicked();
            }
            XStep::Done { path, fingerprint } => {
                ui.label(RichText::new(tr("Transfert créé et vérifié.")).color(theme::ok()).family(theme::semibold()));
                theme::label(ui, tr("Fichier"));
                ui.label(RichText::new(path.as_str()).monospace());
                theme::label(ui, tr("Empreinte (à comparer après la copie sur le nouveau PC)"));
                ui.label(RichText::new(fingerprint.as_str()).monospace().size(16.0).color(theme::accent()));
                theme::label(ui, tr("Sur le nouveau PC : installez Vylt, choisissez « Importer un transfert », puis saisissez la passphrase de transfert."));
                if ui.button(tr("Terminer")).clicked() {
                    cancel = true;
                }
            }
        }

        if start_export {
            run_export(s);
        } else if cancel {
            s.st.xfer = None;
        }
    });
}

fn default_dest(name: &str) -> String {
    let base = std::env::var_os("USERPROFILE").map(std::path::PathBuf::from).unwrap_or_default().join("Desktop");
    base.join(format!("vylt-{}-{}.svtransfer", crate::config::folder_name(name), now_secs())).to_string_lossy().into_owned()
}

fn run_export(s: &mut Session) {
    let Some(x) = s.st.xfer.as_mut() else { return };
    let (dest, pass) = (x.dest.clone(), x.pass.clone());
    s.vault.settings.transfer_log.push(now_secs());
    s.persist();
    let res = s.profile.secret_key()
        .and_then(|sk| transfer::export(&s.profile.vault_path, &sk, &s.profile.name, &pass, transfer::KDF, Path::new(&dest)));
    let Some(x) = s.st.xfer.as_mut() else { return };
    match res {
        Ok(fingerprint) => {
            x.pass.zeroize();
            x.pass2.zeroize();
            x.pw.zeroize();
            x.step = XStep::Done { path: dest, fingerprint };
        }
        Err(e) => {
            x.err = format!("{} : {e}", tr("Échec du transfert"));
            x.step = XStep::Prepare;
            s.vault.settings.transfer_log.pop();
            s.persist();
        }
    }
}

fn passkeys_card(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config) {
    let count: usize = s.vault.entries.iter().map(|e| e.passkeys.len()).sum();
    theme::label(ui, &tr("Les sites enregistrent leurs clés d'accès (passkeys) dans ce coffre. Clés d'accès dans ce profil : {n}.").replace("{n}", &count.to_string()));
    ui.add_space(6.0);
    row(ui, tr("Extension de navigateur"), tr("Pour Chrome, Edge et Brave, y compris en mode portable. L'extension transmet les demandes des sites à Vylt ; elle ne voit jamais les clés privées."), |ui| {
        let last = crate::broker::LAST_EXTENSION.load(std::sync::atomic::Ordering::Relaxed);
        if cfg.extension {
            ui.label(RichText::new(tr("Installée")).color(theme::ok()));
            if last > 0 {
                theme::label(ui, &format!("{} {}", tr("Dernière demande reçue le"), fmt_date(last)));
            }
        } else {
            ui.label(RichText::new(tr("Non installée")).color(theme::dim()));
        }
        ui.horizontal(|ui| {
            let label = if cfg.extension { tr("Réinstaller l'extension…") } else { tr("Installer l'extension…") };
            if ui.button(label).clicked() {
                match crate::pipe::install() {
                    Ok(dir) => {
                        cfg.extension = true;
                        config::save(cfg);
                        platform::spawn_detached("explorer.exe", &[dir.to_string_lossy().into_owned()]);
                        s.st.pk_msg = tr("1. Ouvrez chrome://extensions (ou edge://extensions). 2. Activez le mode développeur. 3. Cliquez sur « Charger l'extension non empaquetée » et choisissez le dossier qui vient de s'ouvrir : {dir}").replace("{dir}", &dir.to_string_lossy());
                    }
                    Err(e) => s.st.pk_msg = crate::errcode::tag(&format!("{} : {e}", tr("Installation impossible")), "SV-E60"),
                }
            }
            if cfg.extension && theme::danger_button(ui, tr("Retirer")).clicked() {
                crate::pipe::uninstall();
                cfg.extension = false;
                config::save(cfg);
                s.st.pk_msg = tr("Extension retirée de Vylt. Supprimez-la aussi de la page des extensions du navigateur.").into();
            }
        });
        if config::portable_root().is_some() {
            theme::label(ui, tr("En mode portable, l'installation inscrit le chemin de Vylt dans le registre de ce PC (navigateurs de l'utilisateur uniquement)."));
        }
        if !s.st.pk_msg.is_empty() {
            ui.label(RichText::new(&s.st.pk_msg).size(13.0));
        }
    });
    row(ui, tr("Intégration Windows"), tr("Vylt apparaît comme fournisseur de clés d'accès dans Windows : Chrome, Edge, Firefox et les applications. Windows demande une seule fois votre code PIN pour l'activer."), |ui| {
        use crate::winplugin::State;
        match crate::winplugin::state() {
            State::Unsupported => theme::label(ui, tr("Windows 11 version 24H2 ou plus récente est nécessaire.")),
            State::NoIdentity => theme::label(ui, tr("Disponible uniquement avec l'installation Windows signée. Indisponible en mode portable et en version de développement.")),
            State::NotRegistered => {
                ui.label(RichText::new(tr("Non enregistrée")).color(theme::dim()));
                if theme::primary(ui, tr("Enregistrer dans Windows")).clicked() {
                    match crate::winplugin::register() {
                        Ok(()) => {
                            crate::ui_passkey::sync_windows(s);
                            crate::winplugin::open_settings();
                            s.st.pk_msg = tr("Enregistrée. Dans les paramètres Windows qui s'ouvrent, activez Vylt, puis confirmez avec votre code PIN Windows.").into();
                        }
                        Err(e) => s.st.pk_msg = crate::errcode::tag(&format!("{} : {e}", tr("Enregistrement impossible")), "SV-E61"),
                    }
                }
            }
            State::Disabled => {
                ui.label(RichText::new(tr("Enregistrée, à activer dans Windows")).color(theme::accent()));
                ui.horizontal(|ui| {
                    if ui.button(tr("Ouvrir les paramètres Windows")).clicked() {
                        crate::winplugin::open_settings();
                    }
                    if theme::danger_button(ui, tr("Retirer de Windows")).clicked() {
                        crate::winplugin::unregister();
                        s.st.pk_msg = tr("Vylt a été retiré des fournisseurs de clés d'accès Windows.").into();
                    }
                });
            }
            State::Enabled => {
                crate::ui_passkey::sync_windows(s);
                ui.label(RichText::new(tr("Activée")).color(theme::ok()));
                ui.horizontal(|ui| {
                    if ui.button(tr("Ouvrir les paramètres Windows")).clicked() {
                        crate::winplugin::open_settings();
                    }
                    if theme::danger_button(ui, tr("Retirer de Windows")).clicked() {
                        crate::winplugin::unregister();
                        s.st.pk_msg = tr("Vylt a été retiré des fournisseurs de clés d'accès Windows.").into();
                    }
                });
            }
        }
    });
    row(ui, tr("Vérification"), tr("Ce qui est demandé avant chaque utilisation d'une clé d'accès. Windows Hello n'est jamais utilisé."), |ui| {
        let mut always = s.vault.settings.passkey_password;
        egui::ComboBox::from_id_salt("pk-verify")
            .selected_text(if always { tr("Toujours le mot de passe maître") } else { tr("Coffre ouvert : confirmation") })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut always, false, tr("Coffre ouvert : confirmation"));
                ui.selectable_value(&mut always, true, tr("Toujours le mot de passe maître"));
            });
        if always != s.vault.settings.passkey_password {
            s.vault.settings.passkey_password = always;
            s.persist();
        }
    });
}

/// Move this profile between the PC and a USB drive. The secret key, if any, always goes along
/// to a chosen place: switching mode never removes it.
fn portable_card(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config) {
    let here = config::portable_drive();
    let portable = here.is_some();
    theme::card(ui, |ui| {
        if portable {
            theme::heading(ui, tr("Passer ce profil en mode fixe"));
            theme::label(ui, tr("Le coffre est copié de la clé USB vers cet ordinateur (%APPDATA%\\Vylt), vérifié, puis effacé de la clé USB. Fermez Vylt installé sur ce PC avant de continuer."));
        } else {
            theme::heading(ui, tr("Passer ce profil en mode portable"));
            theme::label(ui, tr("Le programme et ce coffre sont copiés sur une clé USB, vérifiés, puis le coffre est effacé de cet ordinateur."));
        }
        ui.add_space(6.0);
        let drives: Vec<char> = platform::removable_drives().into_iter().filter(|&d| Some(d) != here).collect();
        let target = if portable {
            None
        } else {
            if drives.is_empty() {
                theme::label(ui, tr("Aucune clé USB détectée. Branchez-en une pour continuer."));
                return;
            }
            if !s.st.mv_drive.is_some_and(|d| drives.contains(&d)) {
                s.st.mv_drive = drives.first().copied();
            }
            theme::field_row(ui, tr("Clé USB"), |ui| {
                egui::ComboBox::from_id_salt("mv-drive")
                    .selected_text(format!("{}:\\", s.st.mv_drive.unwrap_or('?')))
                    .show_ui(ui, |ui| {
                        for &d in &drives {
                            ui.selectable_value(&mut s.st.mv_drive, Some(d), format!("{d}:\\"));
                        }
                    });
            });
            s.st.mv_drive
        };
        // The vault's future drive: the target USB drive, or none once on the PC.
        let vault_drive = target;
        let file = s.profile.key_path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "secret.key".into());
        if s.profile.use_key {
            ui.add_space(4.0);
            theme::label(ui, tr("Emplacement de la clé secrète"));
            ui.radio_value(&mut s.st.mv_key, 0, tr("Sur cet ordinateur"));
            if portable {
                ui.radio_value(&mut s.st.mv_key, 1, tr("Sur la clé USB"));
            } else if s.st.mv_key == 1 {
                s.st.mv_key = 0;
            }
            ui.radio_value(&mut s.st.mv_key, 2, tr("Sur un autre support"));
            if s.st.mv_key == 2 {
                if s.st.mv_path.is_empty()
                    && let Some(d) = drives.iter().find(|&&d| Some(d) != vault_drive)
                {
                    s.st.mv_path = format!("{d}:\\Vylt\\{file}");
                }
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut s.st.mv_path).font(egui::TextStyle::Monospace).desired_width(380.0));
                    if ui.button(tr("Choisir…")).clicked()
                        && let Some(p) = rfd::FileDialog::new().set_file_name(&file).add_filter("Clé", &["key"]).save_file()
                    {
                        s.st.mv_path = p.to_string_lossy().into_owned();
                    }
                });
            }
            theme::label(ui, tr("La clé secrète ne peut pas être retirée lors d'un changement de mode."));
        }
        ui.add_space(4.0);
        theme::label(ui, tr("Mot de passe maître"));
        password_field(ui, &mut s.st.mv_pw, "");
        theme::error(ui, &s.st.mv_err);
        let label = if portable { tr("Passer en mode fixe") } else { tr("Passer en mode portable") };
        if theme::primary(ui, label).clicked() {
            run_move(s, cfg, target, &file);
        }
    });
}

fn run_move(s: &mut Session, cfg: &mut Config, target: Option<char>, file: &str) {
    s.st.mv_err.clear();
    // Kept (wiped on drop) until the copy has been opened at its destination.
    let pw = s.st.mv_pw.clone();
    s.st.mv_pw.zeroize();
    let ok = s.profile.secret_key().and_then(|sk| Vault::open(&s.profile.vault_path, &pw, &sk)).is_ok();
    if !ok {
        s.st.mv_err = tr("Identifiants invalides.").into();
        return;
    }
    let portable = config::portable_root();
    let key_dst = if !s.profile.use_key {
        None
    } else {
        let k = match (portable, s.st.mv_key) {
            (Some(_), 0) => config::installed_dir().join("profiles").join(config::folder_name(&s.profile.name)).join(file),
            (None, 0) => config::pc_keys_dir().join(file),
            (Some(root), 1) => root.join("keys").join(file),
            _ => PathBuf::from(s.st.mv_path.trim()),
        };
        if config::drive_of(&k).is_none() {
            s.st.mv_err = tr("Veuillez choisir un emplacement pour la clé secrète.").into();
            return;
        }
        if s.st.mv_key == 2 && config::drive_of(&k) == target {
            s.st.mv_err = tr("La clé secrète doit être sur un autre support que la clé USB du coffre.").into();
            return;
        }
        Some(k)
    };
    let Some(idx) = profile_index(s, cfg) else { return };
    s.persist();
    let verify = |p: &config::Profile| p.secret_key().and_then(|sk| Vault::open(&p.vault_path, &pw, &sk)).is_ok();
    let res = match target {
        Some(d) => crate::portable::to_portable(cfg, idx, d, key_dst, &verify),
        None => crate::portable::to_fixed(cfg, idx, key_dst, &verify),
    };
    match res {
        Ok(body) => s.st.moved = Some(Alert { title: tr("Profil déplacé").into(), body, close_app: false, info: true, code: String::new() }),
        Err(e) => s.st.mv_err = e,
    }
}

fn info_card(ui: &mut egui::Ui, s: &mut Session, lock: &mut bool) {
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Fichiers de ce profil"));
        theme::label(ui, tr("Coffre"));
        ui.label(s.profile.vault_path.to_string_lossy());
        if s.profile.use_key {
            theme::label(ui, tr("Clé secrète"));
            ui.label(s.profile.key_path.to_string_lossy());
            theme::label(ui, tr("Sans la clé secrète ET le mot de passe maître, le coffre est indéchiffrable. Conservez une copie de la clé hors ligne."));
        } else {
            theme::label(ui, tr("Aucune clé secrète : la protection repose sur le mot de passe maître seul."));
        }
        if ui.button(tr("Verrouiller maintenant")).clicked() {
            *lock = true;
        }
    });
}

fn update_card(ui: &mut egui::Ui) {
    use crate::update::{self, Status};
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Mises à jour"));
        theme::label(ui, &format!("{} : {}", tr("Version installée"), update::current()));
        theme::label(ui, tr("Vylt ne se met pas à jour tout seul. La vérification est manuelle et n'interroge GitHub que pour comparer le numéro de version ; aucune donnée personnelle n'est envoyée."));
        let running = update::is_running();
        ui.add_enabled_ui(!running, |ui| {
            if theme::primary(ui, tr("Rechercher les mises à jour")).clicked() {
                update::check(ui.ctx());
            }
        });
        if running {
            theme::label(ui, tr("Vérification…"));
        }
        match update::status() {
            Status::Idle => {}
            Status::UpToDate => {
                ui.label(RichText::new(tr("Vous avez la dernière version.")).color(theme::ok()));
            }
            Status::Newer(r) => {
                ui.label(RichText::new(format!("{} {}", tr("Nouvelle version disponible :"), r.version)).color(theme::accent()));
                if !r.url.is_empty() {
                    ui.hyperlink_to(tr("Télécharger"), &r.url);
                }
                if !r.notes.trim().is_empty() {
                    theme::label(ui, tr("Notes"));
                    ui.label(r.notes.trim());
                }
            }
            Status::Error(e) => {
                ui.label(RichText::new(e).color(theme::danger()));
            }
        }
    });
}
