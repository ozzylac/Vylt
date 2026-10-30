//! The "Coffre" tab: entry list, categories, detail view with code gate, editor.

use eframe::egui::{self, RichText};
use vylt::hidden::OpenBox;
use vylt::lock::{EntryLock, LockKind};
use vylt::otp;
use vylt::vault::{Code, Entry};
use zeroize::Zeroize;

use crate::config::now_secs;
use crate::i18n::tr;
use crate::pwgen;
use crate::session::*;
use crate::theme;
use crate::ui_common::{lock_error, lock_label, no_history, strength};

/// Returns true when the session must lock (too many wrong entry codes).
pub fn vault_tab(ui: &mut egui::Ui, s: &mut Session) -> bool {
    if ui.input(|i| i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::H)) && !s.is_decoy {
        s.show_special = !s.show_special;
    }
    left_panel(ui, s);

    let mut lock = false;
    egui::CentralPanel::default().frame(egui::Frame::new().fill(theme::bg()).inner_margin(20)).show(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            if s.edit.is_some() {
                edit_ui(ui, s);
            } else if let Some(i) = s.selected.filter(|&i| i < s.entries().len()) {
                lock = detail_ui(ui, s, i);
            } else {
                ui.add_space(80.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new(tr("Aucune entrée sélectionnée")).size(18.0).color(theme::dim()));
                    theme::label(ui, tr("Sélectionnez une entrée à gauche ou créez-en une."));
                });
            }
        });
    });
    lock
}

fn left_panel(ui: &mut egui::Ui, s: &mut Session) {
    egui::Panel::left("list")
        .min_size(260.0)
        .frame(egui::Frame::new().fill(theme::panel()).inner_margin(12))
        .show(ui, |ui| {
            if let Some(name) = s.hidden_name().map(str::to_owned) {
                theme::card(ui, |ui| {
                    theme::label(ui, tr("Catégorie cachée"));
                    ui.label(RichText::new(&name).family(theme::semibold()).color(theme::accent()));
                    ui.horizontal(|ui| {
                        if ui.button(tr("Fermer")).clicked() {
                            close_box(s);
                        }
                        let label = if s.confirm_delete_box { tr("Confirmer la suppression") } else { tr("Supprimer") };
                        if theme::danger_button(ui, label).clicked() {
                            if s.confirm_delete_box {
                                delete_box(s);
                            } else {
                                s.confirm_delete_box = true;
                            }
                        }
                    });
                });
            }

            ui.add(egui::TextEdit::singleline(&mut s.search).hint_text(tr("Rechercher…")).desired_width(f32::INFINITY));
            if theme::primary(ui, tr("+ Nouvelle entrée")).clicked() {
                s.edit = Some(Edit::new(None, Entry::blank()));
            }

            // categories: plain text filters, the current one in semibold
            let mut cats: Vec<String> = s.entries().iter().map(|e| e.category.clone()).filter(|c| !c.is_empty()).collect();
            cats.sort();
            cats.dedup();
            if !cats.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    let pick = |ui: &mut egui::Ui, on: bool, text: &str| -> bool {
                        let t = if on { theme::bold(text).size(13.0) } else { RichText::new(text).size(13.0).color(theme::dim()) };
                        ui.add(egui::Label::new(t).sense(egui::Sense::click())).clicked()
                    };
                    if pick(ui, s.cat_filter.is_none(), tr("Toutes")) {
                        s.cat_filter = None;
                    }
                    for c in &cats {
                        if pick(ui, s.cat_filter.as_deref() == Some(c.as_str()), c) {
                            s.cat_filter = Some(c.clone());
                        }
                    }
                });
            }

            let q = s.search.to_lowercase();
            let mut clicked = None;
            egui::ScrollArea::vertical().max_height((ui.available_height() - 60.0).max(80.0)).show(ui, |ui| {
                for (i, e) in s.entries().iter().enumerate() {
                    let user_hit = e.lock.is_none() && e.username.to_lowercase().contains(&q);
                    if !q.is_empty() && !e.site.to_lowercase().contains(&q) && !user_hit {
                        continue;
                    }
                    if s.cat_filter.as_ref().is_some_and(|c| *c != e.category) {
                        continue;
                    }
                    let on = s.selected == Some(i) && s.edit.is_none();
                    let r = egui::Frame::new()
                        .fill(if on { theme::selected_fill() } else { egui::Color32::TRANSPARENT })
                        .corner_radius(8)
                        .inner_margin(egui::Margin::symmetric(8, 6))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                theme::tile(ui, &e.site, 28.0);
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 0.0;
                                    ui.label(theme::bold(&e.site));
                                    // A gated entry shows nothing but its name.
                                    if e.lock.is_none() {
                                        ui.label(RichText::new(&e.username).size(12.0).color(theme::dim()));
                                    }
                                });
                                if e.lock.is_some() {
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        theme::padlock(ui, 14.0, theme::dim());
                                    });
                                }
                            });
                        })
                        .response
                        .interact(egui::Sense::click());
                    if r.clicked() {
                        clicked = Some(i);
                    }
                }
            });
            if let Some(i) = clicked {
                s.selected = Some(i);
                s.edit = None;
                s.reset_reveal();
            }

            if s.show_special && !s.is_decoy {
                ui.separator();
                let r = ui.add(
                    egui::TextEdit::singleline(&mut *s.special)
                        .password(true)
                        .hint_text(tr("Accès spécial"))
                        .desired_width(f32::INFINITY),
                );
                no_history(ui, &r);
                r.request_focus();
                if ui.input(|i| i.key_pressed(egui::Key::Enter)) && !s.special.is_empty() {
                    try_open_hidden(s);
                }
            }
        });
}

fn try_open_hidden(s: &mut Session) {
    let pw = s.special.clone();
    s.special.zeroize();
    let found = s.vault.hidden.iter().find_map(|hb| OpenBox::open(hb, &pw));
    match found {
        Some(ob) => {
            let id = ob.id;
            if !s.open.iter().any(|b| b.id == id) {
                s.open.push(ob);
            }
            s.switch_view(View::Hidden(id));
            s.show_special = false;
            s.say(tr("Catégorie ouverte"));
        }
        // Same message whether nothing exists or the password is wrong.
        None => s.say(tr("Aucune correspondance")),
    }
}

fn close_box(s: &mut Session) {
    if let View::Hidden(id) = s.view {
        s.persist();
        s.open.retain(|b| b.id != id);
        s.confirm_delete_box = false;
        s.switch_view(View::Main);
    }
}

fn delete_box(s: &mut Session) {
    if let View::Hidden(id) = s.view {
        s.open.retain(|b| b.id != id);
        s.vault.hidden.retain(|b| !b.is(id));
        s.confirm_delete_box = false;
        s.switch_view(View::Main);
        s.persist();
        s.say(tr("Catégorie supprimée"));
    }
}

/// Returns true if the session must lock.
fn detail_ui(ui: &mut egui::Ui, s: &mut Session, i: usize) -> bool {
    let e = s.entries()[i].clone();
    let blocked = s.entry_blocked(i);
    let mut copy: Option<(String, &'static str)> = None;
    let (mut edit, mut delete, mut lock) = (false, false, false);

    ui.horizontal(|ui| {
        theme::tile(ui, &e.site, 40.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            theme::title(ui, &e.site);
            if !e.category.is_empty() {
                theme::label(ui, &e.category);
            }
        });
        if !blocked {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                delete = theme::danger_button(ui, tr("Supprimer")).clicked();
                edit = ui.button(tr("Modifier")).clicked();
            });
        }
    });

    if blocked {
        if let Some(gate) = e.lock.clone().filter(|g| crate::ui_digicode::digits_of(g.kind).is_some()) {
            match crate::ui_digicode::show(ui.ctx(), s, i, &gate, &e.site) {
                crate::ui_digicode::Outcome::Close => {
                    s.selected = None;
                    s.reset_reveal();
                }
                crate::ui_digicode::Outcome::Lock => lock = true,
                crate::ui_digicode::Outcome::Stay => {}
            }
            return lock;
        }
        lock = gate_ui(ui, s, i, &e);
        return lock;
    }

    ui.add_space(8.0);
    theme::field_row(ui, tr("Identifiant"), |ui| {
        ui.label(RichText::new(&e.username).size(15.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::link(ui, tr("Copier")).clicked() {
                copy = Some((e.username.clone(), tr("Identifiant")));
            }
        });
    });
    theme::field_row(ui, tr("Mot de passe"), |ui| {
        let shown = if s.reveal_pw { e.password.clone() } else { "•".repeat(e.password.chars().count().min(24)) };
        ui.label(RichText::new(shown).monospace().size(15.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::link(ui, tr("Copier")).clicked() {
                copy = Some((e.password.clone(), tr("Mot de passe")));
            }
            let toggle = RichText::new(if s.reveal_pw { tr("Masquer") } else { tr("Afficher") }).color(theme::dim());
            if ui.add(egui::Label::new(toggle).sense(egui::Sense::click())).clicked() {
                s.reveal_pw = !s.reveal_pw;
            }
            let (txt, col) = strength(pwgen::bits(&e.password));
            ui.label(RichText::new(format!("{} {txt}", tr("Robustesse"))).size(12.0).color(col));
        });
    });
    if !e.notes.is_empty() {
        theme::field_row(ui, tr("Notes"), |ui| {
            ui.label(RichText::new(&e.notes).color(theme::dim()));
        });
    }
    theme::hline(ui);

    if !e.codes.is_empty() {
        ui.add_space(14.0);
        theme::heading(ui, tr("Codes de validation"));
        if s.reveal_codes.len() < e.codes.len() {
            s.reveal_codes.resize(e.codes.len(), false);
        }
        for (ci, c) in e.codes.iter().enumerate() {
            theme::hline(ui);
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(egui::vec2(180.0, 44.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.set_min_size(egui::vec2(180.0, 44.0));
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(theme::bold(&c.label));
                    if !c.note.is_empty() {
                        theme::label(ui, &c.note);
                    }
                });
                if c.totp {
                    match otp::live(&c.secret) {
                        Some(l) => {
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 4.0;
                                let (a, b) = l.code.split_at(l.code.len() / 2);
                                ui.label(RichText::new(format!("{a} {b}")).monospace().size(28.0));
                                ui.horizontal(|ui| {
                                    theme::countdown(ui, l.ttl as f32 / l.period as f32, 160.0);
                                    theme::label(ui, &format!("{} s", l.ttl));
                                });
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if theme::link(ui, tr("Copier")).clicked() {
                                    copy = Some((l.code.clone(), tr("Code")));
                                }
                            });
                        }
                        None => {
                            ui.label(RichText::new(tr("Clé TOTP invalide")).color(theme::danger()));
                        }
                    }
                } else {
                    let shown = if s.reveal_codes[ci] { c.secret.clone() } else { "•".repeat(c.secret.chars().count().min(16)) };
                    ui.label(RichText::new(shown).monospace().size(16.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::link(ui, tr("Copier")).clicked() {
                            copy = Some((c.secret.clone(), tr("Code")));
                        }
                        let toggle = RichText::new(if s.reveal_codes[ci] { tr("Masquer") } else { tr("Afficher") }).color(theme::dim());
                        if ui.add(egui::Label::new(toggle).sense(egui::Sense::click())).clicked() {
                            s.reveal_codes[ci] = !s.reveal_codes[ci];
                        }
                    });
                }
            });
        }
        theme::hline(ui);
    }

    let mut drop_pk = None;
    if !e.passkeys.is_empty() {
        ui.add_space(14.0);
        theme::heading(ui, tr("Clés d'accès"));
        theme::label(ui, tr("Créées par les sites, signées dans Vylt : la clé privée ne quitte jamais le coffre."));
        for (pi, p) in e.passkeys.iter().enumerate() {
            theme::hline(ui);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(theme::bold(&p.rp_id));
                    theme::label(ui, &format!("{} · {} {}", p.user_name, tr("créée le"), crate::ui_settings::fmt_date(p.created)));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::danger_button(ui, tr("Supprimer")).clicked() {
                        drop_pk = Some(pi);
                    }
                    let used = if p.last_used == 0 { tr("Jamais utilisée").to_owned() } else { format!("{} {}", tr("Dernière connexion le"), crate::ui_settings::fmt_date(p.last_used)) };
                    theme::label(ui, &used);
                });
            });
        }
        theme::hline(ui);
        theme::label(ui, tr("Supprimer une clé d'accès ici ne la retire pas du site : révoquez-la aussi dans les réglages de sécurité du site."));
    }

    if let Some(pi) = drop_pk {
        s.entries_mut()[i].passkeys.remove(pi);
        s.persist();
        crate::ui_passkey::sync_windows(s);
        s.say(tr("Clé d'accès supprimée"));
    }
    if let Some((text, what)) = copy {
        s.copy(&text, what);
    }
    if edit {
        s.edit = Some(Edit::new(Some(i), e));
    } else if delete {
        s.entries_mut().remove(i);
        s.selected = None;
        s.persist();
        s.say(tr("Entrée supprimée"));
    }
    lock
}

/// Code gate for a protected entry. Returns true when the session must lock.
fn gate_ui(ui: &mut egui::Ui, s: &mut Session, i: usize, e: &Entry) -> bool {
    let Some(gate) = e.lock.clone() else { return false };
    let mut lock = false;
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Entrée protégée par un code"));
        theme::label(ui, lock_label(gate.kind));
        let limit = match gate.kind {
            LockKind::Pin4 => 4,
            LockKind::Pin6 => 6,
            LockKind::Pin8 => 8,
            LockKind::Alpha => 32,
        };
        let r = ui.add(
            egui::TextEdit::singleline(&mut *s.entry_code)
                .password(true)
                .char_limit(limit)
                .font(egui::FontId::monospace(22.0))
                .desired_width(200.0),
        );
        no_history(ui, &r);
        r.request_focus();
        if s.entry_wait > 0 {
            theme::error(ui, &tr("Trop d'essais. Réessayez dans {n} s.").replace("{n}", &s.entry_wait.to_string()));
        } else if s.entry_fails > 0 {
            theme::error(ui, &format!("{} ({}/3)", tr("Code incorrect"), s.entry_fails));
        }
        let go = theme::primary(ui, tr("Déverrouiller l'entrée")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter));
        if go && !s.entry_code.is_empty() {
            let code = s.entry_code.clone();
            s.entry_code.zeroize();
            if !s.try_entry_code(i, &code) && s.entry_wait == 0 && s.entry_fails >= 3 {
                lock = true;
            }
        }
    });
    lock
}

fn edit_ui(ui: &mut egui::Ui, s: &mut Session) {
    let mut save = false;
    let mut cancel = false;
    let mut toast: Option<String> = None;
    let mut cats: Vec<String> = s.entries().iter().map(|e| e.category.clone()).filter(|c| !c.is_empty()).collect();
    cats.sort();
    cats.dedup();
    let Some(ed) = s.edit.as_mut() else { return };

    theme::title(ui, if ed.idx.is_some() { tr("Modifier l'entrée") } else { tr("Nouvelle entrée") });
    theme::card(ui, |ui| {
        theme::label(ui, tr("Site / service"));
        ui.add(egui::TextEdit::singleline(&mut ed.entry.site).desired_width(f32::INFINITY));
        theme::label(ui, tr("Catégorie"));
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut ed.entry.category).desired_width(200.0));
            if !cats.is_empty() {
                egui::ComboBox::from_id_salt("cat_pick").selected_text(tr("Choisir")).show_ui(ui, |ui| {
                    for c in &cats {
                        if ui.selectable_label(false, c).clicked() {
                            ed.entry.category = c.clone();
                        }
                    }
                });
            }
        });
        theme::label(ui, tr("Identifiant"));
        ui.add(egui::TextEdit::singleline(&mut ed.entry.username).desired_width(f32::INFINITY));
        theme::label(ui, tr("Mot de passe"));
        ui.add(egui::TextEdit::singleline(&mut ed.entry.password).password(!ed.reveal).desired_width(f32::INFINITY));
        let (txt, col) = strength(pwgen::bits(&ed.entry.password));
        ui.label(RichText::new(format!("{} : {txt}", tr("Robustesse"))).size(12.0).color(col));
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut ed.reveal, tr("Afficher"));
            ui.add(egui::Slider::new(&mut ed.gen_len, 12..=64).text(tr("longueur")));
            ui.checkbox(&mut ed.gen_symbols, tr("symboles"));
            if ui.button(tr("Générer")).clicked() {
                ed.entry.password.zeroize();
                ed.entry.password = pwgen::password(ed.gen_len, ed.gen_symbols);
                ed.reveal = true;
            }
        });
        theme::label(ui, tr("Notes"));
        ui.add(egui::TextEdit::multiline(&mut ed.entry.notes).desired_rows(3).desired_width(f32::INFINITY));
    });

    // --- code gate
    theme::card(ui, |ui| {
        theme::heading(ui, tr("Protection de l'entrée par un code"));
        theme::label(ui, tr("Le code est demandé avant d'afficher ou de copier cette entrée. 3 erreurs verrouillent la session."));
        let current = match &ed.lock_choice {
            LockChoice::Keep if ed.entry.lock.is_some() => tr("Conserver le code actuel"),
            LockChoice::Keep | LockChoice::Off => tr("Aucun code"),
            LockChoice::Kind(k) => lock_label(*k),
        };
        egui::ComboBox::from_id_salt("lockkind").selected_text(current).show_ui(ui, |ui| {
            if ed.entry.lock.is_some() && ui.selectable_label(matches!(ed.lock_choice, LockChoice::Keep), tr("Conserver le code actuel")).clicked() {
                ed.lock_choice = LockChoice::Keep;
            }
            if ui.selectable_label(matches!(ed.lock_choice, LockChoice::Off), tr("Aucun code")).clicked() {
                ed.lock_choice = LockChoice::Off;
            }
            for k in [LockKind::Pin6, LockKind::Pin8, LockKind::Alpha] {
                if ui.selectable_label(matches!(ed.lock_choice, LockChoice::Kind(x) if x == k), lock_label(k)).clicked() {
                    ed.lock_choice = LockChoice::Kind(k);
                }
            }
        });
        if let LockChoice::Kind(k) = ed.lock_choice {
            let limit = match k {
                LockKind::Pin4 => 4,
                LockKind::Pin6 => 6,
                LockKind::Pin8 => 8,
                LockKind::Alpha => 32,
            };
            theme::label(ui, tr("Nouveau code"));
            let r = ui.add(egui::TextEdit::singleline(&mut *ed.lock_code).password(true).char_limit(limit).desired_width(200.0));
            no_history(ui, &r);
            theme::label(ui, tr("Confirmation du code"));
            let r = ui.add(egui::TextEdit::singleline(&mut *ed.lock_code2).password(true).char_limit(limit).desired_width(200.0));
            no_history(ui, &r);
        }
    });

    // --- validation codes
    theme::heading(ui, tr("Codes de validation"));
    theme::label(
        ui,
        tr("Plusieurs par entrée. TOTP = code à 6 chiffres qui change (clé base32 ou lien otpauth://). Statique = code de secours."),
    );
    let mut remove = None;
    for (ci, c) in ed.entry.codes.iter_mut().enumerate() {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut c.label).hint_text(tr("Libellé")).desired_width(180.0));
                ui.add(egui::TextEdit::singleline(&mut c.note).hint_text(tr("Note")).desired_width(220.0));
                ui.checkbox(&mut c.totp, "TOTP");
                if theme::danger_button(ui, tr("Retirer")).clicked() {
                    remove = Some(ci);
                }
            });
            ui.add(
                egui::TextEdit::singleline(&mut c.secret)
                    .password(true)
                    .hint_text(if c.totp { tr("Clé base32 ou otpauth://…") } else { tr("Code") })
                    .desired_width(f32::INFINITY),
            );
            if c.totp && !c.secret.is_empty() && otp::parse(&c.secret).is_none() {
                ui.label(RichText::new(tr("Clé TOTP invalide")).color(theme::danger()));
            }
        });
    }
    if let Some(ci) = remove {
        ed.entry.codes.remove(ci);
    }
    ui.horizontal_wrapped(|ui| {
        if ui.button(tr("+ Code TOTP")).clicked() {
            ed.entry.codes.push(Code { label: String::new(), note: String::new(), secret: String::new(), totp: true });
        }
        if ui.button(tr("+ Code statique")).clicked() {
            ed.entry.codes.push(Code { label: String::new(), note: String::new(), secret: String::new(), totp: false });
        }
        if ui.button(tr("Importer un QR (capture dans le presse-papier)")).clicked() {
            match crate::platform::clipboard_qr() {
                Some(data) if otp::parse(&data).is_some() => {
                    let label = otp::suggested_label(&data).unwrap_or_default();
                    ed.entry.codes.push(Code { label, note: String::new(), secret: data, totp: true });
                    toast = Some(tr("QR importé").to_owned());
                }
                Some(_) => toast = Some(tr("QR lu, mais ce n'est pas un code TOTP").to_owned()),
                None => toast = Some(tr("Aucun QR détecté : copiez une capture d'écran (Win+Maj+S).").to_owned()),
            }
        }
    });

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        save = theme::primary(ui, tr("Enregistrer")).clicked();
        cancel = ui.button(tr("Annuler")).clicked();
    });

    if let Some(t) = toast {
        s.say(t);
    }
    if save {
        commit_edit(s);
    } else if cancel {
        s.edit = None;
    }
}

/// Validate and store the edited entry; stays in the editor (with a toast) on invalid input.
fn commit_edit(s: &mut Session) {
    let Some(ed) = s.edit.as_mut() else { return };
    if ed.entry.site.trim().is_empty() {
        s.say(tr("Le site est obligatoire"));
        return;
    }
    match &ed.lock_choice {
        LockChoice::Kind(k) => {
            let (k, code) = (*k, ed.lock_code.clone());
            if *ed.lock_code != *ed.lock_code2 {
                s.say(tr("Les codes diffèrent"));
                return;
            }
            match EntryLock::new(k, &code) {
                Ok(l) => ed.entry.lock = Some(l),
                Err(m) => {
                    let _ = m;
                    let m = lock_error(k);
                    s.say(m);
                    return;
                }
            }
        }
        LockChoice::Off => ed.entry.lock = None,
        LockChoice::Keep => {}
    }
    if ed.idx.is_none() || *ed.entry.password != **ed.orig_password {
        ed.entry.updated = now_secs();
    }
    let Some(ed) = s.edit.take() else { return };
    match ed.idx {
        Some(i) => s.entries_mut()[i] = ed.entry.clone(),
        None => {
            s.entries_mut().push(ed.entry.clone());
            s.selected = Some(s.entries().len() - 1);
        }
    }
    s.reset_reveal();
    s.persist();
    s.say(tr("Enregistré"));
}
