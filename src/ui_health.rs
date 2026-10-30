//! The "Santé" tab: weak / reused / old passwords, as a table sorted by risk.

use std::collections::BTreeSet;

use eframe::egui::{self, RichText};
use vylt::health;

use crate::config::now_secs;
use crate::i18n::tr;
use crate::pwgen;
use crate::session::*;
use crate::theme;

struct Row {
    entry: usize,
    text: String,
    risky: bool,
}

pub fn health_tab(ui: &mut egui::Ui, s: &mut Session) {
    let now = now_secs();
    let report = health::analyze(s.entries(), now);
    // An entry behind a code only says "a problem", and never shows up in another entry's
    // reuse list: the details appear once its code has been typed.
    let blocked: BTreeSet<usize> = (0..s.entries().len()).filter(|&i| s.entry_blocked(i)).collect();
    let entries = s.entries();
    let name = |i: usize| entries[i].site.clone();

    // Highest risk first: reused and weak, then old and empty.
    let mut rows: Vec<Row> = Vec::new();
    let mut hidden: BTreeSet<usize> = BTreeSet::new();
    for group in &report.reused {
        let open: Vec<usize> = group.iter().copied().filter(|i| !blocked.contains(i)).collect();
        hidden.extend(group.iter().filter(|i| blocked.contains(i)));
        if open.len() < 2 {
            continue;
        }
        for &i in &open {
            let others: Vec<String> = open.iter().filter(|&&j| j != i).map(|&j| name(j)).collect();
            rows.push(Row {
                entry: i,
                text: tr("Mot de passe réutilisé : le même que {others}").replace("{others}", &others.join(", ")),
                risky: true,
            });
        }
    }
    for &i in &report.weak {
        if blocked.contains(&i) {
            hidden.insert(i);
            continue;
        }
        let bits = format!("{:.0}", pwgen::bits(&entries[i].password));
        rows.push(Row {
            entry: i,
            text: tr("Mot de passe faible : {bits} bits, facile à deviner").replace("{bits}", &bits),
            risky: true,
        });
    }
    for &i in &report.old {
        if blocked.contains(&i) {
            hidden.insert(i);
            continue;
        }
        let months = (now.saturating_sub(entries[i].updated) / (30 * 86_400)).to_string();
        rows.push(Row { entry: i, text: tr("Mot de passe inchangé depuis {months} mois").replace("{months}", &months), risky: false });
    }
    for &i in &report.empty {
        if blocked.contains(&i) {
            hidden.insert(i);
            continue;
        }
        rows.push(Row { entry: i, text: tr("Aucun mot de passe enregistré").to_owned(), risky: false });
    }

    for &i in &hidden {
        rows.push(Row { entry: i, text: tr("Un problème a été détecté. Saisissez le code de l'entrée pour le voir.").to_owned(), risky: true });
    }

    let flagged: BTreeSet<usize> = rows.iter().map(|r| r.entry).collect();
    let total = entries.len();
    let names: Vec<String> = (0..total).map(name).collect();
    let mut open = None;

    if flagged.is_empty() {
        theme::title(ui, tr("Aucun problème local détecté."));
    } else {
        theme::title(
            ui,
            &tr("{n} entrées sur {total} ont un problème").replace("{n}", &flagged.len().to_string()).replace("{total}", &total.to_string()),
        );
        ui.label(RichText::new(tr("Les plus risquées sont en haut.")).color(theme::dim()));
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(egui::vec2(200.0, 18.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.set_min_width(200.0);
                theme::label(ui, tr("Entrée"));
            });
            theme::label(ui, tr("Problème"));
        });
        for r in &rows {
            theme::hline(ui);
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(egui::vec2(200.0, 28.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.set_min_width(200.0);
                    ui.label(theme::bold(&names[r.entry]));
                });
                let color = if r.risky { theme::danger() } else { theme::dim() };
                ui.label(RichText::new(&r.text).color(color));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::link(ui, if blocked.contains(&r.entry) { tr("Saisir le code") } else { tr("Ouvrir") }).clicked() {
                        open = Some(r.entry);
                    }
                });
            });
        }
        theme::hline(ui);
    }

    ui.add_space(20.0);
    hibp_card(ui, s, &names, &blocked);

    if let Some(i) = open {
        s.tab = Tab::Vault;
        s.selected = Some(i);
        s.edit = None;
        s.reset_reveal();
    }
}

/// Opt-in check against Have I Been Pwned. Only the first 5 hex chars of each password's SHA-1
/// hash are sent (k-anonymity); the password never leaves. It is the only online feature.
fn hibp_card(ui: &mut egui::Ui, s: &mut Session, names: &[String], blocked: &BTreeSet<usize>) {
    theme::heading(ui, tr("Vérification des fuites (Have I Been Pwned)"));
    if !s.vault.settings.hibp {
        theme::label(ui, tr("Compare vos mots de passe à la base des fuites connues. Seuls les 5 premiers caractères de l'empreinte SHA-1 sont envoyés (anonymat-k) : le mot de passe, lui, ne quitte jamais cet ordinateur. C'est la seule fonction qui utilise Internet, et elle est désactivée par défaut."));
        ui.add_space(4.0);
        if theme::primary(ui, tr("Activer la vérification des fuites")).clicked() {
            s.vault.settings.hibp = true;
            s.persist();
        }
        return;
    }
    ui.horizontal(|ui| {
        let running = crate::hibp::is_running();
        if ui.add_enabled(!running, egui::Button::new(tr("Vérifier les fuites maintenant"))).clicked() {
            let items: Vec<(usize, String)> = s
                .entries()
                .iter()
                .enumerate()
                .filter(|(i, e)| !e.password.is_empty() && !blocked.contains(i))
                .map(|(i, e)| (i, e.password.clone()))
                .collect();
            crate::hibp::start(ui.ctx(), items);
        }
        if running {
            ui.label(RichText::new(tr("Vérification en cours…")).color(theme::dim()));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::link(ui, tr("Désactiver")).clicked() {
                s.vault.settings.hibp = false;
                s.persist();
            }
        });
    });
    let rep = crate::hibp::report();
    if let Some(e) = &rep.err {
        theme::error(ui, &crate::errcode::tag(&format!("{} : {e}", tr("Vérification impossible")), "SV-E70"));
    } else if rep.done {
        if rep.pwned.is_empty() {
            ui.label(RichText::new(tr("Aucun de vos mots de passe vérifiés n'apparaît dans une fuite connue.")).color(theme::ok()));
        } else {
            ui.label(RichText::new(tr("Mots de passe apparaissant dans des fuites connues — à changer :")).color(theme::danger()));
            for (i, count) in &rep.pwned {
                theme::hline(ui);
                ui.horizontal(|ui| {
                    ui.label(theme::bold(names.get(*i).map(String::as_str).unwrap_or("?")));
                    ui.label(RichText::new(tr("vu {n} fois dans des fuites").replace("{n}", &count.to_string())).color(theme::danger()));
                });
            }
            theme::hline(ui);
        }
        theme::label(ui, &tr("{n} mots de passe vérifiés.").replace("{n}", &rep.checked.to_string()));
    }
}
