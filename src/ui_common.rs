//! Helpers shared by the UI modules.

use eframe::egui::{self, Color32};
use vylt::lock::LockKind;

use crate::config::{self, Config};
use crate::i18n::{self, tr, Lang};
use crate::session::Secret;
use crate::theme;

pub fn centered(ui: &mut egui::Ui, width: f32, add: impl FnOnce(&mut egui::Ui)) {
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.14).max(10.0));
        ui.allocate_ui_with_layout(egui::vec2(width, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.set_width(width);
            add(ui);
        });
    });
}

pub fn password_field(ui: &mut egui::Ui, s: &mut Secret, hint: &str) -> egui::Response {
    let r = ui.add(egui::TextEdit::singleline(&mut **s).password(true).hint_text(hint).desired_width(f32::INFINITY));
    no_history(ui, &r);
    r
}

/// egui keeps an undo history (copies of the text) for every text field: never for secrets.
pub fn no_history(ui: &egui::Ui, r: &egui::Response) {
    if let Some(mut st) = egui::text_edit::TextEditState::load(ui.ctx(), r.id) {
        st.clear_undoer();
        st.store(ui.ctx(), r.id);
    }
}

pub fn name_issue_text(i: &config::NameIssue) -> &'static str {
    match i {
        config::NameIssue::Empty => tr("Veuillez saisir un nom de profil."),
        config::NameIssue::TooLong => tr("64 caractères maximum."),
        config::NameIssue::Reserved => tr("Ce nom est réservé par Windows. Choisissez-en un autre."),
    }
}

pub fn lock_label(k: LockKind) -> &'static str {
    match k {
        LockKind::Pin4 => tr("Code PIN à 4 chiffres"),
        LockKind::Pin6 => tr("Code PIN à 6 chiffres"),
        LockKind::Pin8 => tr("Code PIN à 8 chiffres"),
        LockKind::Alpha => tr("Code alphanumérique (6 à 32 caractères)"),
    }
}

pub fn lock_error(k: LockKind) -> &'static str {
    match k {
        LockKind::Pin4 => tr("4 chiffres exactement."),
        LockKind::Pin6 => tr("6 chiffres exactement."),
        LockKind::Pin8 => tr("8 chiffres exactement."),
        LockKind::Alpha => tr("6 à 32 lettres ou chiffres."),
    }
}

/// Label and colour for a zxcvbn score (0..=4).
pub fn strength(score: u8) -> (&'static str, Color32) {
    match score {
        0 => (tr("très faible"), theme::danger()),
        1 => (tr("faible"), theme::danger()),
        2 => (tr("moyenne"), theme::dim()),
        3 => (tr("forte"), theme::ok()),
        _ => (tr("excellente"), theme::ok()),
    }
}

/// Language + theme pickers; persists the choice.
pub fn appearance_bar(ui: &mut egui::Ui, cfg: &mut Config) {
    ui.horizontal(|ui| {
        let mut changed = false;
        egui::ComboBox::from_id_salt("lang").selected_text(i18n::get().name()).show_ui(ui, |ui| {
            for l in Lang::ALL {
                if ui.selectable_label(i18n::get() == l, l.name()).clicked() {
                    cfg.lang = l;
                    i18n::set(l);
                    changed = true;
                }
            }
        });
        let label = if cfg.dark { tr("Thème clair") } else { tr("Thème sombre") };
        if ui.button(label).clicked() {
            cfg.dark = !cfg.dark;
            theme::apply(ui.ctx(), cfg.dark);
            changed = true;
        }
        if changed {
            config::save(cfg);
        }
    });
}
