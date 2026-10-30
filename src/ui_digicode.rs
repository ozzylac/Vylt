//! Digicode pop-up for numeric entry codes (6 or 8 digits; 4 for entries created earlier).
//! Dots show progress, never the digits. The code is checked on the last digit.

use eframe::egui::{self, Color32, Pos2, RichText, Sense, Shape, Stroke, Vec2};
use vylt::lock::{EntryLock, LockKind};
use zeroize::Zeroize;

use crate::i18n::tr;
use crate::session::*;
use crate::theme;

pub enum Outcome {
    Stay,
    Close,
    Lock,
}

pub fn digits_of(kind: LockKind) -> Option<usize> {
    match kind {
        LockKind::Pin4 => Some(4),
        LockKind::Pin6 => Some(6),
        LockKind::Pin8 => Some(8),
        LockKind::Alpha => None,
    }
}

const KEY: [f32; 2] = [84.0, 56.0];
const WIDTH: f32 = 292.0;
/// Left padding that centers the 3 keys (3 x 84 + 2 x 10) inside WIDTH.
const PAD: f32 = (WIDTH - (3.0 * KEY[0] + 20.0)) / 2.0;

fn key(ui: &mut egui::Ui, text: RichText) -> bool {
    ui.add_sized(KEY, egui::Button::new(text).corner_radius(10)).clicked()
}

fn backspace(ui: &mut egui::Ui) -> bool {
    let r = ui.add_sized(KEY, egui::Button::new("").corner_radius(10));
    let c = r.rect.center();
    let p = |x: f32, y: f32| Pos2::new(c.x + x, c.y + y);
    let s = Stroke::new(1.7, theme::text());
    ui.painter().add(Shape::closed_line(vec![p(-4.0, -9.0), p(10.0, -9.0), p(10.0, 9.0), p(-4.0, 9.0), p(-12.0, 0.0)], s));
    ui.painter().line_segment([p(0.0, -4.0), p(6.0, 4.0)], s);
    ui.painter().line_segment([p(6.0, -4.0), p(0.0, 4.0)], s);
    r.clicked()
}

pub fn show(ctx: &egui::Context, s: &mut Session, i: usize, gate: &EntryLock, title: &str) -> Outcome {
    let n = digits_of(gate.kind).unwrap_or(6);
    // Keep typing away from any text field behind the pop-up.
    ctx.memory_mut(|m| {
        if let Some(id) = m.focused() {
            m.surrender_focus(id);
        }
    });

    let mut input: Vec<char> = Vec::new();
    let (mut back, mut clear, mut close) = (false, false, false);
    ctx.input(|inp| {
        for e in &inp.events {
            match e {
                egui::Event::Text(t) => input.extend(t.chars().filter(char::is_ascii_digit)),
                egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => back = true,
                _ => {}
            }
        }
    });

    let entered = s.entry_code.chars().count();
    let failed = s.entry_fails > 0 && entered == 0;
    let left = 3u8.saturating_sub(s.entry_fails);

    let frame = egui::Frame::new()
        .fill(theme::panel())
        .stroke(Stroke::new(1.0, theme::line()))
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(24, 20));
    #[allow(deprecated)]
    let id = egui::Id::new("digicode");
    let resp = egui::Modal::new(id)
        .frame(frame)
        .backdrop_color(Color32::from_black_alpha(170))
        .show(ctx, |ui| {
            ui.set_width(WIDTH);
            ui.horizontal(|ui| {
                theme::padlock(ui, 16.0, theme::dim());
                ui.label(theme::bold(title).size(15.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::link(ui, tr("Fermer")).clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(4.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(tr("Saisissez votre code à {n} chiffres").replace("{n}", &n.to_string())).size(13.0).color(theme::dim()));
                ui.add_space(10.0);

                // progress dots
                let gap = if n > 6 { 10.0 } else { 14.0 };
                let total = n as f32 * 14.0 + (n as f32 - 1.0) * gap;
                let (rect, _) = ui.allocate_exact_size(Vec2::new(WIDTH, 28.0), Sense::hover());
                let x0 = rect.center().x - total / 2.0 + 7.0;
                for k in 0..n {
                    let c = Pos2::new(x0 + k as f32 * (14.0 + gap), rect.center().y);
                    let p = ui.painter();
                    if failed {
                        p.circle_filled(c, 7.0, theme::danger());
                    } else if k < entered {
                        p.circle_filled(c, 7.0, theme::text());
                    } else if k == entered {
                        p.circle_stroke(c, 6.0, Stroke::new(2.0, theme::accent()));
                    } else {
                        p.circle_stroke(c, 6.25, Stroke::new(1.5, theme::dim().linear_multiply(0.6)));
                    }
                }
                ui.allocate_ui(Vec2::new(WIDTH, 22.0), |ui| {
                    ui.set_min_height(22.0);
                    if s.entry_wait > 0 && entered == 0 {
                        let msg = tr("Trop d'essais. Réessayez dans {n} s.").replace("{n}", &s.entry_wait.to_string());
                        ui.label(RichText::new(msg).size(13.0).color(theme::danger()));
                    } else if failed {
                        let msg = tr("Code incorrect. Tentatives restantes : {n}.").replace("{n}", &left.to_string());
                        ui.label(RichText::new(msg).size(13.0).color(theme::danger()));
                    }
                });
                ui.add_space(4.0);

                ui.spacing_mut().item_spacing = Vec2::new(10.0, 10.0);
                ui.spacing_mut().button_padding = Vec2::new(4.0, 4.0);
                for row in [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"]] {
                    ui.horizontal(|ui| {
                        ui.add_space(PAD);
                        for d in row {
                            if key(ui, RichText::new(d).monospace().size(22.0)) {
                                input.extend(d.chars());
                            }
                        }
                    });
                }
                ui.horizontal(|ui| {
                    ui.add_space(PAD);
                    if key(ui, RichText::new(tr("Effacer tout")).size(13.0).color(theme::dim())) {
                        clear = true;
                    }
                    if key(ui, RichText::new("0").monospace().size(22.0)) {
                        input.push('0');
                    }
                    if backspace(ui) {
                        back = true;
                    }
                });
                ui.add_space(8.0);
                ui.label(RichText::new(tr("Validation automatique au dernier chiffre. Le clavier de l'ordinateur est également pris en charge.")).size(12.0).color(theme::dim()));
            });
        });

    if close || resp.should_close() {
        s.entry_code.zeroize();
        return Outcome::Close;
    }
    if clear {
        s.entry_code.zeroize();
    }
    if back {
        s.entry_code.pop();
    }
    for ch in input {
        if s.entry_code.chars().count() < n {
            s.entry_code.push(ch);
        }
    }
    if s.entry_code.chars().count() == n {
        let code = s.entry_code.clone();
        s.entry_code.zeroize();
        if !s.try_entry_code(i, &code) && s.entry_wait == 0 && s.entry_fails >= 3 {
            return Outcome::Lock;
        }
    }
    Outcome::Stay
}
