//! Prompt shown when a site creates or uses a passkey (browser extension or Windows).

use eframe::egui::{self, RichText, Stroke, Vec2};
use vylt::decoy;
use vylt::vault::Entry;
use zeroize::Zeroize;

use crate::broker::{self, Job, PromptState, Reply, Request};
use vylt::lock::{Attempt, EntryLock};
use crate::i18n::tr;
use crate::session::*;
use crate::theme;
use crate::ui_common::*;

/// Every list of entries the open session can reach: the vault, then each open hidden category.
fn lists(s: &mut Session) -> Vec<&mut Vec<Entry>> {
    std::iter::once(&mut s.vault.entries).chain(s.open.iter_mut().map(|b| &mut b.entries)).collect()
}

/// Draw the prompt for `job`. Returns the job back while it still waits for the user.
pub fn prompt(ctx: &egui::Context, mut job: Job, screen: &mut Screen) -> Option<Job> {
    let Screen::Unlocked(s) = screen else {
        return locked_banner(ctx, job);
    };
    match &job.req {
        Request::Get(g) => {
            let found: Vec<(usize, usize, usize)> = lists(s)
                .iter()
                .enumerate()
                .flat_map(|(l, es)| broker::candidates(es.as_slice(), g).into_iter().map(move |(e, p)| (l, e, p)))
                .collect();
            if found.is_empty() {
                job.answer(Reply::Declined);
                return None;
            }
            let rows: Vec<(String, String, Option<EntryLock>)> = {
                let ls = lists(s);
                found
                    .iter()
                    .map(|&(l, e, p)| {
                        let (en, pk) = (&ls[l][e], &ls[l][e].passkeys[p]);
                        let used = if pk.last_used == 0 { tr("jamais utilisée").to_owned() } else { format!("{} {}", tr("dernière connexion le"), crate::ui_settings::fmt_date(pk.last_used)) };
                        (pk.user_name.clone(), format!("{} · {used}", en.site), en.lock.clone())
                    })
                    .collect()
            };
            let rp = g.rp_id.clone();
            let mut done = None;
            modal(ctx, tr("Se connecter avec une clé d'accès"), |ui| {
                ui.label(format!("{} {rp}. {}", tr("Connexion à"), tr("Choisissez le compte :")));
                ui.add_space(6.0);
                for (i, (user, sub, _)) in rows.iter().enumerate() {
                    if row(ui, job.ui.choice == i, user, sub) {
                        job.ui.choice = i;
                    }
                }
                let gate = rows.get(job.ui.choice).and_then(|r| r.2.clone());
                done = footer(ui, s, &mut job.ui, gate, tr("Se connecter"), tr("Annuler"));
            });
            match done {
                Some(true) => {
                    let (l, e, p) = found[job.ui.choice.min(found.len() - 1)];
                    if rows[job.ui.choice.min(found.len() - 1)].2.is_some() && !pass_gate(s, l, e, &mut job.ui) {
                        return Some(job);
                    }
                    let res = { broker::assert_with(lists(s)[l], e, p, g) };
                    finish(s, job, res, tr("Connexion par clé d'accès effectuée"))
                }
                Some(false) => {
                    job.answer(Reply::Declined);
                    None
                }
                None => Some(job),
            }
        }
        Request::Create(c) => {
            if lists(s).iter().any(|es| broker::is_excluded(es.as_slice(), c)) {
                job.answer(Reply::Excluded);
                return None;
            }
            let found: Vec<(usize, usize)> = lists(s)
                .iter()
                .enumerate()
                .flat_map(|(l, es)| es.iter().enumerate().filter(|(_, e)| broker::site_matches(&e.site, &c.rp_id)).map(move |(i, _)| (l, i)))
                .collect();
            let rows: Vec<(String, String, Option<EntryLock>)> = {
                let ls = lists(s);
                found.iter().map(|&(l, i)| (ls[l][i].site.clone(), ls[l][i].username.clone(), ls[l][i].lock.clone())).collect()
            };
            let (rp, user) = (c.rp_id.clone(), if c.user_name.is_empty() { c.user_display.clone() } else { c.user_name.clone() });
            let mut done = None;
            modal(ctx, tr("Enregistrer une clé d'accès"), |ui| {
                ui.label(tr("{rp} souhaite créer une clé d'accès pour {user}.").replace("{rp}", &rp).replace("{user}", &user));
                ui.add_space(6.0);
                theme::label(ui, tr("Ajouter à l'entrée"));
                for (i, (site, name, _)) in rows.iter().enumerate() {
                    if row(ui, job.ui.choice == i, site, name) {
                        job.ui.choice = i;
                    }
                }
                if row(ui, job.ui.choice >= rows.len(), tr("Nouvelle entrée"), &format!("{rp} · {user}")) {
                    job.ui.choice = rows.len();
                }
                let gate = rows.get(job.ui.choice).and_then(|r| r.2.clone());
                done = footer(ui, s, &mut job.ui, gate, tr("Enregistrer"), tr("Refuser"));
            });
            match done {
                Some(true) => {
                    if let Some(&(l, i)) = found.get(job.ui.choice).filter(|_| rows.get(job.ui.choice).is_some_and(|r| r.2.is_some()))
                        && !pass_gate(s, l, i, &mut job.ui)
                    {
                        return Some(job);
                    }
                    let res = match found.get(job.ui.choice) {
                        Some(&(l, i)) => broker::create_in(lists(s)[l], Some(i), c),
                        None => broker::create_in(&mut s.vault.entries, None, c),
                    };
                    finish(s, job, res, tr("Clé d'accès enregistrée"))
                }
                Some(false) => {
                    job.answer(Reply::Declined);
                    None
                }
                None => Some(job),
            }
        }
    }
}

fn finish(s: &mut Session, job: Job, res: Result<Reply, String>, ok: &str) -> Option<Job> {
    match res {
        Ok(r) => {
            s.persist();
            sync_windows(s);
            s.say(ok);
            job.answer(r);
        }
        Err(e) => job.answer(Reply::Error(e)),
    }
    None
}

/// Tell Windows the current set of this profile's (main-vault) passkeys.
pub fn sync_windows(s: &Session) {
    let pks: Vec<&vylt::passkey::Passkey> = s.vault.entries.iter().flat_map(|e| &e.passkeys).collect();
    crate::winplugin::sync(&pks);
}

/// Optional checks, then the two buttons. Some(true) = go (verified), Some(false) = refused.
fn footer(ui: &mut egui::Ui, s: &mut Session, job: &mut PromptState, gate: Option<EntryLock>, go: &str, no: &str) -> Option<bool> {
    let ask_pw = s.vault.settings.passkey_password;
    if ask_pw {
        ui.add_space(8.0);
        theme::label(ui, tr("Mot de passe maître"));
        password_field(ui, &mut job.pw, "");
    }
    if gate.is_some() {
        ui.add_space(8.0);
        theme::label(ui, tr("Code de l'entrée"));
        password_field(ui, &mut job.code, "");
    }
    theme::error(ui, &job.err);
    let mut out = None;
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let ok = ui.add(egui::Button::new(theme::bold(go).color(theme::on_accent())).fill(theme::accent()).stroke(Stroke::NONE).min_size(Vec2::new(120.0, 36.0)));
            if ui.add(egui::Button::new(no).min_size(Vec2::new(0.0, 36.0))).clicked() {
                out = Some(false);
            }
            if ok.clicked() {
                out = Some(true);
            }
        });
    });
    if out == Some(true) && ask_pw {
        let same = s.profile.secret_key().and_then(|sk| decoy::open_either(&s.profile.vault_path, &job.pw, &sk)).is_ok_and(|o| o.is_decoy == s.is_decoy);
        job.pw.zeroize();
        if !same {
            job.err = tr("Identifiants invalides.").into();
            return None;
        }
    }
    out
}

/// The entry's code gate, counted and saved exactly as in the vault view.
fn pass_gate(s: &mut Session, l: usize, e: usize, job: &mut PromptState) -> bool {
    let code = job.code.clone();
    job.code.zeroize();
    let now = crate::config::now_secs();
    let r = lists(s)[l].get_mut(e).and_then(|x| x.lock.as_mut()).map(|g| g.attempt(&code, now));
    s.persist();
    match r {
        None | Some(Attempt::Ok) => true,
        Some(Attempt::Wait(n)) => {
            job.err = tr("Trop d'essais. Réessayez dans {n} s.").replace("{n}", &n.to_string());
            false
        }
        Some(Attempt::Wrong) => {
            job.err = tr("Code incorrect").into();
            false
        }
    }
}

fn row(ui: &mut egui::Ui, on: bool, title: &str, sub: &str) -> bool {
    egui::Frame::new()
        .fill(if on { theme::selected_fill() } else { egui::Color32::TRANSPARENT })
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), egui::Sense::hover());
                if on {
                    ui.painter().circle_stroke(rect.center(), 7.0, Stroke::new(2.0, theme::accent()));
                    ui.painter().circle_filled(rect.center(), 3.5, theme::accent());
                } else {
                    ui.painter().circle_stroke(rect.center(), 7.25, Stroke::new(1.5, theme::dim()));
                }
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(theme::bold(title));
                    theme::label(ui, sub);
                });
            });
        })
        .response
        .interact(egui::Sense::click())
        .clicked()
}

fn modal(ctx: &egui::Context, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    let frame = egui::Frame::new()
        .fill(theme::panel())
        .stroke(Stroke::new(1.0, theme::line()))
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(24, 22));
    #[allow(deprecated)]
    let id = egui::Id::new("passkey-prompt");
    egui::Modal::new(id).frame(frame).backdrop_color(egui::Color32::from_black_alpha(170)).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.horizontal(|ui| {
            ui.label(theme::bold(title).size(16.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| theme::label(ui, "Vylt"));
        });
        ui.add_space(6.0);
        add(ui);
    });
}

/// The vault is locked: say what is waiting; the normal sign-in screen stays usable below.
fn locked_banner(ctx: &egui::Context, job: Job) -> Option<Job> {
    let mut decline = false;
    #[allow(deprecated)]
    egui::Area::new(egui::Id::new("passkey-banner"))
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::CENTER_TOP, Vec2::new(0.0, 12.0))
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(theme::panel())
                .stroke(Stroke::new(1.0, theme::accent()))
                .corner_radius(10)
                .inner_margin(egui::Margin::symmetric(16, 10))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr("{rp} demande une clé d'accès. Déverrouillez Vylt pour continuer.").replace("{rp}", job.req.rp_id())));
                        decline = theme::link(ui, tr("Laisser le navigateur gérer")).clicked();
                    });
                });
        });
    if decline {
        job.answer(Reply::Declined);
        return None;
    }
    Some(job)
}
