#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod broker;
mod config;
mod errcode;
mod gallery;
mod hibp;
#[cfg(feature = "devshots")]
mod devshots;
mod i18n;
mod pipe;
mod platform;
mod portable;
mod pwgen;
mod session;
mod strings;
mod theme;
mod update;
mod ui_auth;
mod ui_common;
mod ui_digicode;
mod ui_health;
mod ui_passkey;
mod ui_settings;
mod ui_setup;
mod ui_vault;
mod winplugin;

use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};

use config::Config;
use i18n::tr;
use session::*;

struct App {
    cfg: Config,
    sel: usize,
    screen: Screen,
    protected: bool,
    alert: Option<Alert>,
    job: Option<broker::Job>,
    #[cfg(feature = "devshots")]
    plan: Option<devshots::Plan>,
}

impl App {
    fn new() -> Self {
        let cfg = config::load();
        let sel = cfg.last;
        let screen = if cfg.profiles.is_empty() { new_profile_screen() } else { login_screen("") };
        let alert = config::take_load_note().map(|n| {
            let (title, body, kept, code) = match n {
                config::LoadNote::Restored { kept } => (tr("Configuration restaurée"), tr("Le fichier de configuration était illisible : la copie précédente a été utilisée. Le fichier abîmé est conservé ici : {path}").to_owned(), kept, "SV-E41"),
                config::LoadNote::Unreadable { kept } => (tr("Configuration illisible"), tr("Le fichier de configuration est illisible et aucune copie n'est utilisable. Vos coffres ne sont pas supprimés ; le fichier abîmé est conservé ici : {path}").to_owned(), kept, "SV-E40"),
                config::LoadNote::Skipped { n, kept } => (
                    tr("Profils illisibles"),
                    tr("{n} profil(s) n'ont pas pu être lus et n'apparaissent pas. Une copie du fichier d'origine est conservée ici : {path}").replace("{n}", &n.to_string()),
                    kept,
                    "SV-E42",
                ),
            };
            Alert { title: title.into(), body: body.replace("{path}", &kept.display().to_string()), close_app: false, info: false, code: code.into() }
        });
        Self {
            cfg,
            sel,
            screen,
            protected: false,
            alert,
            job: None,
            #[cfg(feature = "devshots")]
            plan: devshots::Plan::from_env(),
        }
    }

    fn lock(&mut self) {
        platform::clear_clipboard();
        self.sel = self.sel.min(self.cfg.profiles.len().saturating_sub(1));
        self.screen = if self.cfg.profiles.is_empty() { new_profile_screen() } else { login_screen("") };
    }
}

impl eframe::App for App {
    // Runs even while the window is hidden/minimized: lock as soon as Windows locks or sleeps, or
    // when the session has been idle too long (the clipboard has its own timer in `platform`).
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(250));
        let idle = matches!(&self.screen, Screen::Unlocked(s) if s.last_activity.elapsed() > Duration::from_secs(s.vault.settings.auto_lock_secs));
        if idle || (platform::take_lock_request() && matches!(self.screen, Screen::Unlocked(_) | Screen::TwoFactor { .. })) {
            self.lock();
        }
    }

    fn on_exit(&mut self) {
        platform::clear_clipboard();
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if !self.protected {
            self.protected = platform::protect_window(frame);
        }
        ctx.request_repaint_after(Duration::from_millis(250));

        broker::UNLOCKED.store(matches!(self.screen, Screen::Unlocked(_)), std::sync::atomic::Ordering::Relaxed);
        let mut next: Option<Screen> = None;
        let mut lock = false;

        match &mut self.screen {
            Screen::Unlocked(s) => {
                if ctx.input(|i| !i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO) {
                    s.last_activity = Instant::now();
                }
                if s.last_activity.elapsed() > Duration::from_secs(s.vault.settings.auto_lock_secs) {
                    lock = true;
                } else {
                    if s.clip_clear_at.is_some_and(|t| Instant::now() >= t) {
                        platform::clear_clipboard();
                        s.clip_clear_at = None;
                        s.say(tr("Presse-papier effacé"));
                    }
                    if s.toast.as_ref().is_some_and(|(_, t)| t.elapsed() > Duration::from_secs(4)) {
                        s.toast = None;
                    }
                    lock = session_ui(ui, s, &mut self.cfg);
                    if let Some(a) = s.st.moved.take() {
                        self.alert = Some(a);
                        lock = true;
                    }
                }
            }
            Screen::Login { pw, err, show_paths } => {
                egui::CentralPanel::default().show(ui, |ui| {
                    next = ui_auth::login_ui(ui, &mut self.cfg, &mut self.sel, pw, err, show_paths, &mut self.alert);
                });
            }
            Screen::NewProfile(w) => next = ui_setup::setup_ui(ui, &mut self.cfg, &mut self.sel, w),
            Screen::Import { path, pass, key_path, err } => {
                egui::CentralPanel::default().show(ui, |ui| {
                    next = ui_auth::import_ui(ui, &mut self.cfg, &mut self.sel, path, pass, key_path, err);
                });
            }
            Screen::TwoFactor { vault, decoy, code, tries, err } => {
                egui::CentralPanel::default().show(ui, |ui| {
                    next = ui_auth::two_factor_ui(ui, &mut self.cfg, self.sel, vault, *decoy, code, tries, err);
                });
            }
        }

        if lock {
            self.lock();
        } else if let Some(n) = next {
            self.screen = n;
        }

        while self.job.as_ref().is_none_or(|j| j.cancelled()) {
            match broker::take() {
                Some(j) => self.job = Some(j),
                None => {
                    self.job = None;
                    break;
                }
            }
        }
        if let Some(j) = self.job.take() {
            self.job = ui_passkey::prompt(&ctx, j, &mut self.screen);
        }

        if let Some(a) = self.alert.clone() {
            // An empty-title alert is dismissed without being drawn; otherwise it shows until closed.
            if a.title.is_empty() || show_alert(&ctx, &a) {
                self.alert = None;
                if a.close_app {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        #[cfg(feature = "devshots")]
        if let Some(mut plan) = self.plan.take() {
            devshots::drive(&ctx, self, &mut plan);
            self.plan = Some(plan);
        }
    }
}

/// Modal error-style message. Returns true once dismissed.
pub fn show_alert(ctx: &egui::Context, a: &Alert) -> bool {
    let frame = egui::Frame::new()
        .fill(theme::panel())
        .stroke(egui::Stroke::new(1.0, theme::line()))
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(24, 22));
    #[allow(deprecated)]
    let id = egui::Id::new("alert");
    let mut ok = false;
    let r = egui::Modal::new(id).frame(frame).backdrop_color(egui::Color32::from_black_alpha(170)).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.horizontal(|ui| {
            if a.info {
                theme::check(ui, theme::ok());
            } else {
                theme::error_icon(ui);
            }
            ui.label(theme::bold(&a.title).size(16.0));
        });
        ui.add_space(6.0);
        ui.label(&a.body);
        if !a.code.is_empty() {
            ui.add_space(4.0);
            ui.label(RichText::new(format!("{} {}", tr("Code :"), a.code)).size(12.0).color(theme::dim()).monospace());
        }
        ui.add_space(10.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ok = ui.add(egui::Button::new(tr("OK")).min_size(egui::vec2(72.0, 34.0))).clicked();
        });
    });
    ok || r.should_close()
}

/// Returns true when the session must lock.
fn session_ui(ui: &mut egui::Ui, s: &mut Session, cfg: &mut Config) -> bool {
    let mut lock = false;

    egui::Panel::top("top")
        .exact_size(52.0)
        .frame(
            egui::Frame::new()
                .fill(theme::panel())
                .stroke(egui::Stroke::new(1.0, theme::line()))
                .inner_margin(egui::Margin::symmetric(20, 0)),
        )
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 22.0;
                ui.allocate_ui_with_layout(egui::vec2(104.0, 52.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.set_min_size(egui::vec2(104.0, 52.0));
                    ui.label(theme::bold("Vylt").size(15.0));
                });
                ui.add_space(6.0);
                for (tab, label) in [(Tab::Vault, tr("Coffre")), (Tab::Health, tr("Santé")), (Tab::Settings, tr("Paramètres"))] {
                    if theme::tab(ui, s.tab == tab, label).clicked() {
                        s.tab = tab;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    if ui.button(tr("Verrouiller")).clicked() {
                        lock = true;
                    }
                    ui.label(RichText::new(&s.profile.name).color(theme::dim()));
                    theme::avatar(ui, &s.profile.name, s.profile.color, s.profile.avatar.as_deref(), 26.0);
                    if let Some((m, _)) = &s.toast {
                        ui.label(RichText::new(m).size(13.0).color(theme::ok()));
                    }
                });
            });
        });
    if lock {
        return true;
    }

    match s.tab {
        Tab::Vault => lock = ui_vault::vault_tab(ui, s),
        Tab::Health => {
            egui::CentralPanel::default().frame(egui::Frame::new().fill(theme::bg()).inner_margin(20)).show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| ui_health::health_tab(ui, s));
            });
        }
        Tab::Settings => ui_settings::settings_tab(ui, s, cfg, &mut lock),
    }
    lock
}

fn main() -> eframe::Result {
    platform::harden();
    config::migrate_legacy_appdata();
    if pipe::is_native_host_launch() {
        pipe::run_native_host();
        return Ok(());
    }
    // One instance per data folder: two would overwrite each other's saves.
    if !platform::single_instance(&config::data_dir()) {
        return Ok(());
    }
    platform::start_lock_watcher();
    let cfg = config::load();
    if cfg.extension && !pipe::host_manifest_points_here() {
        let _ = pipe::install();
    }
    pipe::start_server();
    winplugin::start_server();
    winplugin::reregister_if_known();
    i18n::set(cfg.lang);
    let dark = cfg.dark;
    theme::set_accent(cfg.accent);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 680.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("Vylt")
            .with_icon(std::sync::Arc::new(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")).unwrap_or_default(),
            )),
        ..Default::default()
    };
    eframe::run_native(
        "Vylt",
        options,
        Box::new(move |cc| {
            theme::apply(&cc.egui_ctx, dark);
            broker::set_context(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}
