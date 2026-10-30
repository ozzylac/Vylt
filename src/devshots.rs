//! Development only (cargo feature `devshots`, never in a normal build): renders the app's own
//! frames to PNG through egui, so the UI can be reviewed without any screen capture or keystrokes.
//! Needs the demo profile from `examples/seed_demo.rs` and `VYLT_SHOTS=<output dir>`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui;
use vylt::decoy;

use crate::session::*;
use crate::{theme, App};

const DEMO_PASSWORD: &str = "demo-passphrase-2026";
const STEPS: [&str; 24] = [
    "01-connexion",
    "02-coffre",
    "03-digicode",
    "04-edition",
    "05-sante",
    "06-reglages",
    "07-clair",
    "08-digicode-saisie",
    "09-digicode-erreur",
    "10-anglais",
    "11-destruction",
    "12-perso",
    "13-actions",
    "14-message",
    "15-setup-profil",
    "16-setup-mdp",
    "17-setup-cle",
    "18-setup-recap",
    "19-mode-portable",
    "20-passkey-enregistrer",
    "21-passkey-connexion",
    "22-passkey-reglages",
    "23-passkey-entree",
    "24-profils-lies",
];

pub struct Plan {
    dir: PathBuf,
    step: usize,
    settle: u32,
    requested: bool,
    done: Arc<AtomicBool>,
    since: std::time::Instant,
}

impl Plan {
    pub fn from_env() -> Option<Self> {
        let dir = PathBuf::from(std::env::var_os("VYLT_SHOTS")?);
        std::fs::create_dir_all(&dir).ok()?;
        Some(Self { dir, step: 0, settle: 0, requested: false, done: Arc::new(AtomicBool::new(false)), since: std::time::Instant::now() })
    }
}

fn save(path: &std::path::Path, image: &egui::ColorImage) {
    let [w, h] = image.size;
    let mut data = Vec::with_capacity(w * h * 4);
    for p in &image.pixels {
        data.extend_from_slice(&p.to_array());
    }
    if let Ok(f) = std::fs::File::create(path) {
        let mut enc = png::Encoder::new(std::io::BufWriter::new(f), w as u32, h as u32);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        if let Ok(mut wr) = enc.write_header() {
            let _ = wr.write_image_data(&data);
        }
    }
}

fn demo_create() -> crate::broker::Request {
    crate::broker::Request::Create(crate::broker::CreateReq {
        rp_id: "github.com".into(),
        rp_name: "GitHub".into(),
        user_name: "zatheo.man@gmail.com".into(),
        user_display: "ozzylac".into(),
        user_handle: b"demo-user".to_vec(),
        exclude: Vec::new(),
        client: crate::broker::ClientData::Build { origin: "https://github.com".into(), challenge: b"demo".to_vec(), cross_origin: false },
    })
}

/// Queue a passkey request as the extension would (answered by dropping the job).
fn demo_request(create: bool) {
    std::thread::spawn(move || {
        let req = if create {
            demo_create()
        } else {
            crate::broker::Request::Get(crate::broker::GetReq {
                rp_id: "github.com".into(),
                allow: Vec::new(),
                client: crate::broker::ClientData::Build { origin: "https://github.com".into(), challenge: b"demo".to_vec(), cross_origin: false },
            })
        };
        crate::broker::submit(req, std::time::Duration::from_secs(30));
    });
}

/// Put the app in the state of scene `step`.
fn setup(ctx: &egui::Context, app: &mut App, step: usize) {
    app.job = None;
    if (14..=17).contains(&step) {
        let mut w = Setup::default();
        w.step = step - 14;
        if step > 14 {
            w.name = "ozzylac".into();
            w.name_touched = true;
        }
        w.pw = zeroize::Zeroizing::new("correct cheval batterie agrafe".into());
        w.pw2 = w.pw.clone();
        w.tfa = step == 17;
        app.screen = Screen::NewProfile(Box::new(w));
        return;
    }
    if step == 1 || step == 18 {
        let Some(p) = app.cfg.profiles.first().cloned() else { return };
        let opened = p.secret_key().and_then(|sk| decoy::open_either(&p.vault_path, DEMO_PASSWORD, &sk));
        if let Ok(o) = opened {
            app.screen = Screen::Unlocked(Box::new(Session::new(o.vault, p, false)));
        }
    }
    if let Screen::Unlocked(s) = &mut app.screen {
        s.reset_reveal();
        s.edit = None;
        match step {
            1 => {
                s.tab = Tab::Vault;
                s.selected = Some(0);
            }
            2 => s.selected = Some(2),
            3 => {
                s.selected = Some(0);
                let e = s.entries()[0].clone();
                s.edit = Some(Edit::new(Some(0), e));
            }
            4 => s.tab = Tab::Health,
            5 => s.tab = Tab::Settings,
            6 => {
                theme::apply(ctx, false);
                s.tab = Tab::Vault;
                s.selected = Some(0);
            }
            7 => {
                theme::apply(ctx, true);
                s.tab = Tab::Vault;
                s.selected = Some(2);
                s.entry_code = zeroize::Zeroizing::new("123".into());
            }
            8 => {
                s.selected = Some(2);
                s.entry_fails = 1;
            }
            9 => {
                crate::i18n::set(crate::i18n::Lang::En);
                s.tab = Tab::Settings;
            }
            10 => {
                crate::i18n::set(crate::i18n::Lang::Fr);
                s.tab = Tab::Settings;
                s.st.section = Section::Destroy;
            }
            11 => {
                s.st.section = Section::Appearance;
                theme::set_accent(1);
                theme::apply(ctx, true);
            }
            12 => {
                theme::set_accent(0);
                theme::apply(ctx, true);
                s.st.section = Section::Destroy;
                s.st.dest_tab = 2;
                let mut a = vylt::destroy::Actions::default();
                a.show_message = true;
                a.title = crate::i18n::tr("Erreur de lecture du profil").into();
                a.body = crate::i18n::tr("Le fichier de session est corrompu (code 0x8007045D). Les données n'ont pas pu être chargées.").into();
                a.run = true;
                a.program = r"C:\Outils\alerte.exe".into();
                a.args = "--profil Zatheo".into();
                s.st.act = Some(a);
            }
            13 => {
                s.st.preview = s.st.act.as_ref().map(|a| Alert { title: a.title.clone(), body: a.body.clone(), close_app: false, info: false, code: String::new() });
            }
            18 => {
                s.tab = Tab::Settings;
                s.st.section = Section::Portable;
            }
            19 => {
                s.tab = Tab::Vault;
                demo_request(true);
            }
            20 => {
                if let Some(i) = s.vault.entries.iter().position(|e| crate::broker::site_matches(&e.site, "github.com")) {
                    if let crate::broker::Request::Create(c) = demo_create() {
                        let _ = crate::broker::create_in(&mut s.vault.entries, Some(i), &c);
                    }
                }
                demo_request(false);
            }
            21 => {
                s.tab = Tab::Settings;
                s.st.section = Section::Passkeys;
            }
            22 => {
                s.tab = Tab::Vault;
                s.selected = s.vault.entries.iter().position(|e| !e.passkeys.is_empty());
            }
            23 => {
                s.tab = Tab::Settings;
                s.st.section = Section::Destroy;
                s.st.dest_tab = 1;
            }
            _ => {}
        }
    }
}

pub fn drive(ctx: &egui::Context, app: &mut App, plan: &mut Plan) {
    if plan.requested && plan.done.load(Ordering::SeqCst) {
        plan.step += 1;
        plan.settle = 0;
        plan.since = std::time::Instant::now();
        plan.requested = false;
        plan.done.store(false, Ordering::SeqCst);
        if plan.step >= STEPS.len() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        setup(ctx, app, plan.step);
    }
    plan.settle += 1;
    if plan.settle > 40 && plan.since.elapsed().as_secs_f32() > 1.5 && !plan.requested {
        plan.requested = true;
        let path = plan.dir.join(format!("{}.png", STEPS[plan.step]));
        let done = plan.done.clone();
        ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::ScreenshotCallback::new(move |img| {
            save(&path, &img);
            done.store(true, Ordering::SeqCst);
        })));
    }
    ctx.request_repaint();
}
