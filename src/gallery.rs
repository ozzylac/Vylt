//! Suggested profile pictures: the Bing wallpapers Windows saves in Pictures\BingWallpapers.
//! Decoded and cropped to small square thumbnails on a background thread.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use eframe::egui::{self, Stroke, Vec2};

use crate::theme;

const MAX: usize = 12;
const SIDE: u32 = 112;

fn folder() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join("Pictures").join("BingWallpapers"))
}

fn ready() -> &'static Mutex<Vec<(PathBuf, egui::ColorImage)>> {
    static READY: OnceLock<Mutex<Vec<(PathBuf, egui::ColorImage)>>> = OnceLock::new();
    READY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Newest first, `MAX` at most.
fn list() -> Vec<PathBuf> {
    let Some(dir) = folder() else { return Vec::new() };
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| matches!(x.to_ascii_lowercase().to_str(), Some("jpg" | "jpeg" | "png"))))
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .collect();
    files.sort_by_key(|e| std::cmp::Reverse(e.0));
    files.into_iter().take(MAX).map(|(_, p)| p).collect()
}

fn start(ctx: egui::Context) {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::spawn(move || {
        for path in list() {
            let Ok(img) = image::open(&path) else { continue };
            let side = img.width().min(img.height());
            let sq = img.crop_imm((img.width() - side) / 2, (img.height() - side) / 2, side, side).thumbnail_exact(SIDE, SIDE).to_rgba8();
            let color = egui::ColorImage::from_rgba_unmultiplied([SIDE as usize, SIDE as usize], sq.as_raw());
            if let Ok(mut r) = ready().lock() {
                r.push((path, color));
            }
            ctx.request_repaint();
        }
    });
}

thread_local! {
    static TEXTURES: RefCell<Vec<(PathBuf, egui::TextureHandle)>> = const { RefCell::new(Vec::new()) };
}

fn thumbnails(ctx: &egui::Context) -> Vec<(PathBuf, egui::TextureHandle)> {
    start(ctx.clone());
    let fresh: Vec<_> = ready().lock().map(|mut r| std::mem::take(&mut *r)).unwrap_or_default();
    TEXTURES.with(|t| {
        let mut t = t.borrow_mut();
        for (p, img) in fresh {
            let tex = ctx.load_texture(format!("bing:{}", p.display()), img, egui::TextureOptions::LINEAR);
            t.push((p, tex));
        }
        t.clone()
    })
}

/// Row(s) of round thumbnails. Returns the clicked image's path.
pub fn picker(ui: &mut egui::Ui, selected: Option<&Path>) -> Option<PathBuf> {
    let thumbs = thumbnails(ui.ctx());
    if thumbs.is_empty() {
        return None;
    }
    let mut picked = None;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
        for (path, tex) in &thumbs {
            let (rect, r) = ui.allocate_exact_size(Vec2::splat(48.0), egui::Sense::click());
            egui::Image::new(tex).corner_radius(24.0).paint_at(ui, rect.shrink(3.0));
            let on = selected == Some(path.as_path());
            if on {
                ui.painter().circle_stroke(rect.center(), 23.5, Stroke::new(2.0, theme::accent()));
            } else if r.hovered() {
                ui.painter().circle_stroke(rect.center(), 23.5, Stroke::new(1.0, theme::dim()));
            }
            if r.clicked() {
                picked = Some(path.clone());
            }
        }
    });
    picked
}
