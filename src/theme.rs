//! Design system: warm neutrals, one brass accent, IBM Plex. Dark and light palettes.
//!
//! Rules (from the mockups): the accent only marks primary actions, the current selection and
//! live state; sections are separated by hairlines, not boxed in cards; site tiles are neutral.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use eframe::egui::{
    self, Align2, Color32, FontData, FontDefinitions, FontFamily, FontId, Pos2, Rect, RichText, Sense, Shape, Stroke,
    TextStyle, Vec2,
};

static DARK: AtomicBool = AtomicBool::new(true);
static ACCENT: AtomicU8 = AtomicU8::new(0);

/// App accent choices: (dark theme color, light theme color, text on it in dark, in light).
/// Red and green are kept for danger / success, so they are not offered here.
pub const ACCENTS: [(u32, u32, u32, u32); 6] = [
    (0xD6A24A, 0x8A5A00, 0x17120A, 0xFFFFFF), // laiton
    (0x6EA8FE, 0x1F5FBF, 0x0B1526, 0xFFFFFF), // bleu
    (0x4FC1B0, 0x0F6E63, 0x06201C, 0xFFFFFF), // sarcelle
    (0xA98BFA, 0x5B3FC4, 0x160D2E, 0xFFFFFF), // violet
    (0xF08A9C, 0xA8324A, 0x2A0A12, 0xFFFFFF), // corail
    (0xB8BCC6, 0x4A5160, 0x14161B, 0xFFFFFF), // ardoise
];

pub fn set_accent(i: u8) {
    ACCENT.store(i % ACCENTS.len() as u8, Ordering::Relaxed);
}

pub fn accent_index() -> u8 {
    ACCENT.load(Ordering::Relaxed)
}

/// Swatch color of accent `i` in the current theme.
pub fn accent_of(i: u8) -> Color32 {
    let a = ACCENTS[i as usize % ACCENTS.len()];
    pick(a.0, a.1)
}

fn pick(dark: u32, light: u32) -> Color32 {
    let v = if DARK.load(Ordering::Relaxed) { dark } else { light };
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

pub fn bg() -> Color32 {
    pick(0x131316, 0xF6F4EF)
}
pub fn panel() -> Color32 {
    pick(0x19191D, 0xEDEAE3)
}
/// Text inputs and recessed fields.
pub fn raise() -> Color32 {
    pick(0x0F0F11, 0xFFFFFF)
}
pub fn line() -> Color32 {
    pick(0x2B2B31, 0xD9D5CB)
}
pub fn text() -> Color32 {
    pick(0xEDEBE6, 0x1D1B17)
}
pub fn dim() -> Color32 {
    pick(0xA29F96, 0x6A665C)
}
pub fn accent() -> Color32 {
    accent_of(accent_index())
}
/// Text drawn on top of an accent-filled button.
pub fn on_accent() -> Color32 {
    let a = ACCENTS[accent_index() as usize % ACCENTS.len()];
    pick(a.2, a.3)
}
pub fn ok() -> Color32 {
    pick(0x5CC38A, 0x1F7A4D)
}
pub fn danger() -> Color32 {
    pick(0xFF7B72, 0xB3261E)
}
pub fn tile_fill() -> Color32 {
    pick(0x26262B, 0xE0DCD2)
}
/// Row tint for the selected item.
pub fn selected_fill() -> Color32 {
    accent().linear_multiply(0.14)
}

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn bold(s: impl Into<String>) -> RichText {
    RichText::new(s).family(semibold())
}

fn install_fonts(ctx: &egui::Context) {
    let mut f = FontDefinitions::default();
    f.font_data.insert("plex".into(), FontData::from_static(include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf")).into());
    f.font_data.insert("plex-semi".into(), FontData::from_static(include_bytes!("../assets/fonts/IBMPlexSans-SemiBold.ttf")).into());
    f.font_data.insert("plex-mono".into(), FontData::from_static(include_bytes!("../assets/fonts/IBMPlexMono-Medium.ttf")).into());
    f.families.entry(FontFamily::Proportional).or_default().insert(0, "plex".into());
    f.families.entry(FontFamily::Monospace).or_default().insert(0, "plex-mono".into());
    f.families.insert(semibold(), vec!["plex-semi".into(), "plex".into()]);
    ctx.set_fonts(f);
}

pub fn apply(ctx: &egui::Context, dark: bool) {
    DARK.store(dark, Ordering::Relaxed);
    install_fonts(ctx);

    let mut v = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.panel_fill = bg();
    v.window_fill = panel();
    v.extreme_bg_color = raise();
    v.faint_bg_color = panel();
    v.selection.bg_fill = accent().linear_multiply(0.30);
    v.selection.stroke = Stroke::new(1.5, accent());
    v.hyperlink_color = accent();
    let hover = pick(0x222226, 0xE3DFD6);
    for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
        w.corner_radius = 8.into();
        w.fg_stroke = Stroke::new(1.0, text());
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, line());
    // Slider rails and checkbox boxes use bg_fill; buttons use weak_bg_fill (kept transparent).
    v.widgets.inactive.bg_fill = line();
    v.widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, line());
    v.widgets.hovered.bg_fill = hover;
    v.widgets.hovered.weak_bg_fill = hover;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, dim());
    v.widgets.active.bg_fill = accent().linear_multiply(0.25);
    v.widgets.active.weak_bg_fill = accent().linear_multiply(0.25);
    v.widgets.active.bg_stroke = Stroke::new(1.0, accent());
    // Follow our own setting, not the Windows theme: set both slots and pin the preference.
    ctx.set_theme(if dark { egui::Theme::Dark } else { egui::Theme::Light });
    ctx.set_visuals_of(egui::Theme::Dark, v.clone());
    ctx.set_visuals_of(egui::Theme::Light, v);

    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = Vec2::new(10.0, 8.0);
        s.spacing.button_padding = Vec2::new(14.0, 6.0);
        s.spacing.interact_size.y = 32.0;
        s.spacing.text_edit_width = 280.0;
        // Fixed product scale (ratio ~1.2): 12 / 14 / 16 / 20.
        s.text_styles.insert(TextStyle::Small, FontId::proportional(12.0));
        s.text_styles.insert(TextStyle::Body, FontId::proportional(14.0));
        s.text_styles.insert(TextStyle::Button, FontId::proportional(14.0));
        s.text_styles.insert(TextStyle::Heading, FontId::new(20.0, semibold()));
        s.text_styles.insert(TextStyle::Monospace, FontId::monospace(14.0));
    });
}

// ---------------------------------------------------------------- layout

/// Hairline separator.
pub fn hline(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, line());
}

/// A flat section: top hairline, then content. No box, no fill.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    hline(ui);
    ui.add_space(4.0);
    let r = add(ui);
    ui.add_space(8.0);
    r
}

/// `label` on the left (fixed column), content on the right, hairline below.
pub fn field_row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui)) {
    hline(ui);
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(Vec2::new(120.0, 24.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.set_min_size(Vec2::new(120.0, 24.0));
            ui.label(RichText::new(label).size(12.0).color(dim()));
        });
        add(ui);
    });
}

pub fn label(ui: &mut egui::Ui, s: &str) {
    ui.label(RichText::new(s).size(12.0).color(dim()));
}

pub fn heading(ui: &mut egui::Ui, s: &str) {
    ui.label(bold(s).size(16.0));
}

pub fn title(ui: &mut egui::Ui, s: &str) {
    ui.label(bold(s).size(20.0));
}

pub fn primary(ui: &mut egui::Ui, s: &str) -> egui::Response {
    ui.add(egui::Button::new(bold(s).color(on_accent())).fill(accent()).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 36.0)))
}

/// Primary action spanning the available width.
pub fn primary_wide(ui: &mut egui::Ui, s: &str) -> egui::Response {
    ui.add(
        egui::Button::new(bold(s).color(on_accent()))
            .fill(accent())
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(ui.available_width(), 40.0)),
    )
}

pub fn danger_button(ui: &mut egui::Ui, s: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(s).color(danger())).min_size(Vec2::new(0.0, 32.0)))
}

/// Text-style action (no border), accent colored.
pub fn link(ui: &mut egui::Ui, s: &str) -> egui::Response {
    ui.add(egui::Label::new(RichText::new(s).color(accent())).sense(Sense::click()))
}

pub fn error(ui: &mut egui::Ui, s: &str) {
    if !s.is_empty() {
        ui.label(RichText::new(s).color(danger()));
    }
}

// ---------------------------------------------------------------- drawn pieces

/// Top-bar tab: text with a 2px accent underline when selected.
pub fn tab(ui: &mut egui::Ui, selected: bool, s: &str) -> egui::Response {
    let color = if selected { text() } else { dim() };
    let font = if selected { FontId::new(14.0, semibold()) } else { FontId::proportional(14.0) };
    let galley = ui.painter().layout_no_wrap(s.to_owned(), font, color);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(galley.size().x, 52.0), Sense::click());
    ui.painter().galley(Pos2::new(rect.left(), rect.center().y - galley.size().y / 2.0), galley, color);
    if selected {
        let bar = Rect::from_min_max(Pos2::new(rect.left(), rect.bottom() - 2.0), rect.max);
        ui.painter().rect_filled(bar, 0, accent());
    }
    resp
}

/// Initials backgrounds / foregrounds for profiles without a picture: (dark bg, dark fg, light bg, light fg).
pub const AVATAR_COLORS: [(u32, u32, u32, u32); 6] = [
    (0x3A3326, 0xE8CB8A, 0xEFE3C8, 0x6B4E10),
    (0x26303A, 0x9EC3E8, 0xD8E4F0, 0x1F4A73),
    (0x2A3A2E, 0x9ED8AE, 0xD6EBDC, 0x1F5B33),
    (0x3A2A30, 0xE8A6BE, 0xF0D8E0, 0x7A2846),
    (0x2F2B3A, 0xC2B3F0, 0xE0DAF2, 0x463A80),
    (0x26262B, 0xEDEBE6, 0xE0DCD2, 0x1D1B17),
];

pub fn avatar_colors(i: u8) -> (Color32, Color32) {
    let (db, df, lb, lf) = AVATAR_COLORS[i as usize % AVATAR_COLORS.len()];
    (pick(db, lb), pick(df, lf))
}

fn initials(name: &str) -> String {
    let words: Vec<&str> = name.split_whitespace().collect();
    let mut s: String = words.iter().take(2).filter_map(|w| w.chars().next()).collect();
    if words.len() == 1 {
        s = name.chars().take(2).collect();
    }
    s.to_uppercase()
}

thread_local! {
    static AVATARS: RefCell<HashMap<PathBuf, Option<egui::TextureHandle>>> = RefCell::new(HashMap::new());
}

/// Forget a cached picture (after it changed or was removed).
pub fn forget_avatar(path: &Path) {
    AVATARS.with(|m| m.borrow_mut().remove(path));
}

fn avatar_texture(ctx: &egui::Context, path: &Path) -> Option<egui::TextureHandle> {
    AVATARS.with(|m| {
        m.borrow_mut()
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let img = image::open(path).ok()?.to_rgba8();
                let size = [img.width() as usize, img.height() as usize];
                let color = egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw());
                Some(ctx.load_texture(path.to_string_lossy(), color, egui::TextureOptions::LINEAR))
            })
            .clone()
    })
}

/// Round profile picture, or initials on the chosen color.
pub fn avatar(ui: &mut egui::Ui, name: &str, color: u8, picture: Option<&Path>, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    if let Some(tex) = picture.and_then(|p| avatar_texture(ui.ctx(), p)) {
        egui::Image::new(&tex).corner_radius(size / 2.0).paint_at(ui, rect);
        return;
    }
    let (bg, fg) = avatar_colors(color);
    ui.painter().circle_filled(rect.center(), size / 2.0, bg);
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, initials(name), FontId::new(size * 0.38, semibold()), fg);
}

/// Neutral square tile with the first letter: stands in for a site favicon.
pub fn tile(ui: &mut egui::Ui, name: &str, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    ui.painter().rect_filled(rect, size * 0.22, tile_fill());
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_else(|| "?".into()),
        FontId::new(size * 0.46, semibold()),
        text(),
    );
}

pub fn check(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
    let p = |x: f32, y: f32| rect.min + Vec2::new(x, y);
    ui.painter().add(Shape::line(vec![p(2.5, 7.5), p(5.5, 10.5), p(11.5, 3.5)], Stroke::new(1.8, color)));
}

pub fn cross(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
    let p = |x: f32, y: f32| rect.min + Vec2::new(x, y);
    let s = Stroke::new(1.8, color);
    ui.painter().line_segment([p(3.0, 3.0), p(11.0, 11.0)], s);
    ui.painter().line_segment([p(11.0, 3.0), p(3.0, 11.0)], s);
}

pub fn error_icon(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
    let c = rect.center();
    let s = Stroke::new(1.8, danger());
    ui.painter().circle_stroke(c, 8.5, s);
    ui.painter().line_segment([c + Vec2::new(0.0, -4.5), c + Vec2::new(0.0, 1.5)], s);
    ui.painter().circle_filled(c + Vec2::new(0.0, 4.5), 1.1, danger());
}

pub fn padlock(ui: &mut egui::Ui, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let u = size / 24.0;
    let p = |x: f32, y: f32| rect.min + Vec2::new(x * u, y * u);
    let s = Stroke::new(2.0 * u, color);
    ui.painter().rect_stroke(Rect::from_min_max(p(5.0, 10.0), p(19.0, 20.0)), 2.0 * u, s, egui::StrokeKind::Middle);
    let arc: Vec<Pos2> = (0..=10)
        .map(|i| {
            let a = std::f32::consts::PI * (i as f32 / 10.0);
            p(12.0 - 4.0 * a.cos(), 7.0 - 4.0 * a.sin())
        })
        .collect();
    ui.painter().add(Shape::line(arc, s));
    ui.painter().line_segment([p(8.0, 7.0), p(8.0, 10.0)], s);
    ui.painter().line_segment([p(16.0, 7.0), p(16.0, 10.0)], s);
}

/// Thin countdown line (TOTP validity).
pub fn countdown(ui: &mut egui::Ui, frac: f32, width: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 2.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, line());
    let mut f = rect;
    f.set_width(width * frac.clamp(0.0, 1.0));
    ui.painter().rect_filled(f, 0, accent());
}

/// Draw a QR code (black on white, with quiet zone).
pub fn qr(ui: &mut egui::Ui, width: usize, dark: &[bool], px: f32) {
    let quiet = 3.0;
    let side = (width as f32 + 2.0 * quiet) * px;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(side), Sense::hover());
    ui.painter().rect_filled(rect, 4, Color32::WHITE);
    for y in 0..width {
        for x in 0..width {
            if dark[y * width + x] {
                let min = rect.min + Vec2::new((x as f32 + quiet) * px, (y as f32 + quiet) * px);
                ui.painter().rect_filled(Rect::from_min_size(min, Vec2::splat(px)), 0, Color32::BLACK);
            }
        }
    }
}
