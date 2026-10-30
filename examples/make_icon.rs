//! Dev helper: renders the app icon (dark rounded square, brass keyhole) to assets/icon.ico and
//! assets/icon.png. Usage: cargo run --example make_icon

use image::codecs::ico::{IcoEncoder, IcoFrame};
use image::{ExtendedColorType, Rgba, RgbaImage};

const BG: [u8; 3] = [0x19, 0x19, 0x1D];
const RIM: [u8; 3] = [0x2B, 0x2B, 0x31];
const BRASS: [u8; 3] = [0xD6, 0xA2, 0x4A];

/// Signed distance to a rounded rectangle centered on the origin.
fn rounded_rect(x: f32, y: f32, hw: f32, hh: f32, r: f32) -> f32 {
    let qx = x.abs() - (hw - r);
    let qy = y.abs() - (hh - r);
    (qx.max(0.0).hypot(qy.max(0.0))) + qx.max(qy).min(0.0) - r
}

/// Keyhole: a circle on top of a tapered slot. Negative inside.
fn keyhole(x: f32, y: f32) -> f32 {
    let circle = (x).hypot(y + 0.10) - 0.16;
    let t = ((y - 0.02) / 0.30).clamp(0.0, 1.0);
    let half = 0.055 + 0.045 * t;
    let slot = if (0.0..=0.32).contains(&(y - 0.02)) { x.abs() - half } else { (y - 0.02 - 0.16).abs() - 0.16 };
    circle.min(slot.max(-(y - 0.02)).max(y - 0.34))
}

fn render(size: u32) -> RgbaImage {
    let ss = 4; // supersampling
    let mut img = RgbaImage::new(size, size);
    for py in 0..size {
        for px in 0..size {
            let mut acc = [0f32; 4];
            for sy in 0..ss {
                for sx in 0..ss {
                    let x = ((px * ss + sx) as f32 + 0.5) / (size * ss) as f32 * 2.0 - 1.0;
                    let y = ((py * ss + sy) as f32 + 0.5) / (size * ss) as f32 * 2.0 - 1.0;
                    let outer = rounded_rect(x, y, 0.94, 0.94, 0.30);
                    if outer > 0.0 {
                        continue;
                    }
                    let c = if keyhole(x / 1.7, (y + 0.04) / 1.7) < 0.0 {
                        BRASS
                    } else if outer > -0.045 {
                        RIM
                    } else {
                        BG
                    };
                    acc[0] += c[0] as f32;
                    acc[1] += c[1] as f32;
                    acc[2] += c[2] as f32;
                    acc[3] += 255.0;
                }
            }
            let n = (ss * ss) as f32;
            let a = acc[3] / n;
            let rgb = |v: f32| if a > 0.0 { (v / (acc[3] / 255.0)).round() as u8 } else { 0 };
            img.put_pixel(px, py, Rgba([rgb(acc[0]), rgb(acc[1]), rgb(acc[2]), a.round() as u8]));
        }
    }
    img
}

fn main() {
    std::fs::create_dir_all("assets").unwrap();
    let frames: Vec<IcoFrame> = [16u32, 24, 32, 48, 64, 128, 256]
        .iter()
        .map(|&s| IcoFrame::as_png(render(s).as_raw(), s, s, ExtendedColorType::Rgba8).unwrap())
        .collect();
    let f = std::fs::File::create("assets/icon.ico").unwrap();
    IcoEncoder::new(f).encode_images(&frames).unwrap();
    render(256).save("assets/icon.png").unwrap();
    println!("assets/icon.ico, assets/icon.png");
}
