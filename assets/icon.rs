//! The Promailer icon, drawn in code: a white envelope on a blue rounded
//! square, optionally with a coloured status badge (the tray icon).
//!
//! Shared by source path (`#[path = ".../assets/icon.rs"] mod icon;`):
//! build scripts turn it into the `.ico` embedded in each executable, the
//! Manager uses it as its window icon and the tray draws its status icons.
#![allow(dead_code)]

const BLUE_TOP: [u8; 3] = [0x2f, 0x81, 0xf7];
const BLUE_BOTTOM: [u8; 3] = [0x1a, 0x56, 0xc4];
const WHITE: [u8; 3] = [0xff, 0xff, 0xff];

pub const GREEN: [u8; 3] = [0x1f, 0xa8, 0x4a];
pub const AMBER: [u8; 3] = [0xe8, 0xa3, 0x17];
pub const RED: [u8; 3] = [0xd9, 0x30, 0x25];
pub const GREY: [u8; 3] = [0x8a, 0x8f, 0x98];

/// Supersampling grid per pixel (anti-aliasing).
const SS: u32 = 5;

fn in_rounded_rect(x: f32, y: f32, x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> bool {
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    let cx = x.clamp(x0 + r, x1 - r);
    let cy = y.clamp(y0 + r, y1 - r);
    (x - cx).powi(2) + (y - cy).powi(2) <= r * r
}

/// Distance from (x, y) to the segment (ax, ay)-(bx, by).
fn seg_dist(x: f32, y: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let (dx, dy) = (bx - ax, by - ay);
    let t = (((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
    ((x - ax - t * dx).powi(2) + (y - ay - t * dy).powi(2)).sqrt()
}

fn lerp(a: [u8; 3], b: [u8; 3], t: f32) -> [u8; 3] {
    let m = |i: usize| (a[i] as f32 + (b[i] as f32 - a[i] as f32) * t).round() as u8;
    [m(0), m(1), m(2)]
}

/// Colour at a point in unit coordinates (0..1), or None when transparent.
fn sample(u: f32, v: f32, badge: Option<[u8; 3]>) -> Option<[u8; 3]> {
    if let Some(color) = badge {
        let d = ((u - 0.76).powi(2) + (v - 0.76).powi(2)).sqrt();
        if d <= 0.17 {
            return Some(color);
        }
        if d <= 0.235 {
            return Some(WHITE);
        }
    }
    if !in_rounded_rect(u, v, 0.02, 0.02, 0.98, 0.98, 0.2) {
        return None;
    }
    let bg = lerp(BLUE_TOP, BLUE_BOTTOM, v);
    let (x0, y0, x1, y1) = (0.17, 0.27, 0.83, 0.73);
    if in_rounded_rect(u, v, x0, y0, x1, y1, 0.045) {
        // The envelope flap: a "V" from the top corners to the middle.
        let flap = seg_dist(u, v, x0 + 0.02, y0 + 0.02, 0.5, 0.52).min(seg_dist(u, v, 0.5, 0.52, x1 - 0.02, y0 + 0.02));
        return Some(if flap <= 0.035 { bg } else { WHITE });
    }
    Some(bg)
}

/// Straight (non-premultiplied) RGBA pixels, row-major, top row first.
pub fn rgba(size: u32, badge: Option<[u8; 3]>) -> Vec<u8> {
    let mut out = Vec::with_capacity((size * size * 4) as usize);
    let n = (SS * SS) as f32;
    for py in 0..size {
        for px in 0..size {
            let (mut r, mut g, mut b, mut a) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let u = (px as f32 + (sx as f32 + 0.5) / SS as f32) / size as f32;
                    let v = (py as f32 + (sy as f32 + 0.5) / SS as f32) / size as f32;
                    if let Some(c) = sample(u, v, badge) {
                        r += c[0] as f32;
                        g += c[1] as f32;
                        b += c[2] as f32;
                        a += 1.0;
                    }
                }
            }
            if a == 0.0 {
                out.extend([0, 0, 0, 0]);
            } else {
                out.extend([
                    (r / a).round() as u8,
                    (g / a).round() as u8,
                    (b / a).round() as u8,
                    (a / n * 255.0).round() as u8,
                ]);
            }
        }
    }
    out
}

/// A Windows `.ico` file holding the plain icon at several sizes (32-bit BMP entries).
pub fn ico(sizes: &[u32]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = sizes.iter().map(|&s| bmp_entry(s, &rgba(s, None))).collect();
    let mut out = Vec::new();
    out.extend(0u16.to_le_bytes()); // reserved
    out.extend(1u16.to_le_bytes()); // type: icon
    out.extend((sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (&s, img) in sizes.iter().zip(&images) {
        let dim = if s >= 256 { 0 } else { s as u8 };
        out.extend([dim, dim, 0, 0]); // width, height, palette size, reserved
        out.extend(1u16.to_le_bytes()); // planes
        out.extend(32u16.to_le_bytes()); // bits per pixel
        out.extend((img.len() as u32).to_le_bytes());
        out.extend(offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in images {
        out.extend(img);
    }
    out
}

/// BITMAPINFOHEADER + BGRA rows (bottom-up) + an all-zero AND mask (alpha is used instead).
fn bmp_entry(size: u32, rgba: &[u8]) -> Vec<u8> {
    let mask_row = size.div_ceil(32) * 4;
    let mut out = Vec::new();
    out.extend(40u32.to_le_bytes());
    out.extend((size as i32).to_le_bytes());
    out.extend((size as i32 * 2).to_le_bytes()); // colour + mask
    out.extend(1u16.to_le_bytes());
    out.extend(32u16.to_le_bytes());
    out.extend(0u32.to_le_bytes()); // BI_RGB
    out.extend((size * size * 4 + mask_row * size).to_le_bytes());
    out.extend([0u8; 16]); // resolution, palette counts
    for y in (0..size).rev() {
        for x in 0..size {
            let i = ((y * size + x) * 4) as usize;
            out.extend([rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
        }
    }
    out.extend(std::iter::repeat_n(0u8, (mask_row * size) as usize));
    out
}
