//! Small shared UI helpers: colours, status chips, time formatting.

use crate::client::{CheckStatus, EventKind, RcptStatus};
use chrono::{DateTime, Local, Utc};
use egui::{Color32, RichText, Ui};

pub const GREEN: Color32 = Color32::from_rgb(0x2e, 0xa0, 0x43);
pub const AMBER: Color32 = Color32::from_rgb(0xd2, 0x99, 0x22);
pub const RED: Color32 = Color32::from_rgb(0xda, 0x36, 0x33);
pub const BLUE: Color32 = Color32::from_rgb(0x38, 0x8b, 0xfd);
pub const GREY: Color32 = Color32::from_rgb(0x8b, 0x94, 0x9e);
pub const PURPLE: Color32 = Color32::from_rgb(0xa3, 0x71, 0xf7);

pub fn kind_color(k: EventKind) -> Color32 {
    match k {
        EventKind::Sent => GREEN,
        EventKind::Deferred => AMBER,
        EventKind::Bounced | EventKind::Expired => RED,
        EventKind::Queued => BLUE,
        EventKind::Ndr => PURPLE,
        EventKind::Deleted | EventKind::Other => GREY,
    }
}

pub fn rcpt_color(s: RcptStatus) -> (Color32, &'static str) {
    match s {
        RcptStatus::Pending => (AMBER, "pending"),
        RcptStatus::Delivered => (GREEN, "delivered"),
        RcptStatus::Failed => (RED, "failed"),
    }
}

pub fn check_color(s: CheckStatus) -> (Color32, &'static str) {
    match s {
        CheckStatus::Pass => (GREEN, "PASS"),
        CheckStatus::Warn => (AMBER, "WARN"),
        CheckStatus::Fail => (RED, "FAIL"),
        CheckStatus::Info => (BLUE, "INFO"),
    }
}

/// Coloured, bold, upper-case label.
pub fn chip(ui: &mut Ui, color: Color32, text: &str) {
    ui.label(RichText::new(text.to_uppercase()).color(color).strong().monospace());
}

pub fn local_time(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string()
}

/// "in 4m", "12s ago", ...
pub fn relative(t: DateTime<Utc>) -> String {
    let secs = t.signed_duration_since(Utc::now()).num_seconds();
    let d = duration(secs.unsigned_abs());
    if secs.abs() < 2 {
        "now".into()
    } else if secs > 0 {
        format!("in {d}")
    } else {
        format!("{d} ago")
    }
}

pub fn duration(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h {}m", secs / 3600, secs % 3600 / 60),
        _ => format!("{}d {}h", secs / 86_400, secs % 86_400 / 3600),
    }
}

pub fn bytes(n: u64) -> String {
    match n {
        0..=1023 => format!("{n} B"),
        1024..=1_048_575 => format!("{:.1} KB", n as f64 / 1024.0),
        _ => format!("{:.1} MB", n as f64 / 1_048_576.0),
    }
}

/// First `max` characters with an ellipsis.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// Error banner with the API error text.
pub fn error_label(ui: &mut Ui, msg: &str) {
    ui.label(RichText::new(format!("⚠ {msg}")).color(RED));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration(5), "5s");
        assert_eq!(duration(125), "2m");
        assert_eq!(duration(3 * 3600 + 120), "3h 2m");
        assert_eq!(duration(2 * 86_400 + 3600), "2d 1h");
    }

    #[test]
    fn clipping() {
        assert_eq!(clip("hello", 10), "hello");
        assert_eq!(clip("hello world", 5), "hello…");
    }
}
