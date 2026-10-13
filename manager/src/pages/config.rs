//! Configuration editor with live validation.
//!
//! Two validation layers:
//! * local TOML syntax check on every keystroke (instant, offline);
//! * full server-side validation, debounced, exactly as the service would load
//!   the file: schema, semantic rules, DKIM keys, TLS certificate, and which
//!   changes would need a restart.
//!
//! Saving goes through the server, which refuses invalid files, refuses to
//! overwrite a file that changed on disk since it was loaded, keeps a backup
//! and hot-reloads the running service.

use crate::client::{ApiError, ApiResult, Client, ConfigFile, SaveResult, Validation};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, BLUE, GREEN, GREY, RED};
use egui::text::{CCursor, CCursorRange, LayoutJob};
use egui::{Color32, FontId, RichText, TextFormat, Ui};
use std::time::{Duration, Instant};

const VALIDATE_AFTER: Duration = Duration::from_millis(800);

#[derive(Default)]
pub struct ConfigEditor {
    file: Option<ConfigFile>,
    text: String,
    load: Option<Task<ApiResult<ConfigFile>>>,
    validate: Option<Task<ApiResult<Validation>>>,
    save: Option<Task<ApiResult<SaveResult>>>,
    /// (line, message) of a local TOML syntax error.
    syntax: Option<(usize, String)>,
    validation: Option<Validation>,
    /// Text the current `validation` refers to.
    validated_text: String,
    last_edit: Option<Instant>,
    save_result: Option<Result<SaveResult, ApiError>>,
    confirm_save: bool,
    confirm_discard: bool,
    goto_line: Option<usize>,
    error: Option<String>,
}

impl ConfigEditor {
    fn dirty(&self) -> bool {
        self.file.as_ref().is_some_and(|f| f.text != self.text)
    }

    fn load(&mut self, ctx: &egui::Context, client: &Client) {
        let c = client.clone();
        self.load = Some(Task::spawn(ctx, move || c.config()));
    }

    fn check_syntax(&mut self) {
        self.syntax = match toml::from_str::<toml::Table>(&self.text) {
            Ok(_) => None,
            Err(e) => {
                let line = e.span().map(|s| line_of(&self.text, s.start));
                Some((line.unwrap_or(0), e.message().trim().to_string()))
            }
        };
    }

    pub fn ui(&mut self, ui: &mut Ui, client: &Client) {
        let ctx = ui.ctx().clone();
        self.poll_tasks(&ctx, client);
        if self.file.is_none() && self.load.is_none() && self.error.is_none() {
            self.load(&ctx, client);
        }
        // Debounced server validation after the user stops typing.
        if let Some(t) = self.last_edit {
            if t.elapsed() >= VALIDATE_AFTER && self.validate.is_none() && self.syntax.is_none() {
                self.last_edit = None;
                self.start_validate(&ctx, client);
            } else if self.syntax.is_none() {
                ctx.request_repaint_after(VALIDATE_AFTER);
            }
        }

        self.toolbar(ui, &ctx, client);
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
            if ui.button("Try again").clicked() {
                self.error = None;
            }
            return;
        }
        if self.file.is_none() {
            ui.spinner();
            return;
        }
        self.status_panel(ui, &ctx, client);
        ui.separator();
        self.editor(ui);
        self.dialogs(&ctx, client);
    }

    fn start_validate(&mut self, ctx: &egui::Context, client: &Client) {
        let (c, text) = (client.clone(), self.text.clone());
        self.validated_text = text.clone();
        self.validate = Some(Task::spawn(ctx, move || c.validate_config(&text)));
    }

    fn poll_tasks(&mut self, ctx: &egui::Context, client: &Client) {
        if let Some(res) = poll(&mut self.load) {
            match res {
                Ok(f) => {
                    self.text = f.text.clone();
                    self.file = Some(f);
                    self.check_syntax();
                    self.validation = None;
                    self.error = None;
                    self.start_validate(ctx, client);
                }
                Err(e) if e.status == Some(403) => {
                    self.error = Some(format!("{e} — the config editor needs an API key with the 'admin' permission."))
                }
                Err(e) => self.error = Some(e.message),
            }
        }
        if let Some(res) = poll(&mut self.validate) {
            match res {
                Ok(v) => self.validation = Some(v),
                Err(e) => self.error = Some(e.message),
            }
        }
        if let Some(res) = poll(&mut self.save) {
            match &res {
                Ok(r) => {
                    // The saved text is now the baseline for future saves.
                    if let Some(f) = &mut self.file {
                        f.text = self.text.clone();
                        f.sha256 = r.sha256.clone();
                    }
                }
                Err(e) => {
                    // 422 carries the full validation result.
                    if let Some(v) = e.body.clone().and_then(|b| serde_json::from_value::<Validation>(b).ok()) {
                        self.validated_text = self.text.clone();
                        self.validation = Some(v);
                    }
                }
            }
            self.save_result = Some(res);
        }
    }

    fn toolbar(&mut self, ui: &mut Ui, ctx: &egui::Context, client: &Client) {
        ui.horizontal(|ui| {
            if let Some(f) = &self.file {
                ui.label(RichText::new(&f.path).monospace().color(GREY));
            }
            if self.dirty() {
                ui.label(RichText::new("● unsaved changes").color(AMBER));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can_save = self.dirty() && self.syntax.is_none() && self.save.is_none();
                if ui
                    .add_enabled(can_save, egui::Button::new(RichText::new("Save & apply").strong()))
                    .on_disabled_hover_text("Nothing to save, or the file has a syntax error")
                    .clicked()
                {
                    self.confirm_save = true;
                }
                if ui
                    .add_enabled(self.validate.is_none() && self.syntax.is_none(), egui::Button::new("Validate"))
                    .clicked()
                {
                    self.start_validate(ctx, client);
                }
                if ui.add_enabled(self.load.is_none(), egui::Button::new("Reload from server")).clicked() {
                    if self.dirty() {
                        self.confirm_discard = true;
                    } else {
                        self.load(ctx, client);
                    }
                }
                if self.load.is_some() || self.validate.is_some() || self.save.is_some() {
                    ui.spinner();
                }
            });
        });
    }

    fn status_panel(&mut self, ui: &mut Ui, ctx: &egui::Context, client: &Client) {
        let mut goto = None;
        let mut reload = false;
        if let Some(res) = &self.save_result {
            match res {
                Ok(r) => {
                    let msg = if r.reloaded {
                        "Saved and applied to the running service.".to_string()
                    } else {
                        format!(
                            "Saved, but the reload failed: {}. The service keeps its previous settings.",
                            r.reload_error.as_deref().unwrap_or("unknown error")
                        )
                    };
                    ui.label(RichText::new(msg).color(if r.reloaded { GREEN } else { RED }).strong());
                    for w in &r.warnings {
                        ui.label(RichText::new(format!("⚠ {w}")).color(AMBER));
                    }
                    if !r.backup.is_empty() {
                        ui.label(
                            RichText::new(format!("Previous version backed up to {}", r.backup)).small().color(GREY),
                        );
                    }
                }
                Err(e) if e.status == Some(409) => {
                    ui.horizontal(|ui| {
                        widgets::error_label(ui, &e.message);
                        if ui.button("Copy my edits").clicked() {
                            ui.ctx().copy_text(self.text.clone());
                        }
                        if ui.button("Load server version").clicked() {
                            reload = true;
                        }
                    });
                }
                Err(e) => widgets::error_label(ui, &format!("Not saved: {e}")),
            }
        }

        if let Some((line, msg)) = &self.syntax {
            ui.horizontal(|ui| {
                ui.label(RichText::new("✖ Syntax error").color(RED).strong());
                if ui.link(format!("line {line}")).clicked() {
                    goto = Some(*line);
                }
                ui.label(RichText::new(msg).color(RED));
            });
        } else if let Some(v) = &self.validation {
            let stale = self.validated_text != self.text;
            if v.valid {
                ui.label(
                    RichText::new(if stale {
                        "✔ Valid (checking your latest edits…)"
                    } else {
                        "✔ Configuration is valid"
                    })
                    .color(GREEN),
                );
            }
            for e in &v.errors {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("✖").color(RED).strong());
                    if let Some(l) = e.line {
                        if ui
                            .link(format!("line {l}{}", e.column.map(|c| format!(":{c}")).unwrap_or_default()))
                            .clicked()
                        {
                            goto = Some(l);
                        }
                    }
                    ui.label(RichText::new(&e.message).color(RED));
                });
            }
            for w in &v.warnings {
                ui.label(RichText::new(format!("⚠ {w}")).color(AMBER));
            }
        }
        if goto.is_some() {
            self.goto_line = goto;
        }
        if reload {
            self.save_result = None;
            self.load(ctx, client);
        }
    }

    fn error_lines(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.syntax.iter().map(|(l, _)| *l).collect();
        if let Some(val) = &self.validation {
            if self.validated_text == self.text {
                v.extend(val.errors.iter().filter_map(|e| e.line));
            }
        }
        v
    }

    fn editor(&mut self, ui: &mut Ui) {
        let id = egui::Id::new("config_text");
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
        let error_lines = self.error_lines();
        let dark = ui.visuals().dark_mode;
        let font = egui::TextStyle::Monospace.resolve(ui.style());

        let mut scroll = egui::ScrollArea::both().id_salt("config_scroll").auto_shrink([false, false]);
        if let Some(line) = self.goto_line.take() {
            scroll = scroll.vertical_scroll_offset(((line.saturating_sub(5)) as f32 * row_h).max(0.0));
            // Put the caret at the start of the line.
            let idx: usize = self.text.split('\n').take(line.saturating_sub(1)).map(|l| l.chars().count() + 1).sum();
            if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), id) {
                state.cursor.set_char_range(Some(CCursorRange::one(CCursor::new(idx))));
                state.store(ui.ctx(), id);
            }
            ui.memory_mut(|m| m.request_focus(id));
        }

        let mut layouter = |ui: &Ui, text: &dyn egui::TextBuffer, _wrap: f32| {
            let job = highlight(text.as_str(), &error_lines, dark, font.clone());
            ui.fonts_mut(|f| f.layout_job(job))
        };
        scroll.show(ui, |ui| {
            ui.horizontal_top(|ui| {
                let lines = self.text.split('\n').count().max(1);
                let gutter: String = (1..=lines).map(|n| format!("{n:>4}\n")).collect();
                ui.add_space(2.0);
                ui.vertical(|ui| {
                    ui.add_space(2.0); // matches the TextEdit's top margin
                    ui.label(RichText::new(gutter.trim_end()).monospace().color(GREY));
                });
                let resp = ui.add(
                    egui::TextEdit::multiline(&mut self.text)
                        .id(id)
                        .code_editor()
                        .lock_focus(true)
                        .desired_width(f32::INFINITY)
                        .desired_rows(lines.max(30))
                        .margin(egui::Margin::symmetric(4, 2))
                        .layouter(&mut layouter),
                );
                if resp.changed() {
                    self.check_syntax();
                    self.last_edit = Some(Instant::now());
                    self.save_result = None;
                }
            });
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context, client: &Client) {
        if self.confirm_save {
            let mut decision = None;
            let warnings: Vec<String> = self
                .validation
                .as_ref()
                .filter(|_| self.validated_text == self.text)
                .map(|v| v.warnings.clone())
                .unwrap_or_default();
            egui::Modal::new(egui::Id::new("confirm_save")).show(ctx, |ui| {
                ui.set_width(460.0);
                ui.heading("Apply configuration?");
                ui.add_space(6.0);
                ui.label(
                    "The server validates the file again, saves it (keeping a backup of the current version) \
                     and reloads the running service. Access lists, users, limits, delivery rules, DKIM keys \
                     and the TLS certificate take effect immediately.",
                );
                for w in &warnings {
                    ui.label(RichText::new(format!("⚠ {w}")).color(AMBER));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Save & apply").strong().color(BLUE)).clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        decision = Some(false);
                    }
                });
            });
            if let Some(go) = decision {
                self.confirm_save = false;
                if go {
                    let c = client.clone();
                    let text = self.text.clone();
                    let base = self.file.as_ref().map(|f| f.sha256.clone()).unwrap_or_default();
                    self.save_result = None;
                    self.save = Some(Task::spawn(ctx, move || c.save_config(&text, &base)));
                }
            }
        }
        if self.confirm_discard {
            let mut decision = None;
            egui::Modal::new(egui::Id::new("confirm_discard")).show(ctx, |ui| {
                ui.heading("Discard unsaved changes?");
                ui.label("Reloading replaces your edits with the file currently on the server.");
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Discard").color(RED)).clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
            if let Some(go) = decision {
                self.confirm_discard = false;
                if go {
                    self.save_result = None;
                    self.load(ctx, client);
                }
            }
        }
    }
}

/// 1-based line containing byte `offset` (clamped, UTF-8 safe).
fn line_of(text: &str, offset: usize) -> usize {
    text.bytes().take(offset).filter(|&b| b == b'\n').count() + 1
}

// ---------------------------------------------------------------------------
// TOML syntax highlighting
// ---------------------------------------------------------------------------

struct Palette {
    text: Color32,
    comment: Color32,
    header: Color32,
    key: Color32,
    string: Color32,
    literal: Color32,
    error_bg: Color32,
}

fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            text: Color32::from_gray(220),
            comment: Color32::from_rgb(0x6a, 0x73, 0x7d),
            header: Color32::from_rgb(0x79, 0xc0, 0xff),
            key: Color32::from_rgb(0xd2, 0xa8, 0xff),
            string: Color32::from_rgb(0xa5, 0xd6, 0xff),
            literal: Color32::from_rgb(0xff, 0xa6, 0x57),
            error_bg: Color32::from_rgba_unmultiplied(0xda, 0x36, 0x33, 60),
        }
    } else {
        Palette {
            text: Color32::from_gray(30),
            comment: Color32::from_rgb(0x6e, 0x77, 0x81),
            header: Color32::from_rgb(0x05, 0x50, 0xae),
            key: Color32::from_rgb(0x82, 0x50, 0xdf),
            string: Color32::from_rgb(0x0a, 0x30, 0x69),
            literal: Color32::from_rgb(0x95, 0x38, 0x00),
            error_bg: Color32::from_rgba_unmultiplied(0xda, 0x36, 0x33, 50),
        }
    }
}

/// Line-oriented TOML colouring: comments, [tables], keys, strings and literals.
/// Lines listed in `error_lines` (1-based) get a red background.
fn highlight(text: &str, error_lines: &[usize], dark: bool, font: FontId) -> LayoutJob {
    let p = palette(dark);
    let mut job = LayoutJob::default();
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let bg = if error_lines.contains(&(i + 1)) { p.error_bg } else { Color32::TRANSPARENT };
        let mut push = |s: &str, color: Color32| {
            if !s.is_empty() {
                job.append(s, 0.0, TextFormat { font_id: font.clone(), color, background: bg, ..Default::default() });
            }
        };
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        push(indent, p.text);
        if trimmed.starts_with('#') {
            push(trimmed, p.comment);
        } else if trimmed.starts_with('[') {
            let (code, comment) = split_comment(trimmed);
            push(code, p.header);
            push(comment, p.comment);
        } else if let Some(eq) = trimmed.find('=') {
            push(&trimmed[..eq], p.key);
            push("=", p.text);
            value_tokens(&trimmed[eq + 1..], &p, &mut push);
        } else {
            value_tokens(trimmed, &p, &mut push);
        }
    }
    // Ensure an empty document still lays out one row.
    if text.is_empty() {
        job.append("", 0.0, TextFormat { font_id: font, color: p.text, ..Default::default() });
    }
    job
}

/// Split at the first `#` that is not inside a string.
fn split_comment(s: &str) -> (&str, &str) {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return (&s[..i], &s[i..]),
            None => {}
        }
    }
    (s, "")
}

fn value_tokens(s: &str, p: &Palette, push: &mut impl FnMut(&str, Color32)) {
    let (code, comment) = split_comment(s);
    let mut rest = code;
    while !rest.is_empty() {
        let c = rest.chars().next().unwrap_or(' ');
        let len = if c == '"' || c == '\'' {
            // String up to the matching unescaped quote (or end of line).
            let mut end = rest.len();
            let mut escaped = false;
            for (i, ch) in rest.char_indices().skip(1) {
                if escaped {
                    escaped = false;
                } else if ch == '\\' && c == '"' {
                    escaped = true;
                } else if ch == c {
                    end = i + ch.len_utf8();
                    break;
                }
            }
            push(&rest[..end], p.string);
            end
        } else if c.is_ascii_alphanumeric() || c == '-' || c == '+' || c == '.' {
            let end = rest.find(|ch: char| !(ch.is_ascii_alphanumeric() || "-+._:".contains(ch))).unwrap_or(rest.len());
            push(&rest[..end], p.literal);
            end
        } else {
            let end = c.len_utf8();
            push(&rest[..end], p.text);
            end
        };
        rest = &rest[len..];
    }
    push(comment, p.comment);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_split_ignores_hash_in_strings() {
        assert_eq!(split_comment(r#"a = "x#y" # c"#), (r#"a = "x#y" "#, "# c"));
        assert_eq!(split_comment("a = 1"), ("a = 1", ""));
    }

    #[test]
    fn highlighting_preserves_text() {
        let src = "# top\n[server]\nhostname = \"mx.example.com\" # fqdn\nports = [25, 587]\n\nbad = 'x\n";
        let job = highlight(src, &[3], true, FontId::monospace(12.0));
        assert_eq!(job.text, src);
    }
}
