//! Crash reports: the service's (over the API) and this computer's Manager and
//! tray ones (`%LOCALAPPDATA%\Promailer\crashes`), with one-click reporting to
//! GitHub through a pre-filled issue page the administrator reviews and submits.

use crate::client::{ApiResult, Client, CrashList};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, BLUE, GREEN, GREY};
use egui::{RichText, Ui};
use promailer_crash::{github, CrashReport};
use std::time::{Duration, Instant};

const REFRESH_EVERY: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct CrashReports {
    /// Pending reports of the desktop apps on this computer.
    local: Vec<CrashReport>,
    server: CrashList,
    load: Option<Task<ApiResult<CrashList>>>,
    remove: Option<Task<ApiResult<serde_json::Value>>>,
    last: Option<Instant>,
    pub open: bool,
    error: Option<String>,
}

enum Dismiss {
    Local(String),
    Server(String),
}

impl CrashReports {
    /// Refresh periodically; `client` is None while not connected to a server.
    pub fn tick(&mut self, ctx: &egui::Context, client: Option<&Client>) {
        if let Some(res) = poll(&mut self.load) {
            // Servers older than the crash API answer 404: treat as "none".
            self.server = res.unwrap_or_default();
        }
        if let Some(res) = poll(&mut self.remove) {
            self.error = res.err().map(|e| e.message);
            self.last = None;
        }
        if self.load.is_none() && self.remove.is_none() && self.last.is_none_or(|t| t.elapsed() >= REFRESH_EVERY) {
            self.last = Some(Instant::now());
            self.local = promailer_crash::user_dir().map(|d| promailer_crash::pending(&d)).unwrap_or_default();
            if let Some(c) = client {
                let c = c.clone();
                self.load = Some(Task::spawn(ctx, move || c.crashes()));
            }
        }
    }

    fn repo(&self) -> &str {
        if self.server.repo.is_empty() {
            github::DEFAULT_REPO
        } else {
            &self.server.repo
        }
    }

    /// Reports that still need someone to look at them.
    pub fn pending(&self) -> usize {
        self.local.len() + self.server.reports.iter().filter(|r| !r.report.is_reported()).count()
    }

    pub fn banner(&mut self, ui: &mut Ui) {
        let n = self.pending();
        ui.horizontal(|ui| {
            ui.label(RichText::new("⚠").color(AMBER).strong());
            ui.label(format!("Promailer recorded {n} internal error{}.", if n == 1 { "" } else { "s" }));
            if ui.link("Review and report…").clicked() {
                self.open = true;
            }
        });
    }

    fn row(ui: &mut Ui, r: &CrashReport, new_issue_url: &str, dismiss: &mut Option<String>) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                widgets::chip(ui, if r.app == "promailer" { BLUE } else { GREY }, &r.app);
                ui.label(RichText::new(format!("{} · {}", r.version, widgets::local_time(r.time))).small());
            });
            ui.label(RichText::new(r.summary()).strong());
            ui.label(RichText::new(&r.location).monospace().small().color(GREY));
            ui.horizontal(|ui| {
                match &r.issue_url {
                    Some(url) => {
                        ui.label(RichText::new("Filed:").color(GREEN));
                        ui.hyperlink(url);
                    }
                    None => {
                        if ui.button("Report on GitHub…").clicked() {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(new_issue_url));
                        }
                    }
                }
                if ui.button("Dismiss").clicked() {
                    *dismiss = Some(r.id.clone());
                }
            });
        });
    }

    pub fn dialog(&mut self, ctx: &egui::Context, client: Option<&Client>) {
        if !self.open {
            return;
        }
        let mut action = None;
        let mut close = false;
        egui::Modal::new(egui::Id::new("crashes")).show(ctx, |ui| {
            ui.set_width(640.0);
            ui.heading("Crash Reports");
            ui.label(
                RichText::new(
                    "Each report holds the version, error message and code location; email addresses, IP \
                     addresses, host and account names were removed. \"Report on GitHub\" opens a pre-filled \
                     issue for you to review and submit.",
                )
                .small()
                .color(GREY),
            );
            if self.server.auto_report {
                ui.label(RichText::new("This server files its reports on GitHub automatically.").small().color(GREEN));
            }
            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                if self.server.reports.is_empty() && self.local.is_empty() {
                    ui.label("No crash reports.");
                }
                for c in &self.server.reports {
                    let mut d = None;
                    Self::row(ui, &c.report, &c.new_issue_url, &mut d);
                    action = action.take().or(d.map(Dismiss::Server));
                }
                let repo = self.repo();
                for r in &self.local {
                    let mut d = None;
                    Self::row(ui, r, &github::new_issue_url(repo, r), &mut d);
                    action = action.take().or(d.map(Dismiss::Local));
                }
            });
            if let Some(e) = &self.error {
                widgets::error_label(ui, e);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("  Close  ").clicked() {
                    close = true;
                }
                if self.remove.is_some() || self.load.is_some() {
                    ui.spinner();
                }
            });
        });
        match action {
            Some(Dismiss::Local(id)) => {
                if let Some(dir) = promailer_crash::user_dir() {
                    if let Err(e) = promailer_crash::dismiss(&dir, &id) {
                        self.error = Some(format!("{}: {e}", dir.display()));
                    }
                }
                self.local.retain(|r| r.id != id);
            }
            Some(Dismiss::Server(id)) => {
                if let Some(c) = client {
                    let c = c.clone();
                    self.server.reports.retain(|r| r.report.id != id);
                    self.remove = Some(Task::spawn(ctx, move || c.crash_delete(&id)));
                }
            }
            None => {}
        }
        if close {
            self.open = false;
        }
    }
}
