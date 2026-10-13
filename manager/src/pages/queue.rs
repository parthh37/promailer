//! Queue browser: list, filter, inspect, retry and delete queued messages.

use crate::client::{ApiError, ApiResult, Client, Headers, QueueEntry, QueuePage};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, GREEN, GREY, RED};
use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const PAGE_SIZE: usize = 100;
const AUTO_REFRESH: Duration = Duration::from_secs(5);

/// Per-message outcome of a bulk retry/delete.
type BulkResults = Vec<(String, ApiResult<serde_json::Value>)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Retry,
    Delete,
}

struct Detail {
    entry: QueueEntry,
    headers: Option<Result<Headers, String>>,
    headers_task: Option<Task<ApiResult<Headers>>>,
}

pub struct QueueBrowser {
    filter: String,
    applied_filter: String,
    offset: usize,
    page: Option<QueuePage>,
    load: Option<Task<ApiResult<QueuePage>>>,
    last_load: Option<Instant>,
    auto_refresh: bool,
    selected: BTreeSet<String>,
    detail: Option<Detail>,
    /// Open this message's details once it appears in a loaded page.
    pending_open: Option<String>,
    action: Option<Task<BulkResults>>,
    action_label: &'static str,
    retry_all: Option<Task<ApiResult<serde_json::Value>>>,
    confirm_delete: Option<Vec<String>>,
    status: Option<(bool, String)>,
    error: Option<String>,
}

impl Default for QueueBrowser {
    fn default() -> Self {
        Self {
            filter: String::new(),
            applied_filter: String::new(),
            offset: 0,
            page: None,
            load: None,
            last_load: None,
            auto_refresh: true,
            selected: BTreeSet::new(),
            detail: None,
            pending_open: None,
            action: None,
            action_label: "",
            retry_all: None,
            confirm_delete: None,
            status: None,
            error: None,
        }
    }
}

impl QueueBrowser {
    /// Jump here from search: filter to one message and open it.
    pub fn open(&mut self, id: &str) {
        self.filter = id.to_string();
        self.applied_filter = id.to_string();
        self.offset = 0;
        self.pending_open = Some(id.to_string());
        self.last_load = None;
    }

    fn reload(&mut self, ctx: &egui::Context, client: &Client) {
        if self.load.is_some() {
            return;
        }
        self.last_load = Some(Instant::now());
        let (c, off, f) = (client.clone(), self.offset, self.applied_filter.clone());
        self.load = Some(Task::spawn(ctx, move || c.queue(off, PAGE_SIZE, &f)));
    }

    fn run_bulk(&mut self, ctx: &egui::Context, client: &Client, op: Op, ids: Vec<String>) {
        let c = client.clone();
        self.action_label = if op == Op::Retry { "Retry" } else { "Delete" };
        self.action = Some(Task::spawn(ctx, move || {
            ids.into_iter()
                .map(|id| {
                    let r = match op {
                        Op::Retry => c.retry(&id),
                        Op::Delete => c.delete(&id),
                    };
                    (id, r)
                })
                .collect()
        }));
    }

    pub fn ui(&mut self, ui: &mut Ui, client: &Client) {
        let ctx = ui.ctx().clone();
        self.poll_tasks(&ctx, client);
        if self.page.is_none() || (self.auto_refresh && self.last_load.is_none_or(|t| t.elapsed() >= AUTO_REFRESH)) {
            self.reload(&ctx, client);
        }
        if self.auto_refresh {
            ctx.request_repaint_after(AUTO_REFRESH);
        }

        self.toolbar(ui, &ctx, client);
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        if let Some((ok, msg)) = &self.status {
            ui.label(RichText::new(msg).color(if *ok { GREEN } else { RED }));
        }
        ui.separator();

        let mut close_detail = false;
        let mut detail_op: Option<(Op, String)> = None;
        if let Some(d) = &mut self.detail {
            egui::Panel::right("queue_detail").resizable(true).default_size(420.0).min_size(300.0).show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    detail_ui(ui, &ctx, client, d, &mut close_detail, &mut detail_op);
                });
            });
        }
        if close_detail {
            self.detail = None;
        }
        match detail_op {
            Some((Op::Retry, id)) => self.run_bulk(&ctx, client, Op::Retry, vec![id]),
            Some((Op::Delete, id)) => self.confirm_delete = Some(vec![id]),
            None => {}
        }

        self.table(ui, &ctx, client);
        self.confirm_dialog(&ctx, client);
    }

    fn poll_tasks(&mut self, ctx: &egui::Context, client: &Client) {
        if let Some(res) = poll(&mut self.load) {
            match res {
                Ok(p) => {
                    // Forget selections that are no longer in the queue.
                    let ids: BTreeSet<&str> = p.items.iter().map(|e| e.id.as_str()).collect();
                    self.selected.retain(|id| ids.contains(id.as_str()));
                    if let Some(want) = self.pending_open.take() {
                        match p.items.iter().find(|e| e.id == want) {
                            Some(e) => {
                                self.detail = Some(Detail { entry: e.clone(), headers: None, headers_task: None })
                            }
                            None => self.status = Some((false, format!("{want} is no longer in the queue"))),
                        }
                    }
                    // Keep the open detail panel current.
                    if let Some(d) = &mut self.detail {
                        if let Some(e) = p.items.iter().find(|e| e.id == d.entry.id) {
                            d.entry = e.clone();
                        }
                    }
                    self.page = Some(p);
                    self.error = None;
                }
                Err(e) => self.error = Some(e.message),
            }
        }
        if let Some(results) = poll(&mut self.action) {
            let failed: Vec<String> = results
                .iter()
                .filter_map(|(id, r)| r.as_ref().err().map(|e: &ApiError| format!("{id}: {e}")))
                .collect();
            let ok = results.len() - failed.len();
            let verb = if self.action_label == "Retry" { "rescheduled" } else { "deleted" };
            self.status = Some(if failed.is_empty() {
                (true, format!("{ok} message(s) {verb}."))
            } else {
                (false, format!("{ok} message(s) {verb}; {} failed — {}", failed.len(), failed.join("; ")))
            });
            if self.action_label == "Delete" {
                for (id, r) in &results {
                    if r.is_ok() {
                        self.selected.remove(id);
                        if self.detail.as_ref().is_some_and(|d| &d.entry.id == id) {
                            self.detail = None;
                        }
                    }
                }
            }
            self.last_load = None;
            self.reload(ctx, client);
        }
        if let Some(res) = poll(&mut self.retry_all) {
            self.status = Some(match res {
                Ok(v) => (true, format!("{} message(s) rescheduled for immediate delivery.", v["rescheduled"])),
                Err(e) => (false, e.message),
            });
            self.last_load = None;
            self.reload(ctx, client);
        }
    }

    fn toolbar(&mut self, ui: &mut Ui, ctx: &egui::Context, client: &Client) {
        ui.horizontal(|ui| {
            if let Some(p) = &self.page {
                ui.label(RichText::new(format!("{} message(s)", p.total)).color(GREY));
            }
            ui.add_space(12.0);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter: sender, recipient, subject, ID, error…")
                    .desired_width(300.0),
            );
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if enter || ui.button("Apply").clicked() {
                self.applied_filter = self.filter.trim().to_string();
                self.offset = 0;
                self.last_load = None;
                self.reload(ctx, client);
            }
            if !self.applied_filter.is_empty() && ui.button("Clear").clicked() {
                self.filter.clear();
                self.applied_filter.clear();
                self.offset = 0;
                self.last_load = None;
                self.reload(ctx, client);
            }
            ui.separator();
            if ui.add_enabled(self.load.is_none(), egui::Button::new("Refresh")).clicked() {
                self.reload(ctx, client);
            }
            ui.checkbox(&mut self.auto_refresh, "Auto-refresh");
            if self.load.is_some() || self.action.is_some() || self.retry_all.is_some() {
                ui.spinner();
            }
        });
        ui.horizontal(|ui| {
            let busy = self.action.is_some();
            let n = self.selected.len();
            if ui.add_enabled(n > 0 && !busy, egui::Button::new(format!("Retry selected ({n})"))).clicked() {
                let ids = self.selected.iter().cloned().collect();
                self.run_bulk(ctx, client, Op::Retry, ids);
            }
            if ui
                .add_enabled(
                    n > 0 && !busy,
                    egui::Button::new(RichText::new(format!("Delete selected ({n})")).color(RED)),
                )
                .clicked()
            {
                self.confirm_delete = Some(self.selected.iter().cloned().collect());
            }
            if ui
                .add_enabled(self.retry_all.is_none(), egui::Button::new("Retry all now"))
                .on_hover_text("Reschedule every waiting message for immediate delivery")
                .clicked()
            {
                let c = client.clone();
                self.retry_all = Some(Task::spawn(ctx, move || c.retry_all()));
            }
            if let Some(p) = &self.page {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let last = (p.offset + p.items.len()).min(p.total);
                    if ui.add_enabled(last < p.total, egui::Button::new("Next")).clicked() {
                        self.offset += PAGE_SIZE;
                        self.last_load = None;
                    }
                    ui.label(format!("{}–{} of {}", if p.total == 0 { 0 } else { p.offset + 1 }, last, p.total));
                    if ui.add_enabled(self.offset > 0, egui::Button::new("Previous")).clicked() {
                        self.offset = self.offset.saturating_sub(PAGE_SIZE);
                        self.last_load = None;
                    }
                });
            }
        });
    }

    fn table(&mut self, ui: &mut Ui, ctx: &egui::Context, client: &Client) {
        let Some(page) = &self.page else {
            ui.spinner();
            return;
        };
        if page.items.is_empty() {
            ui.add_space(20.0);
            ui.label(
                RichText::new(if self.applied_filter.is_empty() {
                    "The queue is empty. Everything has been delivered."
                } else {
                    "No queued messages match the filter."
                })
                .color(GREY),
            );
            return;
        }
        let mut open: Option<QueueEntry> = None;
        let all_selected = page.items.iter().all(|e| self.selected.contains(&e.id));
        let mut toggle_all = false;
        let open_id = self.detail.as_ref().map(|d| d.entry.id.clone());
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(24.0))
            .column(Column::initial(200.0).at_least(80.0).clip(true))
            .column(Column::initial(140.0))
            .column(Column::initial(180.0).clip(true))
            .column(Column::initial(200.0).clip(true))
            .column(Column::initial(60.0))
            .column(Column::initial(60.0))
            .column(Column::initial(90.0))
            .column(Column::remainder().clip(true))
            .header(22.0, |mut h| {
                h.col(|ui| {
                    let mut v = all_selected;
                    if ui.checkbox(&mut v, "").changed() {
                        toggle_all = true;
                    }
                });
                for t in ["ID", "Created", "From", "Subject", "Rcpts", "Tries", "Next try", "Last error"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, page.items.len(), |mut row| {
                    let e = &page.items[row.index()];
                    row.set_selected(open_id.as_deref() == Some(e.id.as_str()));
                    row.col(|ui| {
                        let mut v = self.selected.contains(&e.id);
                        if ui.checkbox(&mut v, "").changed() {
                            if v {
                                self.selected.insert(e.id.clone());
                            } else {
                                self.selected.remove(&e.id);
                            }
                        }
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&e.id).monospace().small());
                    });
                    row.col(|ui| {
                        ui.label(widgets::local_time(e.created));
                    });
                    row.col(|ui| {
                        ui.label(if e.sender.is_empty() { "<>" } else { &e.sender });
                    });
                    row.col(|ui| {
                        ui.label(e.subject.as_deref().unwrap_or(""));
                    });
                    row.col(|ui| {
                        ui.label(format!("{}/{}", e.pending().count(), e.recipients.len()));
                    });
                    row.col(|ui| {
                        ui.label(e.attempts.to_string());
                    });
                    row.col(|ui| {
                        ui.label(widgets::relative(e.next_attempt)).on_hover_text(widgets::local_time(e.next_attempt));
                    });
                    row.col(|ui| {
                        if let Some(err) = e.last_error() {
                            ui.label(RichText::new(err).color(AMBER)).on_hover_text(err);
                        }
                    });
                    if row.response().clicked() {
                        open = Some(e.clone());
                    }
                });
            });
        if toggle_all {
            if all_selected {
                self.selected.clear();
            } else {
                self.selected.extend(page.items.iter().map(|e| e.id.clone()));
            }
        }
        if let Some(e) = open {
            self.detail = Some(Detail { entry: e, headers: None, headers_task: None });
        }
        let _ = (ctx, client);
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context, client: &Client) {
        let Some(ids) = self.confirm_delete.clone() else { return };
        let mut decision: Option<bool> = None;
        egui::Modal::new(egui::Id::new("confirm_delete")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading("Delete from queue?");
            ui.add_space(6.0);
            ui.label(format!(
                "{} message(s) will be removed permanently. No delivery will be attempted and no \
                 non-delivery report will be sent to the sender.",
                ids.len()
            ));
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Delete").color(RED).strong()).clicked() {
                    decision = Some(true);
                }
                if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                self.confirm_delete = None;
                self.run_bulk(ctx, client, Op::Delete, ids);
            }
            Some(false) => self.confirm_delete = None,
            None => {}
        }
    }
}

fn detail_ui(
    ui: &mut Ui,
    ctx: &egui::Context,
    client: &Client,
    d: &mut Detail,
    close: &mut bool,
    op: &mut Option<(Op, String)>,
) {
    if let Some(res) = poll(&mut d.headers_task) {
        d.headers = Some(res.map_err(|e| e.message));
    }
    let e = &d.entry;
    ui.horizontal(|ui| {
        ui.heading("Message");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("✕").on_hover_text("Close").clicked() {
                *close = true;
            }
        });
    });
    ui.horizontal(|ui| {
        if ui.button("Retry now").clicked() {
            *op = Some((Op::Retry, e.id.clone()));
        }
        if ui.button(RichText::new("Delete").color(RED)).clicked() {
            *op = Some((Op::Delete, e.id.clone()));
        }
        if ui.button("Copy ID").clicked() {
            ui.ctx().copy_text(e.id.clone());
        }
    });
    ui.separator();
    egui::Grid::new("qd_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        let mut row = |k: &str, v: String| {
            ui.label(RichText::new(k).color(GREY));
            ui.label(v);
            ui.end_row();
        };
        row("ID", e.id.clone());
        row("Subject", e.subject.clone().unwrap_or_default());
        row("From", if e.sender.is_empty() { "<> (bounce)".into() } else { e.sender.clone() });
        row("Source", e.source_label());
        row("Size", widgets::bytes(e.size));
        row("Created", widgets::local_time(e.created));
        row("Attempts", e.attempts.to_string());
        row(
            "Last attempt",
            e.last_attempt
                .map(|t| format!("{} ({})", widgets::local_time(t), widgets::relative(t)))
                .unwrap_or("never".into()),
        );
        row("Next attempt", format!("{} ({})", widgets::local_time(e.next_attempt), widgets::relative(e.next_attempt)));
        if let Some(p) = &e.pool {
            row("IP pool", p.clone());
        }
        row("DKIM", if e.dkim.is_empty() { "not signed".into() } else { e.dkim.join(", ") });
    });
    ui.add_space(8.0);
    ui.strong(format!("Recipients ({})", e.recipients.len()));
    for r in &e.recipients {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (c, label) = widgets::rcpt_color(r.status);
                widgets::chip(ui, c, label);
                ui.label(RichText::new(&r.address).strong());
            });
            ui.label(
                RichText::new(format!(
                    "{} attempt(s){}{}",
                    r.attempts,
                    r.remote_host.as_deref().map(|h| format!(" · last host {h}")).unwrap_or_default(),
                    r.updated.map(|t| format!(" · {}", widgets::relative(t))).unwrap_or_default()
                ))
                .small()
                .color(GREY),
            );
            if let Some(resp) = &r.last_response {
                ui.label(RichText::new(resp).monospace().small());
            }
        });
    }
    ui.add_space(8.0);
    let hdr = egui::CollapsingHeader::new("Message headers").id_salt(&e.id).show(ui, |ui| match &d.headers {
        None => {
            ui.spinner();
        }
        Some(Err(msg)) => widgets::error_label(ui, msg),
        Some(Ok(h)) => {
            ui.label(RichText::new(format!("Full message size {}", widgets::bytes(h.size))).small().color(GREY));
            let mut text = h.headers.clone();
            ui.add(egui::TextEdit::multiline(&mut text).code_editor().desired_width(f32::INFINITY).interactive(true));
        }
    });
    if hdr.fully_open() && d.headers.is_none() && d.headers_task.is_none() {
        let (c, id) = (client.clone(), e.id.clone());
        d.headers_task = Some(Task::spawn(ctx, move || c.queue_headers(&id)));
    }
}
