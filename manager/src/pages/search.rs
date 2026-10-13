//! Message search across the live queue and the on-disk message history.

use crate::client::{ApiResult, Client, Event, EventKind, SearchResult};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, GREY};
use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};

const LIMIT: usize = 500;

pub struct Search {
    query: String,
    kind: Option<EventKind>,
    days: u32,
    result: Option<SearchResult>,
    task: Option<Task<ApiResult<SearchResult>>>,
    error: Option<String>,
    /// Message whose full timeline is shown in the side panel.
    timeline: Option<(String, Option<Vec<Event>>)>,
    timeline_task: Option<Task<ApiResult<SearchResult>>>,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            query: String::new(),
            kind: None,
            days: 7,
            result: None,
            task: None,
            error: None,
            timeline: None,
            timeline_task: None,
        }
    }
}

/// What the user asked the app to do from this page.
pub enum SearchAction {
    OpenInQueue(String),
}

impl Search {
    fn run(&mut self, ctx: &egui::Context, client: &Client) {
        let (c, q, k, d) = (client.clone(), self.query.clone(), self.kind, self.days);
        self.task = Some(Task::spawn(ctx, move || c.search(&q, k.map(EventKind::as_str), d, LIMIT)));
    }

    pub fn open_timeline(&mut self, ctx: &egui::Context, client: &Client, id: &str) {
        self.timeline = Some((id.to_string(), None));
        let (c, id, d) = (client.clone(), id.to_string(), self.days.max(30));
        self.timeline_task = Some(Task::spawn(ctx, move || c.search(&id, None, d, 1000)));
    }

    pub fn ui(&mut self, ui: &mut Ui, client: &Client) -> Option<SearchAction> {
        let ctx = ui.ctx().clone();
        let mut action = None;
        if let Some(res) = poll(&mut self.task) {
            match res {
                Ok(r) => {
                    self.result = Some(r);
                    self.error = None;
                }
                Err(e) => self.error = Some(e.message),
            }
        }
        if let Some(res) = poll(&mut self.timeline_task) {
            if let Some((id, slot)) = &mut self.timeline {
                let mut events: Vec<Event> =
                    res.map(|r| r.history.into_iter().filter(|e| &e.id == id).collect()).unwrap_or_default();
                events.sort_by_key(|e| e.time);
                *slot = Some(events);
            }
        }

        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text("Recipient, sender, subject, queue ID, remote response…")
                    .desired_width(360.0),
            );
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            egui::ComboBox::from_id_salt("search_kind")
                .selected_text(self.kind.map(EventKind::as_str).unwrap_or("any status"))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.kind, None, "any status");
                    for k in EventKind::ALL {
                        ui.selectable_value(&mut self.kind, Some(k), k.as_str());
                    }
                });
            egui::ComboBox::from_id_salt("search_days").selected_text(format!("last {} day(s)", self.days)).show_ui(
                ui,
                |ui| {
                    for d in [1, 7, 30, 90] {
                        ui.selectable_value(&mut self.days, d, format!("last {d} day(s)"));
                    }
                },
            );
            if (enter || ui.add_enabled(self.task.is_none(), egui::Button::new("Search")).clicked())
                && self.task.is_none()
            {
                self.run(&ctx, client);
            }
            if self.task.is_some() {
                ui.spinner();
            }
        });
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        ui.separator();

        // Timeline side panel.
        let mut close = false;
        if let Some((id, events)) = &self.timeline {
            egui::Panel::right("search_timeline").resizable(true).default_size(420.0).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Timeline");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("✕").clicked() {
                            close = true;
                        }
                    });
                });
                ui.label(RichText::new(id).monospace());
                ui.separator();
                match events {
                    None => {
                        ui.spinner();
                    }
                    Some(ev) if ev.is_empty() => {
                        ui.label(RichText::new("No history recorded for this message.").color(GREY));
                    }
                    Some(ev) => {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for e in ev {
                                timeline_entry(ui, e);
                            }
                        });
                    }
                }
            });
        }
        if close {
            self.timeline = None;
        }

        let Some(r) = &self.result else {
            ui.label(
                RichText::new(
                    "Search the queue and the delivery history. Leave the box empty to list the most recent events.",
                )
                .color(GREY),
            );
            return None;
        };
        if !r.history_enabled {
            ui.label(
                RichText::new("History is disabled on the server ([history] enabled = false); only recent events in memory are searched.")
                    .color(AMBER),
            );
        }

        let mut open_timeline: Option<String> = None;
        egui::ScrollArea::vertical().id_salt("search_results").show(ui, |ui| {
            if !r.queued.is_empty() {
                ui.strong(format!("Still in queue ({})", r.queued.len()));
                for e in &r.queued {
                    ui.horizontal(|ui| {
                        if ui.link(RichText::new(&e.id).monospace()).on_hover_text("Open in queue browser").clicked() {
                            action = Some(SearchAction::OpenInQueue(e.id.clone()));
                        }
                        ui.label(format!(
                            "{} → {}",
                            if e.sender.is_empty() { "<>" } else { &e.sender },
                            e.recipients.iter().map(|r| r.address.as_str()).collect::<Vec<_>>().join(", ")
                        ));
                        if let Some(s) = &e.subject {
                            ui.label(RichText::new(format!("“{}”", widgets::clip(s, 60))).color(GREY));
                        }
                        ui.label(RichText::new(format!("next try {}", widgets::relative(e.next_attempt))).color(AMBER));
                    });
                }
                ui.add_space(8.0);
            }
            ui.strong(format!(
                "History ({}{})",
                r.history.len(),
                if r.history.len() >= LIMIT { "+, refine your search" } else { "" }
            ));
            if r.history.is_empty() {
                ui.label(RichText::new("No matching events.").color(GREY));
                return;
            }
            event_table(ui, "search_hist", &r.history, |e| open_timeline = Some(e.id.clone()));
        });
        if let Some(id) = open_timeline {
            self.open_timeline(&ctx, client, &id);
        }
        action
    }
}

fn timeline_entry(ui: &mut Ui, e: &Event) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            widgets::chip(ui, widgets::kind_color(e.kind), e.kind.as_str());
            ui.label(widgets::local_time(e.time));
            if let Some(a) = e.attempt {
                ui.label(RichText::new(format!("attempt {a}")).color(GREY));
            }
        });
        if let Some(to) = &e.to {
            ui.label(format!("to {to}"));
        }
        if let Some(r) = &e.relay {
            ui.label(RichText::new(format!("via {r}")).color(GREY));
        }
        if let Some(d) = &e.detail {
            ui.label(RichText::new(d).monospace().small());
        }
    });
}

/// Shared event table (search results and live log). `on_click` fires for a clicked row.
pub fn event_table<'a>(ui: &mut Ui, id: &str, events: &'a [Event], mut on_click: impl FnMut(&'a Event)) {
    TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .resizable(true)
        .sense(Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(140.0))
        .column(Column::initial(76.0))
        .column(Column::initial(200.0).clip(true))
        .column(Column::initial(180.0).clip(true))
        .column(Column::initial(180.0).clip(true))
        .column(Column::initial(160.0).clip(true))
        .column(Column::remainder().clip(true))
        .header(22.0, |mut h| {
            for t in ["Time", "Status", "Message ID", "From", "To", "Relay", "Detail"] {
                h.col(|ui| {
                    ui.strong(t);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, events.len(), |mut row| {
                let e = &events[row.index()];
                row.col(|ui| {
                    ui.label(widgets::local_time(e.time));
                });
                row.col(|ui| widgets::chip(ui, widgets::kind_color(e.kind), e.kind.as_str()));
                row.col(|ui| {
                    ui.label(RichText::new(&e.id).monospace().small());
                });
                row.col(|ui| {
                    ui.label(if e.from.is_empty() { "<>" } else { &e.from });
                });
                row.col(|ui| {
                    ui.label(e.to.as_deref().unwrap_or(""));
                });
                row.col(|ui| {
                    ui.label(e.relay.as_deref().unwrap_or(""));
                });
                row.col(|ui| {
                    let mut text = e.detail.clone().unwrap_or_default();
                    if let Some(s) = &e.subject {
                        if text.is_empty() {
                            text = format!("“{s}”");
                        }
                    }
                    ui.label(&text).on_hover_text(&text);
                });
                if row.response().clicked() {
                    on_click(e);
                }
            });
        });
}
