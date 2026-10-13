//! Live delivery log: tails the server's event stream.

use crate::client::{ApiResult, Client, Event, EventKind, EventPage};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, GREY};
use egui::{RichText, Ui};
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

const POLL_EVERY: Duration = Duration::from_secs(1);
/// Client-side cap; older lines scroll away.
const KEEP: usize = 5000;

pub struct LiveLog {
    events: VecDeque<Event>,
    last_seq: u64,
    paused: bool,
    filter: String,
    kinds: HashSet<EventKind>,
    task: Option<Task<ApiResult<EventPage>>>,
    last_poll: Option<Instant>,
    error: Option<String>,
    missed: bool,
    /// Messages clicked in the log, to open in search.
    pub open_request: Option<String>,
}

impl Default for LiveLog {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            last_seq: 0,
            paused: false,
            filter: String::new(),
            kinds: EventKind::ALL.into_iter().chain([EventKind::Other]).collect(),
            task: None,
            last_poll: None,
            error: None,
            missed: false,
            open_request: None,
        }
    }
}

impl LiveLog {
    /// Called every frame, visible or not, so the log keeps filling in the background.
    pub fn tick(&mut self, ctx: &egui::Context, client: &Client) {
        if let Some(res) = poll(&mut self.task) {
            match res {
                Ok(page) => {
                    if page.last_seq < self.last_seq {
                        // Server restarted; its sequence numbers start over.
                        self.missed = true;
                    }
                    if page.gap {
                        self.missed = true;
                    }
                    self.last_seq = page.last_seq;
                    self.events.extend(page.events);
                    let excess = self.events.len().saturating_sub(KEEP);
                    self.events.drain(..excess);
                    self.error = None;
                }
                Err(e) => self.error = Some(e.message),
            }
        }
        if !self.paused && self.task.is_none() && self.last_poll.is_none_or(|t| t.elapsed() >= POLL_EVERY) {
            self.last_poll = Some(Instant::now());
            let (c, after) = (client.clone(), self.last_seq);
            self.task = Some(Task::spawn(ctx, move || c.events(after)));
        }
        ctx.request_repaint_after(POLL_EVERY);
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let label = if self.paused { "Resume" } else { "Pause" };
            if ui.button(label).clicked() {
                self.paused = !self.paused;
            }
            if ui.button("Clear").clicked() {
                self.events.clear();
                self.missed = false;
            }
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter…").desired_width(220.0));
            ui.label(RichText::new(format!("{} event(s)", self.events.len())).color(GREY));
            if self.paused {
                ui.label(RichText::new("paused").color(AMBER));
            }
        });
        ui.horizontal_wrapped(|ui| {
            for k in EventKind::ALL {
                let mut on = self.kinds.contains(&k);
                let text = RichText::new(k.as_str()).color(widgets::kind_color(k));
                if ui.toggle_value(&mut on, text).changed() {
                    if on {
                        self.kinds.insert(k);
                    } else {
                        self.kinds.remove(&k);
                    }
                }
            }
        });
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        if self.missed {
            ui.label(
                RichText::new(
                    "Some events were missed (the service restarted or the log fell behind). Use Search to see them.",
                )
                .color(AMBER),
            );
        }
        ui.separator();

        let needle = self.filter.trim().to_lowercase();
        // Newest first, so new activity appears at the top without scrolling.
        let shown: Vec<Event> =
            self.events.iter().rev().filter(|e| self.kinds.contains(&e.kind) && e.matches(&needle)).cloned().collect();
        if shown.is_empty() {
            ui.label(RichText::new("Waiting for delivery activity…").color(GREY));
            return;
        }
        let mut clicked = None;
        crate::pages::search::event_table(ui, "live_log", &shown, |e| clicked = Some(e.id.clone()));
        if clicked.is_some() {
            self.open_request = clicked;
        }
    }
}
