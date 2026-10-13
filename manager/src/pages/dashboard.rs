//! Dashboard: live counters, throughput, bounce rate and queue size over time.

use crate::client::{ApiResult, Client, Sample, Stats, StatsHistory};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, BLUE, GREEN, GREY, RED};
use egui::{Color32, RichText, Ui};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use std::time::{Duration, Instant};

const STATS_EVERY: Duration = Duration::from_secs(2);
const HISTORY_EVERY: Duration = Duration::from_secs(10);
/// Matches the server's 24 h buffer.
const MAX_SAMPLES: usize = 8640;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Window {
    M15,
    H1,
    H6,
    H24,
}

impl Window {
    const ALL: [Window; 4] = [Window::M15, Window::H1, Window::H6, Window::H24];
    fn secs(self) -> i64 {
        match self {
            Window::M15 => 15 * 60,
            Window::H1 => 3600,
            Window::H6 => 6 * 3600,
            Window::H24 => 24 * 3600,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Window::M15 => "15 min",
            Window::H1 => "1 hour",
            Window::H6 => "6 hours",
            Window::H24 => "24 hours",
        }
    }
}

/// Recipient outcomes inside the selected time window.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct WindowTotals {
    /// Messages accepted (SMTP + pickup + API).
    pub received: u64,
    /// Recipients accepted by the remote server.
    pub delivered: u64,
    /// Temporary failures; these recipients are retried later.
    pub deferred: u64,
    /// Permanent failures and expiries (an NDR was or will be sent).
    pub bounced: u64,
}

/// Bounce rate shown on the dashboard, as a fraction in 0.0..=1.0, or `None`
/// to display "—" when there is not enough data to be meaningful.
pub fn bounce_rate(t: &WindowTotals) -> Option<f64> {
    // TODO(you): define the bounce rate for your operators. See the notes in
    // the chat; this one decision drives the dashboard's headline KPI and its
    // colour thresholds below.
    let _ = t;
    None
}

pub struct Dashboard {
    stats: Option<Stats>,
    samples: Vec<Sample>,
    interval: u64,
    window: Window,
    error: Option<String>,
    stats_task: Option<Task<ApiResult<Stats>>>,
    history_task: Option<Task<ApiResult<StatsHistory>>>,
    last_stats: Option<Instant>,
    last_history: Option<Instant>,
}

impl Default for Dashboard {
    fn default() -> Self {
        Self {
            stats: None,
            samples: Vec::new(),
            interval: 10,
            window: Window::H1,
            error: None,
            stats_task: None,
            history_task: None,
            last_stats: None,
            last_history: None,
        }
    }
}

/// Sum of positive deltas of a cumulative counter; a decrease means the
/// service restarted (counters reset), so that step contributes nothing.
fn delta(samples: &[Sample], f: impl Fn(&Sample) -> u64) -> u64 {
    samples.windows(2).map(|w| f(&w[1]).saturating_sub(f(&w[0]))).sum()
}

/// Per-minute rate series of a cumulative counter, plotted at each sample time.
fn rate_series(samples: &[Sample], f: impl Fn(&Sample) -> u64) -> Vec<[f64; 2]> {
    samples
        .windows(2)
        .filter(|w| w[1].t > w[0].t)
        .map(|w| {
            let dt = (w[1].t - w[0].t) as f64;
            let dv = f(&w[1]).saturating_sub(f(&w[0])) as f64;
            [w[1].t as f64, dv * 60.0 / dt]
        })
        .collect()
}

impl Dashboard {
    /// Called every frame, visible or not, so the charts have data when opened.
    pub fn tick(&mut self, ctx: &egui::Context, client: &Client) {
        if let Some(res) = poll(&mut self.stats_task) {
            match res {
                Ok(s) => {
                    // Uptime went backwards: the service restarted and its
                    // in-memory history was reset, so start ours over too.
                    if self.stats.as_ref().is_some_and(|old| s.uptime_seconds < old.uptime_seconds) {
                        self.samples.clear();
                        self.last_history = None;
                    }
                    self.stats = Some(s);
                    self.error = None;
                }
                Err(e) => self.error = Some(e.message),
            }
        }
        if let Some(res) = poll(&mut self.history_task) {
            match res {
                Ok(h) => {
                    self.interval = h.interval_seconds.max(1);
                    let last = self.samples.last().map(|s| s.t).unwrap_or(i64::MIN);
                    self.samples.extend(h.samples.into_iter().filter(|s| s.t > last));
                    let excess = self.samples.len().saturating_sub(MAX_SAMPLES);
                    self.samples.drain(..excess);
                }
                Err(e) => self.error = Some(e.message),
            }
        }
        let due = |last: Option<Instant>, every: Duration| last.is_none_or(|t| t.elapsed() >= every);
        if self.stats_task.is_none() && due(self.last_stats, STATS_EVERY) {
            self.last_stats = Some(Instant::now());
            let c = client.clone();
            self.stats_task = Some(Task::spawn(ctx, move || c.stats()));
        }
        if self.history_task.is_none() && due(self.last_history, HISTORY_EVERY) {
            self.last_history = Some(Instant::now());
            let c = client.clone();
            let since = self.samples.last().map(|s| s.t).unwrap_or(0);
            self.history_task = Some(Task::spawn(ctx, move || c.stats_history(since)));
        }
    }

    fn window_samples(&self) -> &[Sample] {
        let Some(last) = self.samples.last() else { return &[] };
        let from = last.t - self.window.secs();
        // Include one sample before the window so the first delta is counted.
        let start = self.samples.partition_point(|s| s.t < from).saturating_sub(1);
        &self.samples[start..]
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        ui.horizontal(|ui| {
            ui.label("Statistics for the last");
            egui::ComboBox::from_id_salt("status_window").selected_text(self.window.label()).show_ui(ui, |ui| {
                for w in Window::ALL {
                    ui.selectable_value(&mut self.window, w, w.label());
                }
            });
        });
        let win = self.window_samples();
        let totals = WindowTotals {
            received: delta(win, |s| s.received),
            delivered: delta(win, |s| s.delivered),
            deferred: delta(win, |s| s.deferred),
            bounced: delta(win, |s| s.bounced),
        };
        let span_min = match (win.first(), win.last()) {
            (Some(a), Some(b)) if b.t > a.t => (b.t - a.t) as f64 / 60.0,
            _ => 0.0,
        };
        let throughput = if span_min > 0.0 { totals.delivered as f64 / span_min } else { 0.0 };
        let stats = self.stats.clone().unwrap_or_default();
        let (rate_text, rate_color) = match bounce_rate(&totals) {
            // Mailbox providers start throttling well before 5 %.
            Some(r) if r >= 0.05 => (format!("{:.2}%", r * 100.0), RED),
            Some(r) if r >= 0.02 => (format!("{:.2}%", r * 100.0), AMBER),
            Some(r) => (format!("{:.2}%", r * 100.0), ui.visuals().text_color()),
            None => ("—".into(), GREY),
        };

        ui.add_space(4.0);
        let text = ui.visuals().text_color();
        egui::Grid::new("status_grid").num_columns(2).striped(true).spacing([40.0, 6.0]).min_col_width(200.0).show(
            ui,
            |ui| {
                let mut row = |k: &str, v: String, c: Color32| {
                    ui.label(k);
                    ui.label(RichText::new(v).color(c));
                    ui.end_row();
                };
                let state = if self.stats.is_some() { "Running" } else { "Unknown" };
                row("State", format!("{state} (up {})", widgets::duration(stats.uptime_seconds)), text);
                row("Messages in queue", stats.queue_size.to_string(), if stats.queue_size > 0 { BLUE } else { text });
                row("Being delivered", stats.deliveries_in_flight.to_string(), text);
                row("Throughput", format!("{throughput:.1} recipients/min"), text);
                row("Delivered", totals.delivered.to_string(), text);
                row(
                    "Deferred (will retry)",
                    totals.deferred.to_string(),
                    if totals.deferred > 0 { AMBER } else { text },
                );
                row("Bounced", totals.bounced.to_string(), if totals.bounced > 0 { RED } else { text });
                row("Bounce rate", rate_text, rate_color);
                row("Received", totals.received.to_string(), text);
                row("Open SMTP connections", stats.connections_active.to_string(), text);
            },
        );
        ui.add_space(10.0);

        if win.len() < 2 {
            ui.label(
                RichText::new(format!("Collecting data… the server records a sample every {} seconds.", self.interval))
                    .color(GREY),
            );
            return;
        }
        let time_axis = |mark: egui_plot::GridMark, _: &std::ops::RangeInclusive<f64>| {
            chrono::DateTime::from_timestamp(mark.value as i64, 0)
                .map(|t| t.with_timezone(&chrono::Local).format("%H:%M").to_string())
                .unwrap_or_default()
        };
        ui.label("Recipients per minute");
        Plot::new("throughput")
            .height(ui.available_height().clamp(140.0, 260.0))
            .legend(Legend::default())
            .x_axis_formatter(time_axis)
            .include_y(0.0)
            .allow_scroll(false)
            .show(ui, |p| {
                p.line(series("Delivered", rate_series(win, |s| s.delivered), GREEN));
                p.line(series("Deferred", rate_series(win, |s| s.deferred), AMBER));
                p.line(series("Bounced", rate_series(win, |s| s.bounced), RED));
                p.line(series("Queued", win.iter().map(|s| [s.t as f64, s.queue as f64]).collect(), BLUE));
            });
    }
}

fn series(name: &str, points: Vec<[f64; 2]>, color: Color32) -> Line<'static> {
    Line::new(name, PlotPoints::from(points)).color(color).width(1.5)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: i64, delivered: u64) -> Sample {
        Sample { t, received: 0, delivered, deferred: 0, bounced: 0, queue: 0 }
    }

    #[test]
    fn deltas_survive_counter_reset() {
        // 10 → 25 (+15), restart resets to 3 (ignored), 3 → 8 (+5)
        let v = [s(0, 10), s(10, 25), s(20, 3), s(30, 8)];
        assert_eq!(delta(&v, |x| x.delivered), 20);
    }

    #[test]
    fn rates_are_per_minute() {
        let v = [s(0, 0), s(10, 5)];
        assert_eq!(rate_series(&v, |x| x.delivered), vec![[10.0, 30.0]]);
    }
}
