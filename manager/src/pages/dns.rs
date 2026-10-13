//! Deliverability DNS check: rDNS/FCrDNS, HELO, SPF, DKIM, DMARC and MX.

use crate::client::{ApiResult, CheckReport, CheckStatus, Client};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, GREEN, GREY, RED};
use egui::{RichText, Ui};

#[derive(Default)]
pub struct DnsCheck {
    pub domain: String,
    ips: String,
    report: Option<CheckReport>,
    task: Option<Task<ApiResult<CheckReport>>>,
    error: Option<String>,
}

impl DnsCheck {
    /// Returns true when a check was started (so the caller can persist the domain).
    pub fn ui(&mut self, ui: &mut Ui, client: &Client) -> bool {
        let ctx = ui.ctx().clone();
        let mut started = false;
        if let Some(res) = poll(&mut self.task) {
            match res {
                Ok(r) => {
                    self.report = Some(r);
                    self.error = None;
                }
                Err(e) if e.status == Some(403) => {
                    self.error = Some(format!("{e} — DNS checks need an API key with the 'admin' permission."))
                }
                Err(e) => self.error = Some(e.message),
            }
        }

        ui.label(
            RichText::new(
                "Verifies what Gmail, Outlook and Yahoo check before accepting your mail: reverse DNS of each \
                 sending IP, HELO name, SPF, DKIM (against the keys configured on this server), DMARC and MX.",
            )
            .color(GREY),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Sending domain");
            let r1 = ui.add(egui::TextEdit::singleline(&mut self.domain).hint_text("example.com").desired_width(220.0));
            ui.label("Public IP(s)");
            let r2 = ui
                .add(
                    egui::TextEdit::singleline(&mut self.ips)
                        .hint_text("optional, e.g. 203.0.113.10")
                        .desired_width(220.0),
                )
                .on_hover_text(
                    "Leave empty to use the [[outbound_ip]] addresses from the configuration, or the server's \
                 detected address. Behind NAT, enter the public address here.",
                );
            let enter = (r1.lost_focus() || r2.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let can_run = self.task.is_none() && !self.domain.trim().is_empty();
            if (ui.add_enabled(can_run, egui::Button::new("Run check")).clicked() || (enter && can_run)) && can_run {
                let (c, d, ips) = (client.clone(), self.domain.trim().to_lowercase(), self.ips.clone());
                self.task = Some(Task::spawn(&ctx, move || c.check(&d, &ips)));
                started = true;
            }
            if self.task.is_some() {
                ui.spinner();
                ui.label(RichText::new("querying DNS…").color(GREY));
            }
        });
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        ui.separator();

        let Some(r) = &self.report else { return started };
        let count = |s: CheckStatus| r.items.iter().filter(|i| i.status == s).count();
        let (fail, warn, pass) = (count(CheckStatus::Fail), count(CheckStatus::Warn), count(CheckStatus::Pass));
        ui.horizontal(|ui| {
            ui.label(RichText::new(&r.domain).strong().size(18.0));
            if !r.ips.is_empty() {
                ui.label(RichText::new(format!("from {}", r.ips.join(", "))).color(GREY));
            }
        });
        let (summary, color) = if fail > 0 {
            (format!("{fail} problem(s) will hurt deliverability"), RED)
        } else if warn > 0 {
            (format!("No blocking problems; {warn} warning(s) to review"), AMBER)
        } else {
            ("All checks passed".to_string(), GREEN)
        };
        ui.label(RichText::new(format!("{summary}  ·  {pass} pass, {warn} warn, {fail} fail")).color(color).strong());
        ui.add_space(6.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("dns_grid").num_columns(3).striped(true).spacing([14.0, 8.0]).show(ui, |ui| {
                for item in &r.items {
                    let (c, label) = widgets::check_color(item.status);
                    widgets::chip(ui, c, label);
                    ui.label(RichText::new(&item.check).strong());
                    // Records (SPF/DKIM values) can be long; let them wrap.
                    ui.add(egui::Label::new(&item.detail).wrap());
                    ui.end_row();
                }
            });
        });
        started
    }
}
