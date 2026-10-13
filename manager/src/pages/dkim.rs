//! DKIM Keys: list signing keys, show the DNS record to publish, create and remove keys.
//!
//! Keys are generated on the server; the private key never crosses the network.

use crate::client::{ApiResult, CheckStatus, Client, CreatedDkimKey, DkimKey, DkimKeys, NewDkimKey};
use crate::task::{poll, Task};
use crate::widgets::{self, GREY, RED};
use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};

struct NewKeyForm {
    domain: String,
    selector: String,
    /// 0 = RSA 2048, 1 = Ed25519
    algorithm: usize,
    include_subdomains: bool,
}

impl Default for NewKeyForm {
    fn default() -> Self {
        // Dated selectors make rotation easy: publish s202611 next to s202610, then switch.
        Self {
            domain: String::new(),
            selector: format!("s{}", chrono::Local::now().format("%Y%m")),
            algorithm: 0,
            include_subdomains: false,
        }
    }
}

#[derive(Default)]
pub struct DkimPage {
    keys: Option<Vec<DkimKey>>,
    load: Option<Task<ApiResult<DkimKeys>>>,
    selected: Option<(String, String)>,
    form: Option<NewKeyForm>,
    create: Option<Task<ApiResult<CreatedDkimKey>>>,
    created: Option<CreatedDkimKey>,
    confirm_remove: Option<(String, String)>,
    remove: Option<Task<ApiResult<serde_json::Value>>>,
    error: Option<String>,
    form_error: Option<String>,
}

impl DkimPage {
    fn refresh(&mut self, ctx: &egui::Context, client: &Client) {
        if self.load.is_none() {
            let c = client.clone();
            self.load = Some(Task::spawn(ctx, move || c.dkim_keys()));
        }
    }

    pub fn ui(&mut self, ui: &mut Ui, client: &Client) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx, client);
        if self.keys.is_none() && self.load.is_none() && self.error.is_none() {
            self.refresh(&ctx, client);
        }

        ui.horizontal(|ui| {
            if ui.button("New Key…").clicked() {
                self.form = Some(NewKeyForm::default());
                self.form_error = None;
            }
            let sel = self.selected.clone();
            if ui.add_enabled(sel.is_some(), egui::Button::new("Remove")).clicked() {
                self.confirm_remove = sel;
            }
            if ui.add_enabled(self.load.is_none(), egui::Button::new("Verify DNS")).clicked() {
                self.refresh(&ctx, client);
            }
            if self.load.is_some() || self.remove.is_some() {
                ui.spinner();
            }
        });
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        ui.separator();

        let Some(empty) = self.keys.as_ref().map(Vec::is_empty) else { return };
        if empty {
            ui.label(
                RichText::new(
                    "No DKIM keys. Without DKIM, Gmail, Outlook and Yahoo are likely to reject or junk your mail. \
                     Click New Key… to create one for each domain you send from.",
                )
                .color(GREY),
            );
        } else {
            self.table(ui);
        }

        let keys = self.keys.as_deref().unwrap_or_default();
        let key = self.selected.as_ref().and_then(|(d, s)| keys.iter().find(|k| &k.domain == d && &k.selector == s));
        if let Some(k) = key {
            ui.separator();
            record_ui(ui, &k.dns_name, k.dns_value.as_deref(), Some((k.dns_status, &k.dns_detail)));
            ui.label(RichText::new(format!("Private key: {}", k.private_key)).small().color(GREY));
        }

        self.dialogs(&ctx, client);
    }

    fn poll(&mut self, ctx: &egui::Context, client: &Client) {
        if let Some(res) = poll(&mut self.load) {
            match res {
                Ok(k) => {
                    self.keys = Some(k.keys);
                    self.error = None;
                }
                Err(e) if e.status == Some(403) => {
                    self.error = Some(format!("{e} — managing DKIM keys needs an API key with the 'admin' permission."))
                }
                Err(e) => self.error = Some(e.message),
            }
        }
        if let Some(res) = poll(&mut self.create) {
            match res {
                Ok(k) => {
                    self.selected = Some((k.domain.clone(), k.selector.clone()));
                    self.created = Some(k);
                    self.form = None;
                    self.refresh(ctx, client);
                }
                Err(e) => {
                    let detail = e
                        .body
                        .as_ref()
                        .and_then(|b| b.get("errors"))
                        .and_then(|v| v.get(0))
                        .and_then(|v| v.get("message"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    self.form_error = Some(detail.unwrap_or(e.message));
                }
            }
        }
        if let Some(res) = poll(&mut self.remove) {
            match res {
                Ok(_) => {
                    self.selected = None;
                    self.refresh(ctx, client);
                }
                Err(e) => self.error = Some(e.message),
            }
        }
    }

    fn table(&mut self, ui: &mut Ui) {
        let Some(keys) = &self.keys else { return };
        let mut clicked = None;
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .max_scroll_height(260.0)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(200.0))
            .column(Column::initial(110.0))
            .column(Column::initial(120.0))
            .column(Column::initial(80.0))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                for t in ["Domain", "Selector", "Algorithm", "DNS", "Status"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, keys.len(), |mut row| {
                    let k = &keys[row.index()];
                    row.set_selected(self.selected.as_ref() == Some(&(k.domain.clone(), k.selector.clone())));
                    row.col(|ui| {
                        ui.label(if k.include_subdomains {
                            format!("{} (+ subdomains)", k.domain)
                        } else {
                            k.domain.clone()
                        });
                    });
                    row.col(|ui| {
                        ui.label(&k.selector);
                    });
                    row.col(|ui| {
                        ui.label(&k.algorithm);
                    });
                    row.col(|ui| {
                        let (c, _) = widgets::check_color(k.dns_status);
                        let label = match k.dns_status {
                            CheckStatus::Pass => "Published",
                            CheckStatus::Fail => "Not published",
                            _ => "Unknown",
                        };
                        ui.label(RichText::new(label).color(c));
                    });
                    row.col(|ui| {
                        ui.label(&k.dns_detail);
                    });
                    if row.response().clicked() {
                        clicked = Some((k.domain.clone(), k.selector.clone()));
                    }
                });
            });
        if clicked.is_some() {
            self.selected = clicked;
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context, client: &Client) {
        if let Some(form) = &mut self.form {
            let mut cancel = false;
            let mut submit = false;
            let busy = self.create.is_some();
            egui::Modal::new(egui::Id::new("dkim_new")).show(ctx, |ui| {
                ui.set_width(440.0);
                ui.heading("New DKIM Key");
                ui.add_space(6.0);
                egui::Grid::new("dkim_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Domain");
                    ui.add(egui::TextEdit::singleline(&mut form.domain).hint_text("example.com").desired_width(240.0));
                    ui.end_row();
                    ui.label("Selector");
                    ui.add(egui::TextEdit::singleline(&mut form.selector).desired_width(240.0));
                    ui.end_row();
                    ui.label("Key type");
                    egui::ComboBox::from_id_salt("dkim_alg")
                        .selected_text(["RSA 2048-bit (recommended)", "Ed25519"][form.algorithm])
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut form.algorithm, 0, "RSA 2048-bit (recommended)");
                            ui.selectable_value(&mut form.algorithm, 1, "Ed25519");
                        });
                    ui.end_row();
                    ui.label("");
                    ui.checkbox(&mut form.include_subdomains, "Also sign mail from subdomains");
                    ui.end_row();
                });
                if form.algorithm == 1 {
                    ui.label(
                        RichText::new(
                            "Some receivers cannot verify Ed25519 yet; add an RSA key for the same domain too.",
                        )
                        .small()
                        .color(GREY),
                    );
                }
                ui.label(
                    RichText::new(
                        "The key is generated on the server and added to the configuration. Signing starts \
                         immediately, so publish the DNS record shown next straight away.",
                    )
                    .small()
                    .color(GREY),
                );
                if let Some(e) = &self.form_error {
                    widgets::error_label(ui, e);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ready = !form.domain.trim().is_empty() && !form.selector.trim().is_empty() && !busy;
                    if ui.add_enabled(ready, egui::Button::new("Create")).clicked() {
                        submit = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    if busy {
                        ui.spinner();
                        ui.label(RichText::new("generating key…").color(GREY));
                    }
                });
            });
            if submit {
                let req = NewDkimKey {
                    domain: form.domain.trim().to_lowercase(),
                    selector: form.selector.trim().to_lowercase(),
                    algorithm: if form.algorithm == 0 { "rsa-sha256" } else { "ed25519-sha256" }.into(),
                    bits: 2048,
                    include_subdomains: form.include_subdomains,
                };
                let c = client.clone();
                self.form_error = None;
                self.create = Some(Task::spawn(ctx, move || c.dkim_create(&req)));
            }
            if cancel && !busy {
                self.form = None;
            }
        }

        if let Some(k) = &self.created {
            let mut close = false;
            egui::Modal::new(egui::Id::new("dkim_created")).show(ctx, |ui| {
                ui.set_width(560.0);
                ui.heading("Publish this DNS record");
                ui.label(format!(
                    "Create a TXT record in the DNS zone of {}. Mail is signed from now on; receivers can verify it once the record is live.",
                    k.domain
                ));
                ui.add_space(6.0);
                record_ui(ui, &k.dns_name, Some(&k.dns_value), None);
                ui.label(
                    RichText::new(format!("Private key saved on the server at {} — include it in your backups.", k.private_key))
                        .small()
                        .color(GREY),
                );
                ui.add_space(8.0);
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
            if close {
                self.created = None;
            }
        }

        if let Some((d, s)) = self.confirm_remove.clone() {
            let mut decision = None;
            egui::Modal::new(egui::Id::new("dkim_remove")).show(ctx, |ui| {
                ui.set_width(420.0);
                ui.heading("Remove DKIM key?");
                ui.label(format!(
                    "Mail from {d} will no longer be signed with selector {s}. The key file stays on the server, \
                     and you can remove the DNS record once no messages signed with it are in transit."
                ));
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Remove").color(RED)).clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
            if let Some(go) = decision {
                self.confirm_remove = None;
                if go {
                    let c = client.clone();
                    self.remove = Some(Task::spawn(ctx, move || c.dkim_delete(&d, &s)));
                }
            }
        }
    }
}

/// Name/value of the TXT record with copy buttons.
fn record_ui(ui: &mut Ui, name: &str, value: Option<&str>, status: Option<(CheckStatus, &str)>) {
    egui::Grid::new(("dkim_record", name)).num_columns(3).spacing([10.0, 6.0]).show(ui, |ui| {
        ui.label("Type");
        ui.label(RichText::new("TXT").monospace());
        ui.label("");
        ui.end_row();
        ui.label("Name");
        ui.label(RichText::new(name).monospace());
        if ui.small_button("Copy").clicked() {
            ui.ctx().copy_text(name.to_string());
        }
        ui.end_row();
        if let Some(v) = value {
            ui.label("Value");
            ui.add(egui::Label::new(RichText::new(v).monospace().small()).wrap());
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(v.to_string());
            }
            ui.end_row();
        }
        if let Some((s, detail)) = status {
            ui.label("Status");
            let (c, _) = widgets::check_color(s);
            ui.label(RichText::new(detail).color(c));
            ui.end_row();
        }
    });
}
