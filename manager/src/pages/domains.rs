//! Domains (IIS "Domains" node): local domains delivered to the Drop folder and
//! remote-domain rules (smart host, TLS policy, connection limit).

use crate::client::{ApiResult, Client, ConfigFile, SaveResult};
use crate::confdoc::{self, ConfigDoc};
use crate::task::{poll, Task};
use crate::widgets::{self, GREY, RED};
use egui::{RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};
use toml_edit::Table;

#[derive(Clone, PartialEq)]
enum Entry {
    Local(String),
    /// Index into `[[domain]]`.
    Remote(usize),
}

#[derive(Clone, Default)]
struct RemoteForm {
    /// None = new rule.
    index: Option<usize>,
    name: String,
    smarthost: String,
    port: String,
    tls: String,
    max_connections: String,
}

const TLS: &[(&str, &str)] = &[
    ("", "Server default"),
    ("opportunistic", "Use TLS when offered"),
    ("required", "Require TLS"),
    ("disabled", "Never use TLS"),
];

#[derive(Default)]
pub struct DomainsPage {
    doc: Option<ConfigDoc>,
    load: Option<Task<ApiResult<ConfigFile>>>,
    save: Option<Task<ApiResult<SaveResult>>>,
    selected: Option<Entry>,
    new_local: Option<String>,
    remote: Option<RemoteForm>,
    confirm_delete: Option<Entry>,
    error: Option<String>,
}

impl DomainsPage {
    fn reload(&mut self, ctx: &egui::Context, client: &Client) {
        let c = client.clone();
        self.load = Some(Task::spawn(ctx, move || c.config()));
    }

    pub fn ui(&mut self, ui: &mut Ui, client: &Client) {
        let ctx = ui.ctx().clone();
        if let Some(res) = poll(&mut self.load) {
            match res.map_err(|e| e.message).and_then(|f| ConfigDoc::from_file(&f)) {
                Ok(d) => {
                    self.doc = Some(d);
                    self.error = None;
                }
                Err(e) => self.error = Some(e),
            }
        }
        if let Some(res) = poll(&mut self.save) {
            match res {
                Ok(r) => {
                    self.error = r.reload_error.map(|e| format!("Saved, but the service could not reload: {e}"));
                    self.remote = None;
                    self.new_local = None;
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
                    self.error = Some(detail.unwrap_or(e.message));
                }
            }
            self.reload(&ctx, client);
        }
        if self.doc.is_none() && self.load.is_none() && self.error.is_none() {
            self.reload(&ctx, client);
        }

        ui.horizontal(|ui| {
            if ui.button("New Local Domain…").clicked() {
                self.new_local = Some(String::new());
            }
            if ui.button("New Remote Domain…").clicked() {
                self.remote = Some(RemoteForm::default());
            }
            let sel = self.selected.clone();
            if ui.add_enabled(matches!(sel, Some(Entry::Remote(_))), egui::Button::new("Properties…")).clicked() {
                if let (Some(Entry::Remote(i)), Some(d)) = (&sel, &self.doc) {
                    self.remote = Some(remote_form(d, *i));
                }
            }
            if ui.add_enabled(sel.is_some(), egui::Button::new("Delete")).clicked() {
                self.confirm_delete = sel;
            }
            if self.load.is_some() || self.save.is_some() {
                ui.spinner();
            }
        });
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        ui.separator();

        let Some(doc) = &self.doc else { return };
        let mut rows: Vec<(Entry, String, &str, String)> = vec![(
            Entry::Local(String::new()),
            confdoc::display(doc.get("server.hostname")),
            "Local (Default)",
            "Mail for the server's own name".into(),
        )];
        rows.retain(|(_, n, _, _)| !n.is_empty());
        for d in doc.get("server.local_domains").as_array().into_iter().flatten() {
            let n = confdoc::display(d);
            rows.push((Entry::Local(n.clone()), n, "Local (Drop)", "Written to the Drop folder".into()));
        }
        for (i, d) in doc.get("domain").as_array().into_iter().flatten().enumerate() {
            rows.push((Entry::Remote(i), confdoc::display(&d["name"]), "Remote", describe_remote(d)));
        }
        let mut clicked = None;
        TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(240.0))
            .column(Column::initial(120.0))
            .column(Column::remainder())
            .header(20.0, |mut h| {
                for t in ["Domain Name", "Type", "Delivery"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let (e, name, kind, how) = &rows[row.index()];
                    // The default domain is informational only.
                    let selectable = *e != Entry::Local(String::new());
                    row.set_selected(selectable && self.selected.as_ref() == Some(e));
                    row.col(|ui| {
                        ui.label(name);
                    });
                    row.col(|ui| {
                        ui.label(*kind);
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(how).color(GREY));
                    });
                    if selectable && row.response().clicked() {
                        clicked = Some(e.clone());
                    }
                    if selectable && row.response().double_clicked() {
                        if let Entry::Remote(i) = e {
                            self.remote = Some(remote_form(doc, *i));
                        }
                    }
                });
            });
        if clicked.is_some() {
            self.selected = clicked;
        }
        self.dialogs(&ctx, client);
    }

    fn apply(&mut self, ctx: &egui::Context, client: &Client, edit: impl FnOnce(&mut ConfigDoc) -> Result<(), String>) {
        let Some(doc) = &self.doc else { return };
        let mut d = ConfigDoc {
            doc: doc.doc.clone(),
            effective: doc.effective.clone(),
            sha256: doc.sha256.clone(),
            path: doc.path.clone(),
        };
        if let Err(e) = edit(&mut d) {
            self.error = Some(e);
            return;
        }
        let (c, text, sha) = (client.clone(), d.text(), d.sha256.clone());
        self.selected = None;
        self.save = Some(Task::spawn(ctx, move || c.save_config(&text, &sha)));
    }

    fn dialogs(&mut self, ctx: &egui::Context, client: &Client) {
        let busy = self.save.is_some();
        if let Some(name) = &mut self.new_local {
            let (mut ok, mut cancel) = (false, false);
            egui::Modal::new(egui::Id::new("new_local")).show(ctx, |ui| {
                ui.set_width(380.0);
                ui.heading("New Local Domain");
                ui.label(
                    RichText::new("Mail for this domain is written to the Drop folder instead of being sent.")
                        .color(GREY),
                );
                ui.add(egui::TextEdit::singleline(name).hint_text("intranet.example.com").desired_width(300.0));
                ui.horizontal(|ui| {
                    ok = ui.add_enabled(!busy && !name.trim().is_empty(), egui::Button::new("OK")).clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
            if ok {
                let n = name.trim().to_lowercase();
                self.apply(ctx, client, |d| {
                    let mut list: Vec<String> =
                        d.get("server.local_domains").as_array().into_iter().flatten().map(confdoc::display).collect();
                    if list.contains(&n) {
                        return Err(format!("{n} is already a local domain"));
                    }
                    list.push(n);
                    d.set("server.local_domains", confdoc::str_array(list.iter().map(String::as_str)))
                });
            } else if cancel {
                self.new_local = None;
            }
        }

        if let Some(form) = &mut self.remote {
            let (mut ok, mut cancel) = (false, false);
            egui::Modal::new(egui::Id::new("remote_domain")).show(ctx, |ui| {
                ui.set_width(440.0);
                ui.heading(if form.index.is_some() { "Remote Domain Properties" } else { "New Remote Domain" });
                ui.add_space(4.0);
                egui::Grid::new("remote_grid").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Domain name");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.name)
                            .hint_text("example.com or *.example.com")
                            .desired_width(240.0),
                    );
                    ui.end_row();
                    ui.label("Forward all mail to smart host");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.smarthost)
                            .hint_text("optional, e.g. relay.example.com")
                            .desired_width(240.0),
                    );
                    ui.end_row();
                    ui.label("Smart host port");
                    ui.add(egui::TextEdit::singleline(&mut form.port).hint_text("25").desired_width(80.0));
                    ui.end_row();
                    ui.label("TLS encryption");
                    egui::ComboBox::from_id_salt("remote_tls")
                        .selected_text(
                            TLS.iter().find(|(v, _)| *v == form.tls).map(|(_, l)| *l).unwrap_or("Server default"),
                        )
                        .show_ui(ui, |ui| {
                            for (v, l) in TLS {
                                ui.selectable_value(&mut form.tls, v.to_string(), *l);
                            }
                        });
                    ui.end_row();
                    ui.label("Limit connections to");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.max_connections)
                            .hint_text("server default")
                            .desired_width(80.0),
                    );
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    ok = ui.add_enabled(!busy && !form.name.trim().is_empty(), egui::Button::new("OK")).clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
            if ok {
                let f = form.clone();
                self.apply(ctx, client, move |d| write_remote(d, &f));
            } else if cancel {
                self.remote = None;
            }
        }

        if let Some(entry) = self.confirm_delete.clone() {
            let mut decision = None;
            egui::Modal::new(egui::Id::new("domain_delete")).show(ctx, |ui| {
                ui.heading("Delete domain?");
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Delete").color(RED)).clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
            if let Some(go) = decision {
                self.confirm_delete = None;
                if go {
                    self.apply(ctx, client, move |d| match entry {
                        Entry::Local(n) => {
                            let list: Vec<String> = d
                                .get("server.local_domains")
                                .as_array()
                                .into_iter()
                                .flatten()
                                .map(confdoc::display)
                                .filter(|x| *x != n)
                                .collect();
                            d.set("server.local_domains", confdoc::str_array(list.iter().map(String::as_str)))
                        }
                        Entry::Remote(i) => {
                            let arr = d.tables_mut("domain")?;
                            if i < arr.len() {
                                arr.remove(i);
                            }
                            if arr.is_empty() {
                                d.doc.remove("domain");
                            }
                            Ok(())
                        }
                    });
                }
            }
        }
    }
}

fn describe_remote(d: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    match d.get("smarthost").filter(|s| !s.is_null()) {
        Some(s) => {
            parts.push(format!("via smart host {}:{}", confdoc::display(&s["host"]), confdoc::display(&s["port"])))
        }
        None => parts.push("direct (MX)".into()),
    }
    if let Some(t) = d.get("tls").and_then(|t| t.as_str()) {
        parts.push(format!("TLS {t}"));
    }
    if let Some(n) = d.get("max_connections").and_then(|n| n.as_u64()) {
        parts.push(format!("max {n} connections"));
    }
    parts.join(", ")
}

fn remote_form(doc: &ConfigDoc, i: usize) -> RemoteForm {
    let d = &doc.get("domain")[i];
    let sh = d.get("smarthost").filter(|s| !s.is_null());
    RemoteForm {
        index: Some(i),
        name: confdoc::display(&d["name"]),
        smarthost: sh.map(|s| confdoc::display(&s["host"])).unwrap_or_default(),
        port: sh.map(|s| confdoc::display(&s["port"])).unwrap_or_default(),
        tls: d.get("tls").map(confdoc::display).unwrap_or_default(),
        max_connections: d.get("max_connections").map(confdoc::display).unwrap_or_default(),
    }
}

fn write_remote(d: &mut ConfigDoc, f: &RemoteForm) -> Result<(), String> {
    let max = match f.max_connections.trim() {
        "" => None,
        s => Some(s.parse::<i64>().map_err(|_| "connection limit must be a whole number")?),
    };
    let port = match f.port.trim() {
        "" => 25,
        s => s.parse::<i64>().map_err(|_| "port must be a number")?,
    };
    let arr = d.tables_mut("domain")?;
    let mut fresh = Table::new();
    let t = match f.index {
        Some(i) => arr.get_mut(i).ok_or("this domain was removed meanwhile")?,
        None => &mut fresh,
    };
    confdoc::set_in(t, "name", Some(f.name.trim().to_lowercase().into()));
    confdoc::set_in(t, "tls", (!f.tls.is_empty()).then(|| f.tls.as_str().into()));
    confdoc::set_in(t, "max_connections", max.map(Into::into));
    // Update host/port in place so other smart host settings (credentials, TLS) survive.
    match (f.smarthost.trim(), t.get_mut("smarthost").and_then(|i| i.as_table_like_mut())) {
        ("", _) => {
            t.remove("smarthost");
        }
        (host, Some(existing)) => {
            existing.insert("host", toml_edit::value(host));
            existing.insert("port", toml_edit::value(port));
        }
        (host, None) => {
            let mut it = toml_edit::InlineTable::new();
            it.insert("host", host.into());
            it.insert("port", port.into());
            t.insert("smarthost", toml_edit::Item::Value(toml_edit::Value::InlineTable(it)));
        }
    }
    if f.index.is_none() {
        arr.push(fresh);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_remote_keeps_smart_host_credentials() {
        let text = "[[domain]]\nname = \"partner.com\"\nsmarthost = { host = \"old\", port = 25, username = \"u\", password = \"p\" }\n";
        let mut d = ConfigDoc {
            doc: text.parse().unwrap(),
            effective: serde_json::json!({}),
            sha256: String::new(),
            path: String::new(),
        };
        let f = RemoteForm {
            index: Some(0),
            name: "partner.com".into(),
            smarthost: "new".into(),
            port: "587".into(),
            ..Default::default()
        };
        write_remote(&mut d, &f).unwrap();
        let out = d.text();
        assert!(out.contains("host = \"new\""));
        assert!(out.contains("port = 587"));
        assert!(out.contains("username = \"u\""));
    }
}
