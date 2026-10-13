//! "SMTP Virtual Server Properties" — the IIS 6 property sheet, backed by promailer.toml.
//!
//! Tabs and wording follow IIS 6 so administrators find familiar settings.
//! Only changed settings are written (see `confdoc.rs`), then the server
//! validates, backs up, saves and hot-reloads.

use crate::client::{ApiError, ApiResult, Client, ConfigFile, SaveResult, Validation};
use crate::confdoc::{self, ConfigDoc};
use crate::task::{poll, Task};
use crate::widgets::{self, AMBER, GREY, RED};
use egui::{RichText, Ui};
use std::collections::HashMap;
use toml_edit::Table;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    /// Empty removes the setting (server default applies).
    OptText,
    Password,
    Int,
    Bool,
    /// "25MB", "512KB" or bytes.
    Size,
    /// "30s", "10m", "2days".
    Duration,
    /// One entry per line (IP/CIDR lists, domains).
    Lines,
    /// Comma-separated durations.
    DurList,
    Choice(&'static [(&'static str, &'static str)]),
}

struct Field {
    path: &'static str,
    label: &'static str,
    kind: Kind,
}

enum Row {
    Group(&'static str),
    F(Field),
    Note(&'static str),
}

const fn f(path: &'static str, label: &'static str, kind: Kind) -> Row {
    Row::F(Field { path, label, kind })
}

const OUT_TLS: &[(&str, &str)] = &[
    ("opportunistic", "Use TLS when offered (recommended)"),
    ("required", "Require TLS"),
    ("disabled", "Never use TLS"),
];
const SMART_TLS: &[(&str, &str)] =
    &[("starttls", "STARTTLS"), ("implicit", "TLS (port 465)"), ("none", "None (plain text)")];
const ACCESS_DEFAULT: &[(&str, &str)] = &[("allow", "All except the list below"), ("deny", "Only the list below")];
const LOG_LEVEL: &[(&str, &str)] =
    &[("error", "Errors"), ("warn", "Warnings"), ("info", "Information"), ("debug", "Verbose")];

const GENERAL: &[Row] = &[
    Row::Group("Connections"),
    f("limits.max_connections", "Limit number of connections to", Kind::Int),
    f("limits.max_connections_per_ip", "Limit connections per client IP to", Kind::Int),
    f("limits.command_timeout", "Connection time-out", Kind::Duration),
    Row::Group("Logging"),
    f("logging.protocol_log", "Enable SMTP protocol logging", Kind::Bool),
    f("logging.delivery_log", "Enable delivery logging", Kind::Bool),
    f("logging.level", "Service log level", Kind::Choice(LOG_LEVEL)),
    Row::Note("Listener and logging changes take effect after the service restarts."),
];

const ACCESS: &[Row] = &[
    Row::Group("Connection control"),
    f("access.default", "Grant access to", Kind::Choice(ACCESS_DEFAULT)),
    f("access.allow", "Always granted (IP or network, one per line)", Kind::Lines),
    f("access.deny", "Denied (IP or network, one per line)", Kind::Lines),
    f("access.reverse_dns_lookup", "Perform reverse DNS lookup on incoming messages", Kind::Bool),
    Row::Group("Relay restrictions"),
    f("access.relay_allow", "Computers allowed to relay (IP or network, one per line)", Kind::Lines),
    f("access.relay_authenticated", "Allow all computers which successfully authenticate to relay", Kind::Bool),
];

const MESSAGES: &[Row] = &[
    Row::Group("Limits"),
    f("limits.max_message_size", "Limit message size to", Kind::Size),
    f("limits.max_session_size", "Limit session size to", Kind::Size),
    f("limits.max_messages_per_connection", "Limit number of messages per connection to", Kind::Int),
    f("limits.max_recipients_per_message", "Limit number of recipients per message to", Kind::Int),
    f("limits.max_queue_size", "Stop accepting mail when the queue holds (0 = no limit)", Kind::Int),
    Row::Group("Non-delivery reports"),
    f("delivery.send_ndr", "Send non-delivery reports to the sender", Kind::Bool),
    f("delivery.ndr_copy_to", "Send copy of Non-Delivery Report to", Kind::OptText),
    f("server.postmaster", "Postmaster address (NDR sender)", Kind::OptText),
];

const DELIVERY: &[Row] = &[
    Row::Group("Outbound"),
    f("delivery.retry_intervals", "Retry intervals (first, second, …; last repeats)", Kind::DurList),
    f("delivery.expire_after", "Expiration timeout", Kind::Duration),
    f("delivery.delay_notification_after", "Delay notification (0s = never)", Kind::Duration),
    Row::Group("Outbound security"),
    f("delivery.tls", "TLS encryption", Kind::Choice(OUT_TLS)),
    f("delivery.verify_certificates", "Verify remote server certificates", Kind::Bool),
    Row::Group("Outbound connections"),
    f("delivery.max_connections", "Limit number of connections to", Kind::Int),
    f("delivery.max_connections_per_domain", "Limit number of connections per domain to", Kind::Int),
    f("delivery.connect_timeout", "Time-out", Kind::Duration),
    Row::Group("Advanced"),
    f("server.hostname", "Fully-qualified domain name", Kind::Text),
    f("server.masquerade_domain", "Masquerade domain", Kind::OptText),
    f("server.max_hop_count", "Maximum hop count", Kind::Int),
    Row::Group("Smart host"),
    f("delivery.smarthost.host", "Smart host (empty = deliver directly)", Kind::OptText),
    f("delivery.smarthost.port", "Port", Kind::Int),
    f("delivery.smarthost.tls", "Encryption", Kind::Choice(SMART_TLS)),
    f("delivery.smarthost.username", "User name", Kind::OptText),
    f("delivery.smarthost.password", "Password", Kind::Password),
    f("delivery.attempt_direct_before_smarthost", "Attempt direct delivery before sending to smart host", Kind::Bool),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    General,
    Access,
    Messages,
    Delivery,
}

impl Tab {
    const ALL: [Tab; 4] = [Tab::General, Tab::Access, Tab::Messages, Tab::Delivery];
    fn label(self) -> &'static str {
        match self {
            Tab::General => "General",
            Tab::Access => "Access",
            Tab::Messages => "Messages",
            Tab::Delivery => "Delivery",
        }
    }
    fn rows(self) -> &'static [Row] {
        match self {
            Tab::General => GENERAL,
            Tab::Access => ACCESS,
            Tab::Messages => MESSAGES,
            Tab::Delivery => DELIVERY,
        }
    }
}

#[derive(Clone, PartialEq)]
struct Buf {
    text: String,
    flag: bool,
}

#[derive(Clone, PartialEq)]
struct ListenerRow {
    orig: Option<usize>,
    name: String,
    bind: String,
    tls: String,
    require_auth: bool,
    require_tls: bool,
    allow_plaintext_auth: bool,
}

#[derive(Clone, PartialEq)]
struct UserRow {
    orig: Option<usize>,
    username: String,
    /// Set when a new password was entered.
    new_hash: Option<String>,
    disabled: bool,
}

#[derive(Default)]
struct NewUser {
    username: String,
    password: String,
    confirm: String,
    error: Option<String>,
}

struct Loaded {
    doc: ConfigDoc,
    initial: HashMap<&'static str, Buf>,
    bufs: HashMap<&'static str, Buf>,
    listeners0: Vec<ListenerRow>,
    listeners: Vec<ListenerRow>,
    users0: Vec<UserRow>,
    users: Vec<UserRow>,
}

pub struct Properties {
    pub open: bool,
    tab: Tab,
    loaded: Option<Loaded>,
    load: Option<Task<ApiResult<ConfigFile>>>,
    save: Option<Task<ApiResult<SaveResult>>>,
    close_after_save: bool,
    new_user: NewUser,
    error: Option<String>,
    validation: Option<Validation>,
    notice: Option<String>,
}

impl Default for Properties {
    fn default() -> Self {
        Self {
            open: false,
            tab: Tab::General,
            loaded: None,
            load: None,
            save: None,
            close_after_save: false,
            new_user: NewUser::default(),
            error: None,
            validation: None,
            notice: None,
        }
    }
}

fn buf_from(doc: &ConfigDoc, f: &Field) -> Buf {
    let v = doc.get(f.path);
    match f.kind {
        Kind::Bool => Buf { text: String::new(), flag: v.as_bool().unwrap_or(false) },
        Kind::Size => Buf { text: confdoc::size_text(v), flag: false },
        Kind::DurList => Buf {
            text: v
                .as_array()
                .map(|a| a.iter().map(confdoc::display).collect::<Vec<_>>().join(", "))
                .unwrap_or_default(),
            flag: false,
        },
        _ => Buf { text: confdoc::display(v), flag: false },
    }
}

fn str_of(v: &serde_json::Value, k: &str) -> String {
    v.get(k).map(confdoc::display).unwrap_or_default()
}

fn bool_of(v: &serde_json::Value, k: &str) -> bool {
    v.get(k).and_then(|b| b.as_bool()).unwrap_or(false)
}

fn all_fields() -> impl Iterator<Item = &'static Field> {
    Tab::ALL.into_iter().flat_map(|t| t.rows()).filter_map(|r| match r {
        Row::F(f) => Some(f),
        _ => None,
    })
}

impl Loaded {
    fn new(doc: ConfigDoc) -> Self {
        let bufs: HashMap<_, _> = all_fields().map(|f| (f.path, buf_from(&doc, f))).collect();
        // Map rows to their position in the file only when the file actually
        // contains them (the server synthesises a default listener otherwise).
        let in_file = |name: &str| doc.doc.get(name).and_then(|i| i.as_array_of_tables()).map(|a| a.len()).unwrap_or(0);
        let eff = |name: &str| doc.get(name).as_array().cloned().unwrap_or_default();
        let (lf, le) = (in_file("listener"), eff("listener"));
        let listeners: Vec<ListenerRow> = le
            .iter()
            .enumerate()
            .map(|(i, l)| ListenerRow {
                orig: (lf == le.len()).then_some(i),
                name: str_of(l, "name"),
                bind: str_of(l, "bind"),
                tls: str_of(l, "tls"),
                require_auth: bool_of(l, "require_auth"),
                require_tls: bool_of(l, "require_tls"),
                allow_plaintext_auth: bool_of(l, "allow_plaintext_auth"),
            })
            .collect();
        let ue = eff("user");
        let users: Vec<UserRow> = ue
            .iter()
            .enumerate()
            .map(|(i, u)| UserRow {
                orig: (in_file("user") == ue.len()).then_some(i),
                username: str_of(u, "username"),
                new_hash: None,
                disabled: bool_of(u, "disabled"),
            })
            .collect();
        Self {
            doc,
            initial: bufs.clone(),
            bufs,
            listeners0: listeners.clone(),
            listeners,
            users0: users.clone(),
            users,
        }
    }

    fn dirty(&self) -> bool {
        self.bufs != self.initial || self.listeners != self.listeners0 || self.users != self.users0
    }

    /// Produce the new file text, or a message describing invalid input.
    fn build(&self) -> Result<String, String> {
        let mut doc = ConfigDoc {
            doc: self.doc.doc.clone(),
            effective: self.doc.effective.clone(),
            sha256: self.doc.sha256.clone(),
            path: self.doc.path.clone(),
        };
        let smarthost_off = self.bufs.get("delivery.smarthost.host").is_some_and(|b| b.text.trim().is_empty());
        for f in all_fields() {
            let (Some(new), Some(old)) = (self.bufs.get(f.path), self.initial.get(f.path)) else { continue };
            if f.path.starts_with("delivery.smarthost.") && smarthost_off {
                continue;
            }
            if new == old {
                continue;
            }
            let t = new.text.trim();
            let v: Option<toml_edit::Value> = match f.kind {
                Kind::Bool => Some(new.flag.into()),
                Kind::Int => {
                    Some(t.parse::<i64>().map_err(|_| format!("'{}' must be a whole number", f.label))?.into())
                }
                Kind::Size if t.chars().all(|c| c.is_ascii_digit()) && !t.is_empty() => {
                    Some(t.parse::<i64>().map_err(|_| format!("'{}' is too large", f.label))?.into())
                }
                Kind::OptText | Kind::Password if t.is_empty() => None,
                Kind::Lines => Some(confdoc::str_array(new.text.lines().map(str::trim).filter(|l| !l.is_empty()))),
                Kind::DurList => Some(confdoc::str_array(t.split(',').map(str::trim).filter(|l| !l.is_empty()))),
                _ => Some(t.into()),
            };
            match v {
                Some(v) => doc.set(f.path, v)?,
                None => doc.remove(f.path),
            }
        }
        if smarthost_off && !doc.get("delivery.smarthost").is_null() {
            doc.remove("delivery.smarthost");
        }

        if self.listeners != self.listeners0 {
            let removed: Vec<usize> = self
                .listeners0
                .iter()
                .filter_map(|r| r.orig)
                .filter(|o| !self.listeners.iter().any(|r| r.orig == Some(*o)))
                .collect();
            let arr = doc.tables_mut("listener")?;
            sync_rows(
                arr,
                &removed,
                &self.listeners,
                |r| r.orig,
                |r, t| {
                    confdoc::set_in(t, "name", Some(r.name.trim().into()));
                    confdoc::set_in(t, "bind", Some(r.bind.trim().into()));
                    confdoc::set_in(t, "tls", Some(r.tls.as_str().into()));
                    confdoc::set_in(t, "require_auth", Some(r.require_auth.into()));
                    confdoc::set_in(t, "require_tls", Some(r.require_tls.into()));
                    confdoc::set_in(t, "allow_plaintext_auth", Some(r.allow_plaintext_auth.into()));
                },
            );
        }
        if self.users != self.users0 {
            let removed: Vec<usize> = self
                .users0
                .iter()
                .filter_map(|r| r.orig)
                .filter(|o| !self.users.iter().any(|r| r.orig == Some(*o)))
                .collect();
            let arr = doc.tables_mut("user")?;
            sync_rows(
                arr,
                &removed,
                &self.users,
                |r| r.orig,
                |r, t| {
                    confdoc::set_in(t, "username", Some(r.username.trim().into()));
                    if let Some(h) = &r.new_hash {
                        confdoc::set_in(t, "password_hash", Some(h.as_str().into()));
                    }
                    confdoc::set_in(t, "disabled", r.disabled.then(|| true.into()));
                },
            );
            if arr.is_empty() {
                doc.doc.remove("user");
            }
        }
        Ok(doc.text())
    }
}

/// Apply edited rows to an array of tables: remove deleted entries (so their
/// other settings, e.g. a user's allowed IPs, never shift onto a neighbour),
/// update kept ones in place, append new ones.
fn sync_rows<R>(
    arr: &mut toml_edit::ArrayOfTables,
    removed: &[usize],
    rows: &[R],
    orig: impl Fn(&R) -> Option<usize>,
    write: impl Fn(&R, &mut Table),
) {
    let mut removed = removed.to_vec();
    removed.sort_unstable();
    for &i in removed.iter().rev() {
        if i < arr.len() {
            arr.remove(i);
        }
    }
    for r in rows {
        match orig(r) {
            Some(o) => {
                let idx = o - removed.iter().filter(|&&x| x < o).count();
                if let Some(t) = arr.get_mut(idx) {
                    write(r, t);
                }
            }
            None => {
                let mut t = Table::new();
                write(r, &mut t);
                arr.push(t);
            }
        }
    }
}

impl Properties {
    pub fn show(&mut self, ctx: &egui::Context, client: &Client) {
        if !self.open {
            return;
        }
        if self.loaded.is_none() && self.load.is_none() && self.error.is_none() {
            let c = client.clone();
            self.load = Some(Task::spawn(ctx, move || c.config()));
        }
        self.poll(ctx, client);

        let mut open = self.open;
        egui::Window::new("SMTP Virtual Server Properties")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size([600.0, 520.0])
            .show(ctx, |ui| self.contents(ui, ctx, client));
        if !open {
            self.close();
        }
    }

    fn close(&mut self) {
        *self = Self::default();
    }

    fn poll(&mut self, ctx: &egui::Context, client: &Client) {
        if let Some(res) = poll(&mut self.load) {
            match res.map_err(|e| perm_hint(&e)).and_then(|f| ConfigDoc::from_file(&f)) {
                Ok(doc) => {
                    self.loaded = Some(Loaded::new(doc));
                    self.error = None;
                }
                Err(e) => self.error = Some(e),
            }
        }
        if let Some(res) = poll(&mut self.save) {
            match res {
                Ok(r) => {
                    self.validation = None;
                    self.notice = Some(match (&r.reload_error, r.warnings.is_empty()) {
                        (Some(e), _) => format!("Saved, but the service could not reload: {e}"),
                        (None, false) => format!("Applied. {}", r.warnings.join(" ")),
                        (None, true) => "Applied.".into(),
                    });
                    if self.close_after_save && r.reload_error.is_none() && r.warnings.is_empty() {
                        self.close();
                        return;
                    }
                    // Re-read so the next Apply starts from the saved file.
                    let c = client.clone();
                    self.loaded = None;
                    self.load = Some(Task::spawn(ctx, move || c.config()));
                }
                Err(e) => {
                    self.validation = e.body.clone().and_then(|b| serde_json::from_value(b).ok());
                    self.error = Some(if e.status == Some(409) {
                        "The configuration was changed elsewhere. Close this window and open Properties again.".into()
                    } else {
                        e.message
                    });
                }
            }
            self.close_after_save = false;
        }
    }

    fn contents(&mut self, ui: &mut Ui, ctx: &egui::Context, client: &Client) {
        ui.horizontal(|ui| {
            for t in Tab::ALL {
                ui.selectable_value(&mut self.tab, t, t.label());
            }
        });
        ui.separator();

        let footer_h = 64.0;
        let body_h = ui.available_height() - footer_h;
        egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false, false]).show(ui, |ui| {
            match &mut self.loaded {
                None if self.error.is_none() => {
                    ui.spinner();
                }
                None => {}
                Some(l) => {
                    if self.tab == Tab::General {
                        listeners_ui(ui, &mut l.listeners);
                    }
                    form(ui, self.tab.rows(), &mut l.bufs);
                    if self.tab == Tab::Access {
                        users_ui(ui, &mut l.users, &mut self.new_user);
                    }
                }
            }
        });

        ui.separator();
        if let Some(e) = &self.error {
            widgets::error_label(ui, e);
        }
        if let Some(v) = &self.validation {
            for e in &v.errors {
                widgets::error_label(ui, &e.message);
            }
        }
        if let Some(n) = &self.notice {
            ui.label(RichText::new(n).color(AMBER));
        }
        let dirty = self.loaded.as_ref().is_some_and(Loaded::dirty);
        let busy = self.save.is_some();
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let mut apply = false;
            if ui.add_enabled(dirty && !busy, egui::Button::new("Apply")).clicked() {
                apply = true;
            }
            if ui.button("Cancel").clicked() {
                self.close();
                return;
            }
            if ui.add_enabled(!busy, egui::Button::new("  OK  ")).clicked() {
                if dirty {
                    apply = true;
                    self.close_after_save = true;
                } else {
                    self.close();
                    return;
                }
            }
            if busy {
                ui.spinner();
            }
            if apply {
                self.start_save(ctx, client);
            }
        });
    }

    fn start_save(&mut self, ctx: &egui::Context, client: &Client) {
        let Some(l) = &self.loaded else { return };
        match l.build() {
            Ok(text) => {
                self.error = None;
                self.notice = None;
                let (c, sha) = (client.clone(), l.doc.sha256.clone());
                self.save = Some(Task::spawn(ctx, move || c.save_config(&text, &sha)));
            }
            Err(e) => {
                self.error = Some(e);
                self.close_after_save = false;
            }
        }
    }
}

fn perm_hint(e: &ApiError) -> String {
    if e.status == Some(403) {
        format!("{e} — changing properties needs an API key with the 'admin' permission.")
    } else {
        e.message.clone()
    }
}

fn form(ui: &mut Ui, rows: &[Row], bufs: &mut HashMap<&'static str, Buf>) {
    egui::Grid::new(ui.next_auto_id()).num_columns(2).spacing([12.0, 6.0]).min_col_width(240.0).show(ui, |ui| {
        for row in rows {
            match row {
                Row::Group(g) => {
                    ui.end_row();
                    ui.label(RichText::new(*g).strong());
                    ui.end_row();
                }
                Row::Note(n) => {
                    ui.label("");
                    ui.label(RichText::new(*n).small().color(GREY));
                    ui.end_row();
                }
                Row::F(f) => {
                    let Some(b) = bufs.get_mut(f.path) else { continue };
                    if f.kind == Kind::Bool {
                        ui.label("");
                        ui.checkbox(&mut b.flag, f.label);
                        ui.end_row();
                        continue;
                    }
                    ui.label(f.label);
                    match f.kind {
                        Kind::Choice(opts) => {
                            let current = opts
                                .iter()
                                .find(|(v, _)| *v == b.text)
                                .map(|(_, l)| *l)
                                .unwrap_or(b.text.as_str())
                                .to_string();
                            egui::ComboBox::from_id_salt(f.path).selected_text(current).width(260.0).show_ui(
                                ui,
                                |ui| {
                                    for (v, l) in opts {
                                        ui.selectable_value(&mut b.text, v.to_string(), *l);
                                    }
                                },
                            );
                        }
                        Kind::Lines => {
                            ui.add(egui::TextEdit::multiline(&mut b.text).desired_rows(3).desired_width(260.0));
                        }
                        Kind::Int => {
                            let bad = !b.text.trim().is_empty() && b.text.trim().parse::<i64>().is_err();
                            let te = egui::TextEdit::singleline(&mut b.text).desired_width(120.0);
                            ui.add(if bad { te.text_color(RED) } else { te });
                        }
                        Kind::Password => {
                            ui.add(egui::TextEdit::singleline(&mut b.text).password(true).desired_width(260.0));
                        }
                        Kind::Size | Kind::Duration => {
                            ui.add(egui::TextEdit::singleline(&mut b.text).desired_width(120.0));
                        }
                        _ => {
                            ui.add(egui::TextEdit::singleline(&mut b.text).desired_width(260.0));
                        }
                    }
                    ui.end_row();
                }
            }
        }
    });
}

const LISTENER_TLS: &[(&str, &str)] = &[("none", "None"), ("starttls", "STARTTLS"), ("implicit", "TLS (465)")];

fn listeners_ui(ui: &mut Ui, rows: &mut Vec<ListenerRow>) {
    ui.label(RichText::new("IP addresses and ports").strong());
    let mut remove = None;
    egui::Grid::new("listeners").num_columns(6).striped(true).spacing([8.0, 4.0]).show(ui, |ui| {
        for h in ["Name", "IP address:port", "Encryption", "Require auth", "Require TLS", ""] {
            ui.label(RichText::new(h).small().color(GREY));
        }
        ui.end_row();
        for (i, r) in rows.iter_mut().enumerate() {
            ui.add(egui::TextEdit::singleline(&mut r.name).desired_width(70.0));
            ui.add(egui::TextEdit::singleline(&mut r.bind).desired_width(140.0));
            egui::ComboBox::from_id_salt(("ltls", i))
                .selected_text(LISTENER_TLS.iter().find(|(v, _)| *v == r.tls).map(|(_, l)| *l).unwrap_or(&r.tls))
                .width(90.0)
                .show_ui(ui, |ui| {
                    for (v, l) in LISTENER_TLS {
                        ui.selectable_value(&mut r.tls, v.to_string(), *l);
                    }
                });
            ui.checkbox(&mut r.require_auth, "");
            ui.checkbox(&mut r.require_tls, "");
            if ui.small_button("Remove").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        rows.remove(i);
    }
    if ui.small_button("Add…").clicked() {
        rows.push(ListenerRow {
            orig: None,
            name: format!("smtp{}", rows.len() + 1),
            bind: "0.0.0.0:587".into(),
            tls: "starttls".into(),
            require_auth: true,
            require_tls: false,
            allow_plaintext_auth: false,
        });
    }
    ui.add_space(4.0);
}

fn users_ui(ui: &mut Ui, rows: &mut Vec<UserRow>, new: &mut NewUser) {
    ui.add_space(8.0);
    ui.label(RichText::new("Authentication — SMTP users").strong());
    ui.label(RichText::new("Accounts that may log in with SMTP AUTH (Basic authentication).").small().color(GREY));
    let mut remove = None;
    egui::Grid::new("users").num_columns(3).striped(true).spacing([8.0, 4.0]).show(ui, |ui| {
        for (i, r) in rows.iter_mut().enumerate() {
            ui.label(&r.username);
            ui.checkbox(&mut r.disabled, "Disabled");
            ui.horizontal(|ui| {
                if r.new_hash.is_some() {
                    ui.label(RichText::new("new password").small().color(AMBER));
                }
                if ui.small_button("Remove").clicked() {
                    remove = Some(i);
                }
            });
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        rows.remove(i);
    }
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut new.username).hint_text("user name").desired_width(120.0));
        ui.add(egui::TextEdit::singleline(&mut new.password).password(true).hint_text("password").desired_width(110.0));
        ui.add(egui::TextEdit::singleline(&mut new.confirm).password(true).hint_text("confirm").desired_width(110.0));
        if ui.button("Add / Set password").clicked() {
            new.error = add_user(rows, new).err();
        }
    });
    if let Some(e) = &new.error {
        widgets::error_label(ui, e);
    }
}

/// Add a user, or set a new password for an existing one. The password is
/// hashed here (Argon2, same parameters as the server) and never sent in clear.
fn add_user(rows: &mut Vec<UserRow>, new: &mut NewUser) -> Result<(), String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let name = new.username.trim().to_string();
    if name.is_empty() {
        return Err("enter a user name".into());
    }
    if new.password.chars().count() < 8 {
        return Err("use a password of at least 8 characters".into());
    }
    if new.password != new.confirm {
        return Err("the passwords do not match".into());
    }
    let hash = argon2::Argon2::default()
        .hash_password(new.password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| format!("hashing failed: {e}"))?
        .to_string();
    match rows.iter_mut().find(|r| r.username.eq_ignore_ascii_case(&name)) {
        Some(r) => r.new_hash = Some(hash),
        None => rows.push(UserRow { orig: None, username: name, new_hash: Some(hash), disabled: false }),
    }
    *new = NewUser::default();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(text: &str, effective: serde_json::Value) -> Loaded {
        Loaded::new(ConfigDoc { doc: text.parse().unwrap(), effective, sha256: String::new(), path: String::new() })
    }

    #[test]
    fn only_changed_fields_are_written() {
        let text = "# keep\n[limits]\nmax_message_size = \"25MB\" # IIS default was 2MB\n";
        let mut l =
            loaded(text, serde_json::json!({"limits": {"max_message_size": 26214400, "max_connections": 1000}}));
        assert_eq!(l.build().unwrap(), text, "no edits, no changes");
        l.bufs.get_mut("limits.max_message_size").unwrap().text = "10MB".into();
        let out = l.build().unwrap();
        assert!(out.contains("max_message_size = \"10MB\" # IIS default was 2MB"));
        assert!(!out.contains("max_connections"), "untouched defaults stay out of the file");
    }

    #[test]
    fn removing_a_user_does_not_shift_settings() {
        let text = "[[user]]\nusername = \"a\"\npassword_hash = \"$argon2id$a\"\nallowed_ips = [\"10.0.0.1/32\"]\n\n[[user]]\nusername = \"b\"\npassword_hash = \"$argon2id$b\"\n";
        let mut l = loaded(
            text,
            serde_json::json!({"user": [{"username": "a", "disabled": false}, {"username": "b", "disabled": false}]}),
        );
        l.users.remove(0);
        let out = l.build().unwrap();
        let cfg: toml::Table = toml::from_str(&out).unwrap();
        let users = cfg["user"].as_array().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["username"].as_str(), Some("b"));
        assert!(users[0].get("allowed_ips").is_none(), "a's IP restriction must not move to b");
    }

    #[test]
    fn empty_smart_host_removes_it() {
        let text = "[delivery]\nsmarthost = { host = \"relay.example.com\", port = 587 }\n";
        let mut l =
            loaded(text, serde_json::json!({"delivery": {"smarthost": {"host": "relay.example.com", "port": 587}}}));
        l.bufs.get_mut("delivery.smarthost.host").unwrap().text.clear();
        assert_eq!(l.build().unwrap(), "[delivery]\n");
    }

    #[test]
    fn bad_numbers_are_reported() {
        let mut l = loaded("", serde_json::json!({"limits": {"max_connections": 1000}}));
        l.bufs.get_mut("limits.max_connections").unwrap().text = "lots".into();
        assert!(l.build().unwrap_err().contains("whole number"));
    }
}
