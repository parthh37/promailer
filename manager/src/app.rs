//! Application shell, laid out like the IIS 6 SMTP manager (an MMC snap-in):
//! menu bar, toolbar, console tree on the left, details pane on the right,
//! status bar at the bottom, and a property sheet for the virtual server.

use crate::client::{ApiResult, Client, Health, Stats};
use crate::pages::{
    config::ConfigEditor,
    dashboard::Dashboard,
    dkim::DkimPage,
    dns::DnsCheck,
    domains::DomainsPage,
    live_log::LiveLog,
    properties::Properties,
    queue::QueueBrowser,
    search::{Search, SearchAction},
};
use crate::settings::Settings;
use crate::task::{poll, Task};
use crate::widgets::{self, GREEN, GREY, RED};
use egui::{RichText, Ui};
use std::time::{Duration, Instant};

const HEALTH_EVERY: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    Status,
    Queue,
    Search,
    Log,
    Domains,
    Dkim,
    Dns,
    ConfigFile,
}

impl Node {
    const ALL: [Node; 8] =
        [Node::Status, Node::Queue, Node::Search, Node::Log, Node::Domains, Node::Dkim, Node::Dns, Node::ConfigFile];
    fn label(self) -> &'static str {
        match self {
            Node::Status => "Status",
            Node::Queue => "Queue",
            Node::Search => "Message Search",
            Node::Log => "Delivery Log",
            Node::Domains => "Domains",
            Node::Dkim => "DKIM Keys",
            Node::Dns => "DNS Check",
            Node::ConfigFile => "Configuration File",
        }
    }
}

/// Everything tied to one server connection; rebuilt on reconnect.
#[derive(Default)]
struct Pages {
    status: Dashboard,
    queue: QueueBrowser,
    search: Search,
    log: LiveLog,
    domains: DomainsPage,
    dkim: DkimPage,
    dns: DnsCheck,
    config: ConfigEditor,
    properties: Properties,
}

struct ConnectForm {
    url: String,
    key: String,
    remember: bool,
    test: Option<Task<(ApiResult<Health>, ApiResult<Stats>)>>,
    result: Option<Result<String, String>>,
}

pub struct ManagerApp {
    settings: Settings,
    client: Client,
    node: Node,
    pages: Pages,
    health: Option<Result<Health, String>>,
    health_task: Option<Task<ApiResult<Health>>>,
    last_health: Option<Instant>,
    connect: Option<ConnectForm>,
    about: bool,
}

/// A plain, light look closer to classic Windows administration tools.
fn classic_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Light);
    ctx.style_mut_of(egui::Theme::Light, |s| {
        s.spacing.item_spacing = egui::vec2(6.0, 4.0);
        s.spacing.button_padding = egui::vec2(8.0, 3.0);
        s.visuals.window_corner_radius = egui::CornerRadius::same(2);
        s.visuals.menu_corner_radius = egui::CornerRadius::same(2);
        for w in [
            &mut s.visuals.widgets.noninteractive,
            &mut s.visuals.widgets.inactive,
            &mut s.visuals.widgets.hovered,
            &mut s.visuals.widgets.active,
            &mut s.visuals.widgets.open,
        ] {
            w.corner_radius = egui::CornerRadius::same(2);
        }
        s.visuals.panel_fill = egui::Color32::from_rgb(0xf3, 0xf3, 0xf3);
        s.visuals.window_fill = egui::Color32::from_rgb(0xf0, 0xf0, 0xf0);
        s.visuals.extreme_bg_color = egui::Color32::WHITE;
        s.visuals.selection.bg_fill = egui::Color32::from_rgb(0x33, 0x99, 0xff);
        s.visuals.selection.stroke.color = egui::Color32::WHITE;
    });
}

impl ManagerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        classic_style(&cc.egui_ctx);
        let settings = Settings::load();
        let client = Client::new(&settings.url, &settings.api_key);
        let mut app = Self {
            client,
            node: Node::Status,
            pages: Pages::default(),
            health: None,
            health_task: None,
            last_health: None,
            connect: None,
            about: false,
            settings,
        };
        app.pages.dns.domain = app.settings.last_check_domain.clone();
        if app.settings.api_key.is_empty() {
            app.open_connect();
        }
        app
    }

    fn open_connect(&mut self) {
        self.connect = Some(ConnectForm {
            url: self.settings.url.clone(),
            key: self.settings.api_key.clone(),
            remember: self.settings.remember_key,
            test: None,
            result: None,
        });
    }

    fn connected(&self) -> bool {
        !self.settings.api_key.is_empty()
    }

    fn apply_connection(&mut self, url: String, key: String, remember: bool) {
        self.settings.url = url;
        self.settings.api_key = key;
        self.settings.remember_key = remember;
        let _ = self.settings.save();
        self.client = Client::new(&self.settings.url, &self.settings.api_key);
        let domain = std::mem::take(&mut self.pages.dns.domain);
        self.pages = Pages::default();
        self.pages.dns.domain = domain;
        self.health = None;
        self.last_health = None;
    }

    fn background(&mut self, ctx: &egui::Context) {
        if let Some(res) = poll(&mut self.health_task) {
            self.health = Some(res.map_err(|e| e.message));
        }
        if self.health_task.is_none() && self.last_health.is_none_or(|t| t.elapsed() >= HEALTH_EVERY) {
            self.last_health = Some(Instant::now());
            let c = self.client.clone();
            self.health_task = Some(Task::spawn(ctx, move || c.health()));
        }
        if self.connected() {
            // Keep collecting while other nodes are shown.
            self.pages.status.tick(ctx, &self.client);
            self.pages.log.tick(ctx, &self.client);
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn server_label(&self) -> String {
        match &self.health {
            Some(Ok(h)) if !h.hostname.is_empty() => h.hostname.clone(),
            _ => self.client.base().trim_start_matches("http://").trim_start_matches("https://").to_string(),
        }
    }

    fn menu_bar(&mut self, ui: &mut Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("Action", |ui| {
                if ui.add_enabled(self.connected(), egui::Button::new("Properties")).clicked() {
                    self.pages.properties.open = true;
                }
                if ui.button("Connect to Server…").clicked() {
                    self.open_connect();
                }
                ui.separator();
                if ui.button("Exit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("View", |ui| {
                for n in Node::ALL {
                    if ui.button(n.label()).clicked() {
                        self.node = n;
                    }
                }
                ui.separator();
                let dark = ui.visuals().dark_mode;
                if ui.button(if dark { "Light theme" } else { "Dark theme" }).clicked() {
                    ui.ctx().set_theme(if dark { egui::Theme::Light } else { egui::Theme::Dark });
                }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("About Promailer Manager").clicked() {
                    self.about = true;
                }
            });
        });
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.add_enabled(self.connected(), egui::Button::new("Properties")).clicked() {
                self.pages.properties.open = true;
            }
            if ui.button("Connect…").clicked() {
                self.open_connect();
            }
        });
    }

    fn tree(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        egui::CollapsingHeader::new("Promailer").default_open(true).show(ui, |ui| {
            egui::CollapsingHeader::new(self.server_label()).id_salt("server_node").default_open(true).show(ui, |ui| {
                let vs = ui.selectable_label(false, "SMTP Virtual Server").on_hover_text("Double-click for Properties");
                if vs.double_clicked() {
                    self.pages.properties.open = true;
                }
                ui.indent("vs_children", |ui| {
                    for n in Node::ALL {
                        if ui.selectable_label(self.node == n, n.label()).clicked() {
                            self.node = n;
                        }
                    }
                });
            });
        });
    }

    fn status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let (dot, text) = match &self.health {
                None => (GREY, format!("Connecting to {}…", self.client.base())),
                Some(Ok(h)) if h.status == "ok" => {
                    (GREEN, format!("Connected to {} · Promailer {}", self.client.base(), h.version))
                }
                Some(Ok(h)) => (RED, format!("{} · {}", self.client.base(), h.status)),
                Some(Err(e)) => (RED, format!("{} · {e}", self.client.base())),
            };
            ui.label(RichText::new("●").color(dot));
            ui.label(RichText::new(text).small());
        });
    }

    fn connect_dialog(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.connect else { return };
        if let Some((h, s)) = poll(&mut form.test) {
            form.result = Some(match (h, s) {
                (Err(e), _) => Err(e.message),
                (Ok(_), Err(e)) => Err(e.message),
                (Ok(h), Ok(s)) => {
                    Ok(format!("Connected to Promailer {} · {} message(s) queued", h.version, s.queue_size))
                }
            });
        }
        let mut apply = false;
        let mut close = false;
        egui::Modal::new(egui::Id::new("connect")).show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading("Connect to Server");
            ui.add_space(6.0);
            egui::Grid::new("connect_grid").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                ui.label("Server URL");
                ui.add(egui::TextEdit::singleline(&mut form.url).desired_width(320.0));
                ui.end_row();
                ui.label("API key");
                ui.add(egui::TextEdit::singleline(&mut form.key).password(true).desired_width(320.0));
                ui.end_row();
                ui.label("");
                ui.checkbox(&mut form.remember, "Remember API key on this computer");
                ui.end_row();
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Create a key on the server with:  promailer api-key generate --name manager\n\
                     then add the printed [[api.keys]] entry to promailer.toml with\n\
                     permissions = [\"admin\"] and run:  promailer service reload",
                )
                .small()
                .color(GREY),
            );
            ui.add_space(6.0);
            match &form.result {
                Some(Ok(m)) => {
                    ui.label(RichText::new(m).color(GREEN));
                }
                Some(Err(m)) => widgets::error_label(ui, m),
                None => {}
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let ready = !form.url.trim().is_empty() && !form.key.trim().is_empty();
                if ui.add_enabled(ready, egui::Button::new("  OK  ")).clicked() {
                    apply = true;
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
                if ui.add_enabled(ready && form.test.is_none(), egui::Button::new("Test")).clicked() {
                    let c = Client::new(&form.url, &form.key);
                    form.result = None;
                    form.test = Some(Task::spawn(ctx, move || (c.health(), c.stats())));
                }
                if form.test.is_some() {
                    ui.spinner();
                }
            });
        });
        if apply {
            let (url, key, remember) = (form.url.trim().to_string(), form.key.trim().to_string(), form.remember);
            self.connect = None;
            self.apply_connection(url, key, remember);
        } else if close {
            self.connect = None;
        }
    }

    fn about_dialog(&mut self, ctx: &egui::Context) {
        if !self.about {
            return;
        }
        egui::Modal::new(egui::Id::new("about")).show(ctx, |ui| {
            ui.heading("Promailer Manager");
            ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
            ui.label(RichText::new("Outbound SMTP server for Windows.").color(GREY));
            ui.hyperlink("https://github.com/parthh37/promailer");
            if ui.button("  OK  ").clicked() {
                self.about = false;
            }
        });
    }
}

impl eframe::App for ManagerApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.background(&ctx);

        egui::Panel::top("menu").show(ui, |ui| self.menu_bar(ui));
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(2.0);
            self.toolbar(ui);
            ui.add_space(2.0);
        });
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("tree").resizable(true).default_size(220.0).min_size(170.0).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.tree(ui));
        });
        egui::CentralPanel::default().show(ui, |ui| {
            if !self.connected() {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label("Not connected to a Promailer server.");
                    if ui.button("Connect…").clicked() {
                        self.open_connect();
                    }
                });
                return;
            }
            ui.label(RichText::new(self.node.label()).strong().size(15.0));
            ui.separator();
            let client = self.client.clone();
            match self.node {
                Node::Status => self.pages.status.ui(ui),
                Node::Queue => self.pages.queue.ui(ui, &client),
                Node::Search => {
                    if let Some(SearchAction::OpenInQueue(id)) = self.pages.search.ui(ui, &client) {
                        self.pages.queue.open(&id);
                        self.node = Node::Queue;
                    }
                }
                Node::Log => {
                    self.pages.log.ui(ui);
                    if let Some(id) = self.pages.log.open_request.take() {
                        self.pages.search.open_timeline(&ctx, &client, &id);
                        self.node = Node::Search;
                    }
                }
                Node::Domains => self.pages.domains.ui(ui, &client),
                Node::Dkim => self.pages.dkim.ui(ui, &client),
                Node::Dns => {
                    if self.pages.dns.ui(ui, &client) && self.settings.last_check_domain != self.pages.dns.domain {
                        self.settings.last_check_domain = self.pages.dns.domain.trim().to_string();
                        let _ = self.settings.save();
                    }
                }
                Node::ConfigFile => self.pages.config.ui(ui, &client),
            }
        });
        if self.connected() {
            let client = self.client.clone();
            self.pages.properties.show(&ctx, &client);
        }
        self.connect_dialog(&ctx);
        self.about_dialog(&ctx);
    }
}
