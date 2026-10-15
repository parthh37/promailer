//! Promailer Manager - native desktop GUI for the Promailer SMTP server.
//!
//! Talks to the service over its HTTP management API, so it can manage the
//! local server or a remote one, and never shares a process with the mail flow.

// No console window on Windows.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod client;
mod confdoc;
#[path = "../../assets/icon.rs"]
mod icon;
mod pages;
mod settings;
mod task;
mod widgets;

fn options(renderer: eframe::Renderer) -> eframe::NativeOptions {
    eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_title("Promailer Manager")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 560.0])
            .with_icon(std::sync::Arc::new(egui::IconData { rgba: icon::rgba(64, None), width: 64, height: 64 })),
        centered: true,
        ..Default::default()
    }
}

fn main() -> eframe::Result {
    // Crashes are reviewed and reported from Help > Crash Reports on the next start.
    if let Some(dir) = promailer_crash::user_dir() {
        promailer_crash::install("promailer-manager", dir);
    }
    let force_gl = std::env::args().any(|a| a == "--opengl");
    let start =
        |r| eframe::run_native("Promailer Manager", options(r), Box::new(|cc| Ok(Box::new(app::ManagerApp::new(cc)))));
    if force_gl {
        return start(eframe::Renderer::Glow);
    }
    // wgpu covers GPU-less servers via DX12 WARP; OpenGL is the last resort.
    start(eframe::Renderer::Wgpu).or_else(|e| {
        eprintln!("wgpu renderer failed ({e}); falling back to OpenGL");
        start(eframe::Renderer::Glow)
    })
}
