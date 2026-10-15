//! Windows resources for promailer-tray.exe: icon, version info and a manifest
//! (per-monitor DPI awareness for a crisp status icon, themed menus).

use std::path::Path;

#[path = "../assets/icon.rs"]
mod icon;
#[path = "../assets/winres.rs"]
mod winres;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../assets");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let out = Path::new(&out);
    let script = winres::icon_line(out, &icon::ico(&winres::ICO_SIZES))
        + &winres::manifest_line(out)
        + &winres::version_info("Promailer status icon", "promailer-tray.exe");
    let rc = out.join("tray.rc");
    std::fs::write(&rc, script).expect("writing resource script");
    embed_resource::compile(&rc, embed_resource::NONE).manifest_optional().expect("compiling Windows resources");
}
