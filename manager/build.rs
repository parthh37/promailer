//! Windows resources for promailer-manager.exe: icon (Explorer, desktop and
//! Start menu shortcuts) and version info.

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
        + &winres::version_info("Promailer Manager", "promailer-manager.exe");
    let rc = out.join("manager.rc");
    std::fs::write(&rc, script).expect("writing resource script");
    embed_resource::compile(&rc, embed_resource::NONE).manifest_optional().expect("compiling Windows resources");
}
