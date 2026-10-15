//! Windows resources embedded in promailer.exe:
//!
//! * a message table, so Event Viewer renders Promailer's Application-log entries
//!   instead of "The description for Event ID ... cannot be found";
//! * version info (file properties, MSI file versioning);
//! * the application icon (Apps & features, Explorer).

use std::path::Path;

#[path = "assets/icon.rs"]
mod icon;
#[path = "assets/winres.rs"]
mod winres;

/// Event IDs covered by the message table; must include every ID in `src/eventlog.rs`.
const FIRST_EVENT_ID: u32 = 1000;
const LAST_EVENT_ID: u32 = 1199;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let out = Path::new(&out);
    let messages = out.join("messages.bin");
    std::fs::write(&messages, message_table()).expect("writing message table");
    let rc = out.join("promailer.rc");
    let script = resource_script(&messages) + &winres::icon_line(out, &icon::ico(&winres::ICO_SIZES));
    std::fs::write(&rc, script).expect("writing resource script");
    embed_resource::compile(&rc, embed_resource::NONE).manifest_optional().expect("compiling Windows resources");
}

/// Binary MESSAGE_RESOURCE_DATA (what mc.exe produces): one block in which every ID's
/// text is just "%1", i.e. the message is the event's own insertion string.
fn message_table() -> Vec<u8> {
    const MESSAGE_RESOURCE_UNICODE: u16 = 1;
    let text: Vec<u16> = "%1\r\n\0".encode_utf16().collect();
    let len = (4 + text.len() * 2 + 3) & !3; // header + text, DWORD aligned
    let mut entry = Vec::with_capacity(len);
    entry.extend((len as u16).to_le_bytes());
    entry.extend(MESSAGE_RESOURCE_UNICODE.to_le_bytes());
    entry.extend(text.iter().flat_map(|c| c.to_le_bytes()));
    entry.resize(len, 0);

    let mut data = Vec::new();
    data.extend(1u32.to_le_bytes()); // NumberOfBlocks
    data.extend(FIRST_EVENT_ID.to_le_bytes());
    data.extend(LAST_EVENT_ID.to_le_bytes());
    data.extend(16u32.to_le_bytes()); // OffsetToEntries: 4-byte count + one 12-byte block
    for _ in FIRST_EVENT_ID..=LAST_EVENT_ID {
        data.extend(&entry);
    }
    data
}

fn resource_script(messages: &Path) -> String {
    let messages = messages.display().to_string().replace('\\', "\\\\");
    // Type 11 is RT_MESSAGETABLE; the numeric form works with both rc.exe and llvm-rc.
    format!("1 11 \"{messages}\"\n") + &winres::version_info("Promailer SMTP Server", "promailer.exe")
}
