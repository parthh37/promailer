//! Windows resources embedded in promailer.exe:
//!
//! * a message table, so Event Viewer renders Promailer's Application-log entries
//!   instead of "The description for Event ID ... cannot be found";
//! * version info (file properties, MSI file versioning).

use std::path::Path;

/// Event IDs covered by the message table; must include every ID in `src/eventlog.rs`.
const FIRST_EVENT_ID: u32 = 1000;
const LAST_EVENT_ID: u32 = 1199;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let out = Path::new(&out);
    let messages = out.join("messages.bin");
    std::fs::write(&messages, message_table()).expect("writing message table");
    let rc = out.join("promailer.rc");
    std::fs::write(&rc, resource_script(&messages)).expect("writing resource script");
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
    let v = |k: &str| std::env::var(k).unwrap_or_default();
    let (major, minor, patch) =
        (v("CARGO_PKG_VERSION_MAJOR"), v("CARGO_PKG_VERSION_MINOR"), v("CARGO_PKG_VERSION_PATCH"));
    let version = v("CARGO_PKG_VERSION");
    let messages = messages.display().to_string().replace('\\', "\\\\");
    // Type 11 is RT_MESSAGETABLE; the numeric form works with both rc.exe and llvm-rc.
    format!(
        r#"1 11 "{messages}"

1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Promailer"
      VALUE "FileDescription", "Promailer SMTP Server"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "promailer"
      VALUE "OriginalFilename", "promailer.exe"
      VALUE "ProductName", "Promailer"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#
    )
}
