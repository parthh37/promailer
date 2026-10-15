//! Windows resource scripts shared by the build scripts of every executable:
//! the application icon (Explorer, shortcuts, taskbar) and version info.
//!
//! Used by source path from each `build.rs`, next to `icon.rs`.
#![allow(dead_code)]

use std::path::Path;

/// Icon sizes in the embedded `.ico` (16-48 for shell views, larger for tiles).
pub const ICO_SIZES: [u32; 7] = [16, 20, 24, 32, 40, 48, 64];

fn rc_path(p: &Path) -> String {
    p.display().to_string().replace('\\', "\\\\")
}

/// Write `app.ico` into `out` and return the resource line for it. ID 1 is
/// the lowest icon ID, which Explorer uses as the executable's icon.
pub fn icon_line(out: &Path, ico: &[u8]) -> String {
    let path = out.join("app.ico");
    std::fs::write(&path, ico).expect("writing app.ico");
    format!("1 ICON \"{}\"\n", rc_path(&path))
}

/// A manifest resource (RT_MANIFEST = 24) for per-monitor DPI awareness and
/// themed (Common Controls 6) menus and dialogs.
pub fn manifest_line(out: &Path) -> String {
    let path = out.join("app.manifest");
    std::fs::write(&path, MANIFEST).expect("writing app.manifest");
    format!("1 24 \"{}\"\n", rc_path(&path))
}

/// VERSIONINFO block with the workspace version.
pub fn version_info(description: &str, file_name: &str) -> String {
    let v = |k: &str| std::env::var(k).unwrap_or_default();
    let (major, minor, patch) =
        (v("CARGO_PKG_VERSION_MAJOR"), v("CARGO_PKG_VERSION_MINOR"), v("CARGO_PKG_VERSION_PATCH"));
    let version = v("CARGO_PKG_VERSION");
    let internal = file_name.trim_end_matches(".exe");
    format!(
        r#"
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
      VALUE "FileDescription", "{description}"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "{internal}"
      VALUE "OriginalFilename", "{file_name}"
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

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
                        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;
