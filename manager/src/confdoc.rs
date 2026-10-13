//! Form-based configuration editing.
//!
//! The server returns the config file text plus its *effective* settings
//! (defaults filled in, as JSON). Forms display effective values and write
//! only the keys the administrator changed into a `toml_edit` document, so
//! comments and layout in `promailer.toml` survive. The resulting text is
//! saved through the normal validate → backup → reload endpoint.

use crate::client::ConfigFile;
use serde_json::Value;
use toml_edit::{DocumentMut, Item, Table, TableLike};

pub struct ConfigDoc {
    pub doc: DocumentMut,
    pub effective: Value,
    pub sha256: String,
    pub path: String,
}

impl ConfigDoc {
    pub fn from_file(f: &ConfigFile) -> Result<Self, String> {
        let doc = f.text.parse::<DocumentMut>().map_err(|e| format!("configuration file has a syntax error: {e}"))?;
        let effective = f
            .effective
            .clone()
            .ok_or("the configuration file on the server is currently invalid; fix it in Configuration File first")?;
        Ok(Self { doc, effective, sha256: f.sha256.clone(), path: f.path.clone() })
    }

    pub fn text(&self) -> String {
        self.doc.to_string()
    }

    /// Effective value at a dotted path (`limits.max_message_size`); Null if absent.
    pub fn get(&self, path: &str) -> &Value {
        path.split('.').try_fold(&self.effective, |v, k| v.get(k)).unwrap_or(&Value::Null)
    }

    /// Set `path` to `value`, creating parent tables as needed and keeping any
    /// comment attached to an existing value.
    pub fn set(&mut self, path: &str, mut value: toml_edit::Value) -> Result<(), String> {
        let (parents, key) = split(path);
        let table = parent_table(&mut self.doc, &parents)?;
        if let Some(old) = table.get(key).and_then(Item::as_value) {
            *value.decor_mut() = old.decor().clone();
        }
        table.insert(key, Item::Value(value));
        Ok(())
    }

    pub fn remove(&mut self, path: &str) {
        let (parents, key) = split(path);
        let mut cur: &mut dyn TableLike = self.doc.as_table_mut();
        for p in parents {
            match cur.get_mut(p).and_then(Item::as_table_like_mut) {
                Some(t) => cur = t,
                None => return,
            }
        }
        cur.remove(key);
    }

    /// Mutable access to an array of tables such as `[[listener]]`, created if missing.
    pub fn tables_mut(&mut self, name: &str) -> Result<&mut toml_edit::ArrayOfTables, String> {
        self.doc
            .entry(name)
            .or_insert(Item::ArrayOfTables(Default::default()))
            .as_array_of_tables_mut()
            .ok_or_else(|| format!("'{name}' is written in an unusual form; edit it in Configuration File"))
    }
}

fn split(path: &str) -> (Vec<&str>, &str) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let key = parts.pop().unwrap_or(path);
    (parts, key)
}

fn parent_table<'a>(doc: &'a mut DocumentMut, parents: &[&str]) -> Result<&'a mut dyn TableLike, String> {
    let mut cur: &mut dyn TableLike = doc.as_table_mut();
    for p in parents {
        if cur.get(p).is_none() {
            cur.insert(p, Item::Table(Table::new()));
        }
        cur = cur.get_mut(p).and_then(Item::as_table_like_mut).ok_or_else(|| format!("'{p}' is not a table"))?;
    }
    Ok(cur)
}

/// Set or remove a field inside one table of an array of tables.
pub fn set_in(table: &mut Table, key: &str, value: Option<toml_edit::Value>) {
    match value {
        Some(mut v) => {
            if let Some(old) = table.get(key).and_then(Item::as_value) {
                *v.decor_mut() = old.decor().clone();
            }
            table.insert(key, Item::Value(v));
        }
        None => {
            table.remove(key);
        }
    }
}

pub fn str_array<'a>(items: impl IntoIterator<Item = &'a str>) -> toml_edit::Value {
    toml_edit::Value::Array(items.into_iter().collect())
}

/// Effective JSON value as editable text.
pub fn display(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(display).collect::<Vec<_>>().join("\n"),
        other => other.to_string(),
    }
}

/// Bytes as the shortest exact size string ("25MB", "512KB", "1000").
pub fn size_text(v: &Value) -> String {
    let Some(n) = v.as_u64() else { return display(v) };
    const UNITS: [(u64, &str); 3] = [(1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "KB")];
    UNITS.iter().find(|(m, _)| n >= *m && n % m == 0).map(|(m, u)| format!("{}{u}", n / m)).unwrap_or(n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> ConfigDoc {
        ConfigDoc {
            doc: text.parse().unwrap(),
            effective: serde_json::json!({"limits": {"max_message_size": 26214400}}),
            sha256: String::new(),
            path: String::new(),
        }
    }

    #[test]
    fn set_preserves_comments_and_creates_tables() {
        let mut d = doc("# header\n[server]\nhostname = \"old\" # the FQDN\n");
        d.set("server.hostname", "mx.example.com".into()).unwrap();
        d.set("limits.max_message_size", "10MB".into()).unwrap();
        let t = d.text();
        assert!(t.contains("# header"));
        assert!(t.contains("hostname = \"mx.example.com\" # the FQDN"));
        assert!(t.contains("[limits]\nmax_message_size = \"10MB\""));
    }

    #[test]
    fn remove_nested_and_missing() {
        let mut d = doc("[delivery]\nsmarthost = { host = \"relay\", port = 25 }\n");
        d.remove("delivery.smarthost");
        d.remove("nope.missing");
        assert_eq!(d.text(), "[delivery]\n");
    }

    #[test]
    fn effective_lookup_and_sizes() {
        let d = doc("");
        assert_eq!(size_text(d.get("limits.max_message_size")), "25MB");
        assert_eq!(size_text(&serde_json::json!(1000)), "1000");
        assert!(d.get("limits.nope").is_null());
    }
}
