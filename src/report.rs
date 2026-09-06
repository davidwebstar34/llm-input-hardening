use serde::Serialize;

/// One per-event span emitted by the sanitizer when span reporting is enabled.
#[derive(Debug, Clone, Serialize)]
pub struct SpanEvent {
    /// Event kind: `"removed"` or `"flag"`.
    pub kind: String,
    /// Category key (matches `removed_counts` / `flagged_counts` keys).
    pub reason: String,
    /// Start index (UTF-8 byte offset) into the internally scanned string.
    pub start: usize,
    /// End index (UTF-8 byte offset) into the internally scanned string.
    pub end: usize,
    /// Additional detail (typically a `U+XXXX` codepoint).
    pub detail: String,
}

/// Structured report returned by the sanitizer.
///
/// This schema is intended to be stable and **versioned** (`report_version`) so
/// downstream consumers can parse it safely.
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeReport {
    /// Report schema version.
    pub report_version: u32,
    pub policy: String,
    pub normalization: String,
    pub changed: bool,
    pub removed_counts: std::collections::BTreeMap<String, usize>,
    pub flagged_counts: std::collections::BTreeMap<String, usize>,
    pub spans: Vec<SpanEvent>,
    pub stats: serde_json::Value,
}

impl Default for SanitizeReport {
    fn default() -> Self {
        Self {
            report_version: 1,
            policy: String::new(),
            normalization: String::new(),
            changed: false,
            removed_counts: std::collections::BTreeMap::new(),
            flagged_counts: std::collections::BTreeMap::new(),
            spans: Vec::new(),
            stats: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

impl SanitizeReport {
    pub fn bump_removed(&mut self, key: &str, n: usize) {
        *self.removed_counts.entry(key.to_string()).or_insert(0) += n;
    }
    pub fn bump_flagged(&mut self, key: &str, n: usize) {
        *self.flagged_counts.entry(key.to_string()).or_insert(0) += n;
    }
}
