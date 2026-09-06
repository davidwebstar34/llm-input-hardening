use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Sanitization policy preset.
#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub normalize: Normalization,
    pub remove_bidi: bool,
    pub remove_bidi_marks: bool,
    pub flag_bidi_marks: bool,
    pub remove_tag_chars: bool,
    pub cap_variation_selectors: bool,
    pub remove_junk_invisibles: bool,
    pub remove_other_controls: bool,
    pub remove_default_ignorables: bool,
    pub tidy_whitespace: bool,
    pub flag_default_ignorables: bool,
    pub flag_base64ish: bool,
    pub flag_combining_abuse: bool,
}

/// Unicode normalization mode.
#[derive(Debug, Clone, Copy)]
pub enum Normalization {
    Nfc,
    Nfkc,
}

#[derive(Debug, Deserialize)]
struct PolicyRegistry {
    signals: SignalSpec,
    aliases: HashMap<String, String>,
    presets: HashMap<String, PolicySpec>,
}

/// Heuristic-signal thresholds shared with the Python layer via the registry.
///
/// Only the fields the Rust core consumes are deserialized; the registry also
/// carries Python-only thresholds (entropy window, hex blob).
#[derive(Debug, Deserialize)]
pub struct SignalSpec {
    pub entropy_prefix_chars: usize,
    pub entropy_prefix_threshold: f64,
    pub entropy_prefix_min_chars: usize,
    pub base64_min_chars: usize,
    pub combining_ratio_threshold: f64,
    pub combining_min_chars: usize,
}

#[derive(Debug, Deserialize)]
struct PolicySpec {
    normalization: String,
    remove_bidi: bool,
    #[serde(default)]
    remove_bidi_marks: bool,
    #[serde(default = "default_true")]
    flag_bidi_marks: bool,
    #[serde(default = "default_true")]
    remove_tag_chars: bool,
    #[serde(default)]
    cap_variation_selectors: bool,
    remove_junk_invisibles: bool,
    remove_other_controls: bool,
    remove_default_ignorables: bool,
    tidy_whitespace: bool,
    flag_default_ignorables: bool,
    flag_base64ish: bool,
    flag_combining_abuse: bool,
}

fn default_true() -> bool {
    true
}

fn registry() -> &'static PolicyRegistry {
    static REGISTRY: OnceLock<PolicyRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/python/llm_input_hardening/policy_registry.json"
        )))
        .expect("policy registry must be valid JSON")
    })
}

/// Shared heuristic-signal thresholds from the policy registry.
pub fn signal_spec() -> &'static SignalSpec {
    &registry().signals
}

fn normalization_from_string(value: &str) -> Option<Normalization> {
    match value {
        "NFC" => Some(Normalization::Nfc),
        "NFKC" => Some(Normalization::Nfkc),
        _ => None,
    }
}

/// Get a built-in policy preset by name.
///
/// The canonical name is taken directly from the registry key that matched, so
/// adding a preset to `policy_registry.json` is sufficient — there is no
/// second, hand-maintained name list to keep in sync.
pub fn get_policy(name: &str) -> Option<Policy> {
    let registry = registry();
    let canonical = registry
        .aliases
        .get(name)
        .map(String::as_str)
        .unwrap_or(name);
    let (canonical_key, spec) = registry.presets.get_key_value(canonical)?;

    Some(Policy {
        name: canonical_key.clone(),
        normalize: normalization_from_string(&spec.normalization)?,
        remove_bidi: spec.remove_bidi,
        remove_bidi_marks: spec.remove_bidi_marks,
        flag_bidi_marks: spec.flag_bidi_marks,
        remove_tag_chars: spec.remove_tag_chars,
        cap_variation_selectors: spec.cap_variation_selectors,
        remove_junk_invisibles: spec.remove_junk_invisibles,
        remove_other_controls: spec.remove_other_controls,
        remove_default_ignorables: spec.remove_default_ignorables,
        tidy_whitespace: spec.tidy_whitespace,
        flag_default_ignorables: spec.flag_default_ignorables,
        flag_base64ish: spec.flag_base64ish,
        flag_combining_abuse: spec.flag_combining_abuse,
    })
}
