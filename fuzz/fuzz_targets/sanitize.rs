#![no_main]
//! Fuzz the deterministic core: it must never panic on arbitrary input, and
//! sanitization must be idempotent for every policy.
use libfuzzer_sys::fuzz_target;
use llm_input_hardening::sanitize_inner;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    for policy in ["preserve", "balanced_chat", "strict_exec", "code_mode"] {
        // return_spans=true exercises the UTF-8 boundary bookkeeping too.
        if let Ok((clean, _)) = sanitize_inner(s, policy, true) {
            let (again, _) = sanitize_inner(&clean, policy, false)
                .expect("sanitizing already-clean text must not fail");
            assert_eq!(clean, again, "sanitize not idempotent under {policy}");
        }
    }
});
