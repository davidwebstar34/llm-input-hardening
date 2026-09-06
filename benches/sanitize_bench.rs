use criterion::{criterion_group, criterion_main, Criterion};
use llm_input_hardening::*;

fn bench_ascii(c: &mut Criterion) {
    let s = "Hello world this is a normal prompt with ASCII only.";
    c.bench_function("sanitize_ascii_balanced", |b| {
        b.iter(|| {
            let _ = crate::sanitize_inner(s, "balanced", false).unwrap();
        })
    });
}

fn bench_bidi(c: &mut Criterion) {
    let s = "abc\u{202E}def some more text";
    c.bench_function("sanitize_bidi_balanced", |b| {
        b.iter(|| {
            let _ = crate::sanitize_inner(s, "balanced", false).unwrap();
        })
    });
}

criterion_group!(benches, bench_ascii, bench_bidi);
criterion_main!(benches);
