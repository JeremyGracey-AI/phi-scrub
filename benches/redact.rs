use criterion::{black_box, criterion_group, criterion_main, Criterion};
use phi_scrub::Scrubber;

fn bench(c: &mut Criterion) {
    let s = Scrubber::new();
    let text = "Call 808-555-0100 or email a@b.com. SSN 123-45-6789. ".repeat(100);
    c.bench_function("redact_100x", |b| b.iter(|| s.redact(black_box(&text))));
}

criterion_group!(benches, bench);
criterion_main!(benches);
