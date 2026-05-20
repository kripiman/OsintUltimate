use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashSet;

// Local copy of sources.rs::apply_cap (private fn — see N1 audit note)
fn apply_cap(set: HashSet<String>, limit: usize) -> HashSet<String> {
    if limit == 0 {
        return HashSet::new();
    }
    if set.len() > limit {
        set.into_iter().take(limit).collect()
    } else {
        set
    }
}

fn bench_apply_cap(c: &mut Criterion) {
    let mut group = c.benchmark_group("apply_cap");
    for size in [10usize, 100, 1000] {
        let input: HashSet<String> = (0..size).map(|i| i.to_string()).collect();
        group.bench_with_input(BenchmarkId::new("truncate_half", size), &size, |b, &s| {
            b.iter(|| apply_cap(input.clone(), s / 2))
        });
        group.bench_with_input(BenchmarkId::new("zero_disable", size), &size, |b, _| {
            b.iter(|| apply_cap(input.clone(), 0))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_apply_cap);
criterion_main!(benches);
