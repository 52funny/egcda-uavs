use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand::Rng;

fn hash_to_prime_bench(c: &mut Criterion) {
    use utils::hash_to_prime;

    let mut group = c.benchmark_group("hash_to_prime");

    group.bench_function("hash_to_prime", |b| {
        b.iter_batched(
            // setup：random input generation
            || {
                let mut rng = rand::rng();
                let mut input = vec![0u8; 32];
                rng.fill(&mut input[..]);
                unsafe { String::from_utf8_unchecked(input) }
            },
            // measurement
            |input| {
                let _prime = hash_to_prime(black_box(input));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, hash_to_prime_bench);
criterion_main!(benches);
