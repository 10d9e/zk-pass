use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use num_bigint::BigUint;
use zk_pass::rand::RandomGenerator;

fn bench_biguint_random_generation(c: &mut Criterion) {
    c.bench_function("BigUint Random Generation", |b| {
        b.iter(|| {
            let _ = black_box(BigUint::generate_random().unwrap());
        });
    });
}

fn bench_scalar_random_generation(c: &mut Criterion) {
    c.bench_function("Scalar Random Generation", |b| {
        b.iter(|| {
            let _ = black_box(Scalar::generate_random().unwrap());
        });
    });
}

fn bench_ristretto_point_random_generation(c: &mut Criterion) {
    c.bench_function("RistrettoPoint Random Generation", |b| {
        b.iter(|| {
            let _ = black_box(RistrettoPoint::generate_random().unwrap());
        });
    });
}

criterion_group!(
    benches,
    bench_biguint_random_generation,
    bench_scalar_random_generation,
    bench_ristretto_point_random_generation,
);
criterion_main!(benches);
