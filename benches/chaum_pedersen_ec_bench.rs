use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand::rngs::OsRng;
use zk_pass::chaum_pedersen::curve25519::Curve25519ChaumPedersen;
use zk_pass::chaum_pedersen::ChaumPedersen;
use zk_pass::chaum_pedersen::GroupParams;

pub fn elliptic_curve_commitment_benchmark(c: &mut Criterion) {
    c.bench_function("elliptic_curve_commitment", |b| {
        let mut rng = OsRng;
        let x = Scalar::from(3u32);
        let g = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
        let h = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
        let params = GroupParams::<RistrettoPoint> {
            g: g.clone(),
            h: h.clone(),
            p: RISTRETTO_BASEPOINT_POINT,
            q: RISTRETTO_BASEPOINT_POINT,
        };
        b.iter(|| Curve25519ChaumPedersen::commitment(black_box(&params), black_box(&x)));
    });
}

pub fn elliptic_curve_challenge_benchmark(c: &mut Criterion) {
    c.bench_function("elliptic_curve_challenge", |b| {
        let params = GroupParams::<RistrettoPoint> {
            g: RISTRETTO_BASEPOINT_POINT,
            h: RISTRETTO_BASEPOINT_POINT,
            p: RISTRETTO_BASEPOINT_POINT,
            q: RISTRETTO_BASEPOINT_POINT,
        };
        b.iter(|| Curve25519ChaumPedersen::challenge(black_box(&params)));
    });
}

// Add more benchmarks here following the same pattern...

criterion_group!(
    benches,
    elliptic_curve_commitment_benchmark,
    elliptic_curve_challenge_benchmark,
    // Add more benchmarks to the group...
);
criterion_main!(benches);
