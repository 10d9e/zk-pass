use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use zk_pass::chaum_pedersen::GroupParams;
use curve25519_dalek::RistrettoPoint;
use zk_pass::chaum_pedersen::curve25519::EllipticCurveChaumPedersen;
use zk_pass::chaum_pedersen::ChaumPedersen;
use rand::rngs::OsRng;

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
        b.iter(|| EllipticCurveChaumPedersen::commitment(black_box(&params), black_box(&x)));
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
        b.iter(|| EllipticCurveChaumPedersen::challenge(black_box(&params)));
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
