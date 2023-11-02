use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use num_bigint::BigUint;
use num_bigint::ToBigUint;
use rand::rngs::OsRng;
use zk_pass::conversion::ByteConvertible;

fn bench_biguint_serialization(c: &mut Criterion) {
    let biguint = 123456789u64.to_biguint().unwrap();
    c.bench_function("BigUint Serialization", |b| {
        b.iter(|| {
            black_box(BigUint::to_bytes(&biguint));
        });
    });
}

fn bench_biguint_deserialization(c: &mut Criterion) {
    let bytes = BigUint::to_bytes(&123456789u64.to_biguint().unwrap());
    c.bench_function("BigUint Deserialization", |b| {
        b.iter(|| {
            black_box(BigUint::from_bytes(&bytes).unwrap());
        });
    });
}

fn bench_ristretto_point_serialization(c: &mut Criterion) {
    let point = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);
    c.bench_function("RistrettoPoint Serialization", |b| {
        b.iter(|| {
            black_box(RistrettoPoint::to_bytes(&point));
        });
    });
}

fn bench_ristretto_point_deserialization(c: &mut Criterion) {
    let point = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);
    let bytes = RistrettoPoint::to_bytes(&point);
    c.bench_function("RistrettoPoint Deserialization", |b| {
        b.iter(|| {
            black_box(RistrettoPoint::from_bytes(&bytes).unwrap());
        });
    });
}

fn bench_scalar_serialization(c: &mut Criterion) {
    let scalar = Scalar::random(&mut OsRng);
    c.bench_function("Scalar Serialization", |b| {
        b.iter(|| {
            black_box(Scalar::to_bytes(&scalar));
        });
    });
}

fn bench_scalar_deserialization(c: &mut Criterion) {
    let scalar = Scalar::random(&mut OsRng);
    let bytes = Scalar::to_bytes(&scalar);
    c.bench_function("Scalar Deserialization", |b| {
        b.iter(|| {
            black_box(Scalar::from_bytes(&bytes).unwrap());
        });
    });
}

criterion_group!(
    benches,
    bench_biguint_serialization,
    bench_biguint_deserialization,
    bench_ristretto_point_serialization,
    bench_ristretto_point_deserialization,
    bench_scalar_serialization,
    bench_scalar_deserialization,
);
criterion_main!(benches);
