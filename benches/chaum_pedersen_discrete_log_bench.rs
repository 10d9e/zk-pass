use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use zk_pass::chaum_pedersen::constants::{
    RFC5114_MODP_1024_160_BIT_PARAMS, RFC5114_MODP_2048_224_BIT_PARAMS,
    RFC5114_MODP_2048_256_BIT_PARAMS,
};
use zk_pass::chaum_pedersen::discretelog::DiscreteLogChaumPedersen;
use zk_pass::chaum_pedersen::test::test_execute_protocol;
use zk_pass::chaum_pedersen::ChaumPedersen;
use zk_pass::chaum_pedersen::GroupParams;

fn discrete_log_commitment_benchmark(c: &mut Criterion) {
    let g = BigUint::from(4u32);
    let h = BigUint::from(9u32);
    let p = BigUint::from(23u32);
    let q = BigUint::from(11u32);
    let x = BigUint::from(3u32);

    let params = GroupParams::<BigUint> {
        g: g.clone(),
        h: h.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    c.bench_function("discrete_log_commitment", |b| {
        b.iter(|| {
            let _result = DiscreteLogChaumPedersen::commitment(&params, &x);
        })
    });
}

fn discrete_log_verification_benchmark(c: &mut Criterion) {
    let g = BigUint::from(4u32);
    let h = BigUint::from(9u32);
    let p = BigUint::from(23u32);
    let q = BigUint::from(11u32);
    let x = BigUint::from(3u32);

    let params = GroupParams::<BigUint> {
        g: g.clone(),
        h: h.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    let (cp, _k) = DiscreteLogChaumPedersen::commitment(&params, &x);

    c.bench_function("discrete_log_verification", |b| {
        b.iter(|| {
            let _result = DiscreteLogChaumPedersen::verify(
                &params,
                &black_box(BigUint::from(10u32)),
                &black_box(BigUint::from(0u32)),
                &cp,
            );
        })
    });
}

fn bench_protocol(params: &GroupParams<BigUint>, c: &mut Criterion, label: &str) {
    let mut rng = OsRng;
    let x = rng.gen_biguint_below(&params.p);

    c.bench_function(&format!("discrete_log_protocol_{}", label), |b| {
        b.iter(|| test_execute_protocol::<DiscreteLogChaumPedersen>(&params, &x))
    });
}

fn bench_1024_160_bits(c: &mut Criterion) {
    let params = RFC5114_MODP_1024_160_BIT_PARAMS.to_owned();
    bench_protocol(&params, c, "1024_160");
}

fn bench_2048_224_bits(c: &mut Criterion) {
    let params = RFC5114_MODP_2048_224_BIT_PARAMS.to_owned();
    bench_protocol(&params, c, "2048_224");
}

fn bench_2048_256_bits(c: &mut Criterion) {
    let params = RFC5114_MODP_2048_256_BIT_PARAMS.to_owned();
    bench_protocol(&params, c, "2048_256");
}

criterion_group!(
    benches,
    discrete_log_commitment_benchmark,
    discrete_log_verification_benchmark,
    bench_1024_160_bits,
    bench_2048_224_bits,
    bench_2048_256_bits
);
criterion_main!(benches);
