use crate::chaum_pedersen::curve25519::EllipticCurveChaumPedersen;
use crate::chaum_pedersen::discretelog::DiscreteLogChaumPedersen;
use crate::chaum_pedersen::{ChaumPedersen, GroupParams};
use curve25519_dalek::{scalar::Scalar, RistrettoPoint};
use num_bigint::BigUint;

fn execute_protocol_via_factory<T, P, S, F>(params: &GroupParams<P>, x: &T::Secret,
) -> bool
where
    T: ChaumPedersen<
        GroupParameters = GroupParams<P>,
        CommitParameters = (P, P, P, P),
        Response = S,
        Challenge = S,
    >,
{
    // client calculates commitment
    let (cp, k) = T::calculate_commitment(params, x);

    // server sends challenge
    let c = T::challenge(params);

    // client calculates response
    let s = T::calculate_response(params, &k, &c, &x);

    // server verifies
    T::verify(params, &s, &c, &cp)
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaum_pedersen::constants::RFC5114_MODP_1024_160_BIT_PARAMS;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand::rngs::OsRng;

    #[test]
    fn test_factory() {
        // Parameters for the protocols (initialize accordingly)
        let dl_params = RFC5114_MODP_1024_160_BIT_PARAMS.to_owned();

        let mut rng = OsRng;
        let g = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
        let h = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
        let ec_params = GroupParams::<RistrettoPoint> {
            g: g.clone(),
            h: h.clone(),
            p: RISTRETTO_BASEPOINT_POINT,
            q: RISTRETTO_BASEPOINT_POINT,
        };

        // Secret values for the protocols (initialize accordingly)
        let dl_secret: BigUint = BigUint::from(3u32);
        let ec_secret: Scalar = Scalar::from(3u32);

        // Using Default Log Factory
        let dl_result = execute_protocol_via_factory::<DiscreteLogChaumPedersen, _, _, _>(
            &DEFAULT_FACTORY,
            &dl_params,
            &dl_secret,
        );
        println!("Discrete Log result: {}", dl_result);
        assert!(dl_result);

        // Using Discrete Log Factory
        let dl_result = execute_protocol_via_factory::<DiscreteLogChaumPedersen, _, _, _>(
            &DiscreteLogFactory,
            &dl_params,
            &dl_secret,
        );
        println!("Discrete Log result: {}", dl_result);
        assert!(dl_result);

        // Using Elliptic Curve Factory
        let ec_result = execute_protocol_via_factory::<EllipticCurveChaumPedersen, _, _, _>(
            &EllipticCurveFactory,
            &ec_params,
            &ec_secret,
        );
        println!("Elliptic Curve result: {}", ec_result);
        assert!(ec_result);
    }
}
