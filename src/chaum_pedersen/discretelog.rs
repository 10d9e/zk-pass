use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::rngs::OsRng;

use crate::chaum_pedersen::{ChaumPedersen, GroupParams};

/// A struct representing the Chaum-Pedersen protocol specialized for discrete logarithm-based groups.
/// This protocol is used for demonstrating knowledge of a secret in a zero-knowledge manner.
#[derive(Clone)]
pub struct DiscreteLogChaumPedersen {}

impl ChaumPedersen for DiscreteLogChaumPedersen {
    /// Defines the type of secret values used in this protocol as `BigUint`.
    type Secret = BigUint;

    /// Defines the type of randomness used during the commitment phase as `BigUint`.
    type CommitmentRandom = BigUint;

    /// Defines the type of response generated in the protocol as `BigUint`.
    type Response = BigUint;

    /// Defines the type of challenge used in the protocol as `BigUint`.
    type Challenge = BigUint;

    /// Defines the group parameters specific to discrete logarithm groups as `GroupParams<BigUint>`.
    type GroupParameters = GroupParams<BigUint>;

    /// Defines the type of parameters returned during the commitment phase.
    /// These include two values representing the commitment and two values representing the randomness.
    type CommitParameters = (BigUint, BigUint, BigUint, BigUint);

    /// Calculates the commitment for the given secret `x` using the provided group parameters.
    ///
    /// # Arguments
    /// * `params`: Group parameters which include the base points `g` and `h`, and the moduli `p` and `q`.
    /// * `x`: The secret value for which the commitment is being calculated.
    ///
    /// # Returns
    /// A tuple containing:
    /// * A tuple of commitments (`y1`, `y2`, `r1`, `r2`), where `y1` and `y2` are the actual commitments
    ///   and `r1` and `r2` are the random commitments.
    /// * The random value `k` used in the commitment calculations.
    fn commitment(
        params: &Self::GroupParameters, x: &Self::Secret,
    ) -> (Self::CommitParameters, Self::CommitmentRandom)
    where
        Self: Sized,
    {
        let y1 = params.g.modpow(x, &params.p);
        let y2 = params.h.modpow(x, &params.p);
        let mut rng = OsRng;
        let k = rng.gen_biguint_below(&params.p);
        let r1 = params.g.modpow(&k, &params.p);
        let r2 = params.h.modpow(&k, &params.p);
        ((y1, y2, r1, r2), k)
    }

    /// Generates a random challenge for the protocol within the group's range.
    /// This challenge is used as part of the verification process.
    ///
    /// # Arguments
    /// * `params`: Group parameters used to define the range within which the challenge is generated.
    ///
    /// # Returns
    /// A `BigUint` representing the challenge value.
    fn challenge(params: &GroupParams<BigUint>) -> BigUint {
        let mut rng = OsRng;
        rng.gen_biguint_below(&params.p)
    }

    /// Generates a random challenge for the protocol within the group's range.
    /// This challenge is used as part of the verification process.
    ///
    /// # Arguments
    /// * `params`: Group parameters used to define the range within which the challenge is generated.
    ///
    /// # Returns
    /// A `BigUint` representing the challenge value.
    fn challenge_response(
        params: &Self::GroupParameters, k: &Self::CommitmentRandom, c: &Self::Challenge,
        x: &Self::Secret,
    ) -> Self::Response
    where
        Self: Sized,
    {
        if k >= &(c * x) {
            (k - c * x).modpow(&BigUint::one(), &params.q)
        } else {
            &params.q - (c * x - k).modpow(&BigUint::one(), &params.q)
        }
    }

    /// Verifies the response against the given commitment, challenge, and group parameters.
    /// The function checks if the response is valid based on the protocol's criteria.
    ///
    /// # Arguments
    /// * `params`: Group parameters used in the verification.
    /// * `s`: The response to be verified.
    /// * `c`: The challenge against which the response is being verified.
    /// * `cp`: The commitment parameters (`y1`, `y2`, `r1`, `r2`) against which the response is being verified.
    ///
    /// # Returns
    /// `true` if the verification is successful and the response is valid; `false` otherwise.
    fn verify(
        params: &Self::GroupParameters, s: &Self::Response, c: &Self::Challenge,
        cp: &Self::CommitParameters,
    ) -> bool {
        let (y1, y2, r1, r2) = (cp.0.clone(), cp.1.clone(), cp.2.clone(), cp.3.clone());

        let lhs1 = params.g.modpow(s, &params.p);
        let rhs1 = (&r1 * y1.modpow(&(&params.p - c - BigUint::one()), &params.p)) % &params.p;
        let lhs2 = params.h.modpow(s, &params.p);
        let rhs2 = (&r2 * y2.modpow(&(&params.p - c - BigUint::one()), &params.p)) % &params.p;

        lhs1 == rhs1 && lhs2 == rhs2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaum_pedersen::constants::{
        RFC5114_MODP_1024_160_BIT_PARAMS, RFC5114_MODP_2048_224_BIT_PARAMS,
        RFC5114_MODP_2048_256_BIT_PARAMS,
    };
    use crate::chaum_pedersen::test::test_execute_protocol;

    #[test]
    fn test_discrete_log_commitment() {
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
        let (y1, y2, r1, r2) = cp;

        assert_eq!(y1, params.g.modpow(&x, &params.p));
        assert_eq!(y2, params.h.modpow(&x, &params.p));
        assert!(r1 < params.p && r2 < params.p);
    }

    #[test]
    fn test_discrete_log_verification() {
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

        assert!(test_execute_protocol::<DiscreteLogChaumPedersen>(&params, &x));
    }

    #[test]
    fn test_rfc_1024_160_bits_params() {
        let params = RFC5114_MODP_1024_160_BIT_PARAMS.to_owned();
        let mut rng = OsRng;
        let x = rng.gen_biguint_below(&params.p);
        assert!(test_execute_protocol::<DiscreteLogChaumPedersen>(&params, &x));
    }

    #[test]
    fn test_rfc_2048_224_bits_params() {
        let params = RFC5114_MODP_2048_224_BIT_PARAMS.to_owned();
        let mut rng = OsRng;
        let x = rng.gen_biguint_below(&params.p);
        assert!(test_execute_protocol::<DiscreteLogChaumPedersen>(&params, &x));
    }

    #[test]
    fn test_rfc_2048_256_bits_params() {
        let params = RFC5114_MODP_2048_256_BIT_PARAMS.to_owned();
        let mut rng = OsRng;
        let x = rng.gen_biguint_below(&params.p);
        assert!(test_execute_protocol::<DiscreteLogChaumPedersen>(&params, &x));
    }

    #[test]
    fn test_verify() {
        let g = BigUint::from(4u32);
        let h = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);

        let params = GroupParams::<BigUint> {
            g: g.clone(),
            h: h.clone(),
            p: p.clone(),
            q: q.clone(),
        };

        let cp = (
            BigUint::from(6u32),
            BigUint::from(18u32),
            BigUint::from(2u32),
            BigUint::from(3u32),
        );

        // client calculates response
        let x = BigUint::from(10u32);
        let k = BigUint::from(17u32);
        let c = BigUint::from(0u32);
        let s = DiscreteLogChaumPedersen::challenge_response(&params, &k, &c, &x);
        println!("Response: {:?}", s);

        // server verifies
        assert!(DiscreteLogChaumPedersen::verify(&params, &s, &c, &cp));
    }
}
