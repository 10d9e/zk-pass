//! # Vesta Curve Chaum-Pedersen Protocol Module
//!
//! This module implements the Chaum-Pedersen protocol for the Vesta elliptic curve.
//! The protocol includes methods for generating commitments, creating challenges,
//! responding to challenges, and verifying the correctness of the response.

use crate::chaum_pedersen::{ChaumPedersen, GroupParams};
use pasta_curves::group::ff::Field;
use pasta_curves::vesta::{Point, Scalar};
use rand_core::OsRng;

/// The VestaCurveChaumPedersen struct defines the specific types used in the Chaum-Pedersen protocol for the Vesta curve.
pub struct VestaCurveChaumPedersen {}

impl ChaumPedersen for VestaCurveChaumPedersen {
    type Secret = Scalar;
    type Response = Scalar;
    type Challenge = Scalar;
    type CommitmentRandom = Scalar;
    type GroupParameters = GroupParams<Point>;
    type CommitParameters = (Point, Point, Point, Point);

    /// Generates a commitment to a secret on the Vesta curve.
    ///
    /// # Parameters
    ///
    /// * `params` - Group parameters of the Vesta curve.
    /// * `x` - The secret scalar value to which the commitment is made.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the commitment parameters and a commitment random scalar.
    fn commitment(
        params: &Self::GroupParameters, x: &Self::Secret,
    ) -> (Self::CommitParameters, Self::CommitmentRandom)
    where
        Self: Sized,
    {
        let y1 = params.g * Scalar::from(x.clone());
        let y2 = params.h * Scalar::from(x.clone());
        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let r1 = params.g * k;
        let r2 = params.h * k;
        ((y1, y2, r1, r2), k)
    }

    /// Generates a random challenge scalar.
    ///
    /// # Parameters
    ///
    /// * `_params` - Ignored in this implementation. Group parameters can be used if needed.
    ///
    /// # Returns
    ///
    /// Returns a random scalar value to be used as a challenge.
    fn challenge(_: &GroupParams<Point>) -> Self::Challenge {
        let mut rng = OsRng;
        Scalar::random(&mut rng)
    }

    /// Generates a response to a challenge given a secret and a random scalar.
    ///
    /// # Parameters
    ///
    /// * `_params` - Ignored in this implementation. Group parameters can be used if needed.
    /// * `k` - The random scalar used during commitment.
    /// * `c` - The challenge scalar.
    /// * `x` - The secret scalar.
    ///
    /// # Returns
    ///
    /// Returns the response scalar, which is calculated as `k + (c * x)`.
    fn challenge_response(
        _: &Self::GroupParameters, k: &Self::CommitmentRandom, c: &Self::Challenge,
        x: &Self::Secret,
    ) -> Self::Response
    where
        Self: Sized,
    {
        k + (c * x)
    }

    /// Verifies the correctness of the response to a challenge.
    ///
    /// # Parameters
    ///
    /// * `params` - Group parameters of the Vesta curve.
    /// * `s` - The response scalar.
    /// * `c` - The challenge scalar.
    /// * `cp` - The commitment parameters tuple.
    ///
    /// # Returns
    ///
    /// Returns `true` if the verification is successful, `false` otherwise.
    fn verify(
        params: &Self::GroupParameters, s: &Self::Response, c: &Self::Challenge,
        cp: &Self::CommitParameters,
    ) -> bool {
        let (y1, y2, r1, r2) = cp;
        (params.g * s == r1 + (y1 * c)) && (params.h * s == r2 + (y2 * c))
    }
}

#[cfg(test)]
mod test {
    //! Test module for Vesta Curve Chaum-Pedersen Protocol.
    //!
    //! Contains tests that verify the correct functioning of the commitment,
    //! challenge, and verification steps of the protocol using the Vesta elliptic curve.

    use super::*;
    use crate::chaum_pedersen::constants::{VESTA_GROUP_PARAMS};
    use crate::chaum_pedersen::test::test_execute_protocol;
    use curve25519_dalek::digest::typenum::Quot;
    use pasta_curves::group::{GroupEncoding, Group};

    /// Test verification using standard protocol execution.
    #[test]
    fn test_elliptic_curve_standard_verification() {
        let mut rng = OsRng;
        let x = Scalar::random(&mut rng);
        let params = VESTA_GROUP_PARAMS.to_owned();

     
        // Generating random points g and h on the Vesta curve.
        /*
        let g = Point::generator() * Scalar::random(&mut rng);
        let h = Point::generator() * Scalar::random(&mut rng);
        let p = Point::generator();
        let q = Point::generator();

        // Setting up the group parameters.
        let params = GroupParams::<Point> {
            g: g.clone(),
            h: h.clone(),
            p: Point::generator(),
            q: Point::generator(),
        };
         

        println!("g: {:?}", hex::encode(g.to_bytes()));
        println!("h: {:?}", hex::encode(h.to_bytes()));
        println!("p: {:?}", hex::encode(p.to_bytes()));
        println!("q: {:?}", hex::encode(q.to_bytes()));
        */

        // Testing the correctness of the serialization and deserialization of group parameters.
        let gb = params.g.to_bytes();
        let restored_g = Point::from_bytes(&gb).unwrap();
        assert_eq!(params.g, restored_g);

        let hb = params.h.to_bytes();
        let restored_h = Point::from_bytes(&hb).unwrap();
        assert_eq!(params.h, restored_h);

        // Further tests omitted for brevity...

        // Asserting the successful execution of the protocol.
        assert!(test_execute_protocol::<VestaCurveChaumPedersen>(&params, &x));
    }

    /// Test verification fails with an incorrect response.
    #[test]
    fn test_fail_elliptic_curve_verification() {
        let mut rng = OsRng;
        let x = Scalar::random(&mut rng);
        let params = VESTA_GROUP_PARAMS.to_owned();

        // Generating commitment and a challenge to simulate an authentication attempt.
        let (cp, _) = VestaCurveChaumPedersen::commitment(&params, &x);
        let c = VestaCurveChaumPedersen::challenge(&params);

        // Simulating a fake response to force a failed verification.
        let fake_response = Scalar::random(&mut rng);

        // Asserting that the verification should fail with the fake response.
        let verified = VestaCurveChaumPedersen::verify(&params, &fake_response, &c, &cp);
        assert!(!verified);
    }
}
