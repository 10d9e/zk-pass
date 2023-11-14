use crate::chaum_pedersen::{ChaumPedersen, GroupParams};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand::rngs::OsRng;
use crate::rand::RandomGenerator;
use crate::conversion::ByteConvertible;
use std::error::Error;

/// A struct representing the Chaum-Pedersen protocol specialized for elliptic curve groups.
/// This protocol is used for demonstrating knowledge of a secret in a zero-knowledge manner.
/// The elliptic curve used in this implementation is based on Ristretto points.
pub struct Curve25519ChaumPedersen {}

/// Implementing the ChaumPedersen trait for EllipticCurveChaumPedersen.
impl ChaumPedersen for Curve25519ChaumPedersen {
    /// Defines the type of the secret being proven. In this case, it is a scalar value.
    type Secret = Scalar;

    /// Defines the type of the commitment randomness used in the protocol.
    /// This is a scalar value used during the commitment phase.
    type CommitmentRandom = Scalar;

    /// Defines the type of the response generated in the protocol.
    /// This is a scalar value representing the participant's response in the protocol.
    type Response = Scalar;

    /// Defines the type of the challenge used in the protocol.
    /// This is a scalar value representing the challenge posed during the protocol.
    type Challenge = Scalar;

    /// Defines the group parameters used in the protocol.
    /// These parameters are based on Ristretto points, which provide a prime-order group on an elliptic curve.
    type GroupParameters = GroupParams<RistrettoPoint>;

    /// Defines the commitment parameters used in the protocol.
    /// These are four Ristretto points representing the commitments and random commitments.
    type CommitParameters = (RistrettoPoint, RistrettoPoint, RistrettoPoint, RistrettoPoint);

    /// Calculate the commitment values for the Chaum-Pedersen protocol.
    ///
    /// This method generates a random scalar and computes the commitment parameters
    /// using the secret value and the group parameters.
    ///
    /// # Arguments
    /// * `params` - Reference to the group parameters used in the computation.
    /// * `x` - Reference to the secret value.
    ///
    /// # Returns
    /// A tuple containing the commitment parameters and the commitment random value.
    fn commitment(
        params: &Self::GroupParameters, x: &Self::Secret,
    ) -> (Self::CommitParameters, Self::CommitmentRandom)
    where
        Self: Sized,
    {
        let y1 = params.g * x; // Calculate y1 = g * x.
        let y2 = params.h * x; // Calculate y2 = h * x.
        let mut rng = OsRng; // Create a random number generator.
        let k = Scalar::random(&mut rng); // Generate a random scalar k.
        let r1 = params.g * k; // Calculate r1 = g * k.
        let r2 = params.h * k; // Calculate r2 = h * k.
        ((y1, y2, r1, r2), k) // Return the commitment parameters and random value.
    }

    /// Generate a random challenge for the Chaum-Pedersen protocol.
    ///
    /// This method generates a random scalar value to be used as a challenge.
    ///
    /// # Arguments
    /// * `_` - Reference to the group parameters, not used in this implementation.
    ///
    /// # Returns
    /// A random scalar value to be used as a challenge.
    fn challenge(_: &GroupParams<RistrettoPoint>) -> Self::Challenge {
        let mut rng = OsRng; // Create a random number generator.
        Scalar::random(&mut rng) // Generate and return a random scalar as the challenge.
    }

    /// Calculate the response for the Chaum-Pedersen protocol.
    ///
    /// This method computes the response using the commitment random value,
    /// the challenge, and the secret value.
    ///
    /// # Arguments
    /// * `_` - Reference to the group parameters, not used in this implementation.
    /// * `k` - Reference to the commitment random value.
    /// * `c` - Reference to the challenge.
    /// * `x` - Reference to the secret value.
    ///
    /// # Returns
    /// The response for the Chaum-Pedersen protocol.
    fn challenge_response(
        _: &Self::GroupParameters, k: &Self::CommitmentRandom, c: &Self::Challenge,
        x: &Self::Secret,
    ) -> Self::Response
    where
        Self: Sized,
    {
        k + (c * x) // Calculate and return the response as k + (c * x).
    }

    /// Verify the response for the Chaum-Pedersen protocol.
    ///
    /// This method checks if the provided response, along with the challenge and
    /// commitment parameters, satisfies the verification equations.
    ///
    /// # Arguments
    /// * `params` - Reference to the group parameters used in the verification.
    /// * `s` - Reference to the response.
    /// * `c` - Reference to the challenge.
    /// * `cp` - Reference to the commitment parameters.
    ///
    /// # Returns
    /// `true` if the verification is successful, `false` otherwise.
    fn verify(
        params: &Self::GroupParameters, s: &Self::Response, c: &Self::Challenge,
        cp: &Self::CommitParameters,
    ) -> bool {
        // Deconstructing the commitment parameters tuple.
        let (y1, y2, r1, r2) = cp;
        // Verifying the proof by checking two equations.
        (params.g * s == r1 + (y1 * c)) && (params.h * s == r2 + (y2 * c))
    }
}

/// Implementation of `ByteConvertible` for `Scalar`.
///
/// This implementation provides methods to convert `Scalar` objects to and from
/// byte arrays. Scalars are fundamental in cryptographic operations and being able to
/// serialize and deserialize them is crucial.
impl ByteConvertible<Scalar> for Scalar {
    fn convert_to(t: &Scalar) -> Vec<u8> {
        t.to_bytes().to_vec()
    }

    fn convert_from(bytes: &[u8]) -> Result<Scalar, Box<dyn Error>> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid bytes length for Scalar",
            )) as Box<dyn Error>
        })?;
        Ok(Scalar::from_bytes_mod_order(array))
    }
}

/// Implementation of `ByteConvertible` for `RistrettoPoint`.
///
/// This implementation provides methods to convert `RistrettoPoint` objects to and from
/// byte arrays. It uses the compression and decompression features of the Ristretto group
/// to achieve this.
impl ByteConvertible<RistrettoPoint> for RistrettoPoint {
    fn convert_to(t: &RistrettoPoint) -> Vec<u8> {
        t.compress().to_bytes().to_vec()
    }

    fn convert_from(bytes: &[u8]) -> Result<RistrettoPoint, Box<dyn Error>> {
        let compressed = CompressedRistretto::from_slice(bytes);
        compressed?.decompress().ok_or_else(|| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Failed to decompress RistrettoPoint",
            )) as Box<dyn Error>
        })
    }
}

// Implementation of `RandomGenerator` trait for `Scalar`.
impl RandomGenerator<Scalar> for Scalar {
    /// Generates a random `Scalar`.
    ///
    /// # Returns
    /// A `Result` containing the random `Scalar`, or an error if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the conversion from bytes to `Scalar` fails.
    fn generate_random() -> Result<Scalar, Box<dyn Error>> {
        Ok(Scalar::random(&mut OsRng))
    }
}

// Implementation of `RandomGenerator` trait for `RistrettoPoint`.
impl RandomGenerator<RistrettoPoint> for RistrettoPoint {
    /// Generates a random `RistrettoPoint`.
    ///
    /// # Returns
    /// A `Result` containing the random `RistrettoPoint`, or an error if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the conversion from bytes to `RistrettoPoint` fails.
    fn generate_random() -> Result<RistrettoPoint, Box<dyn std::error::Error>> {
        Ok(RistrettoPoint::random(&mut OsRng))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::chaum_pedersen::constants::EC25519_GROUP_PARAMS;
    use crate::chaum_pedersen::test::test_execute_protocol;
    use crate::rand::RandomGenerator;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::CompressedRistretto;

    // Test case to ensure round-trip conversion for `RistrettoPoint`.
    #[test]
    fn ristretto_point_conversion_round_trip() {
        let original = RISTRETTO_BASEPOINT_POINT * Scalar::generate_random().unwrap();
        let bytes = RistrettoPoint::convert_to(&original);
        let recovered = RistrettoPoint::convert_from(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    fn serialize_ristretto_point(point: &RistrettoPoint) -> String {
        // Compress the RistrettoPoint
        let compressed_point = point.compress();

        // Convert the CompressedRistretto to a byte array
        let bytes = compressed_point.to_bytes();

        // Convert the byte array to a hex string
        hex::encode(bytes)
    }

    /// Tests the commitment calculation in the Elliptic Curve Chaum-Pedersen protocol.
    #[test]
    fn test_elliptic_curve_commitment() {
        // Initializing random number generator.
        let mut rng = OsRng;
        // Creating a secret value x.
        let x = Scalar::from(3u32);
        // Generating random points g and h on the Ristretto curve.
        let g = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
        let h = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);

        // Serializing and printing the points g and h.
        let hex_str = serialize_ristretto_point(&g);
        println!("Serialized point: {}", hex_str);
        let hex_str = serialize_ristretto_point(&h);
        println!("Serialized point: {}", hex_str);

        // Setting up the group parameters.
        let params = GroupParams::<RistrettoPoint> {
            g: g.clone(),
            h: h.clone(),
            p: RISTRETTO_BASEPOINT_POINT,
            q: RISTRETTO_BASEPOINT_POINT,
        };

        // Calculating the commitment.
        let (cp, _) = Curve25519ChaumPedersen::commitment(&params, &x);
        let (y1, y2, _, _) = cp;

        // Verifying the correctness of the commitment.
        assert_eq!(y1, params.g * x);
        assert_eq!(y2, params.h * x);
    }

    /// Tests the verification process in the Elliptic Curve Chaum-Pedersen protocol.
    #[test]
    fn test_elliptic_curve_random_point_verification() {
        // Initializing random number generator.
        let mut rng = OsRng;
        // Creating a secret value x.
        let x = Scalar::from(3u32);
        // Generating random points g and h on the Ristretto curve.
        let g = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);
        let h = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng);

        // Setting up the group parameters.
        let params = GroupParams::<RistrettoPoint> {
            g: g.clone(),
            h: h.clone(),
            p: RISTRETTO_BASEPOINT_POINT,
            q: RISTRETTO_BASEPOINT_POINT,
        };

        // Executing the protocol and asserting the verification is successful.
        assert!(test_execute_protocol::<Curve25519ChaumPedersen>(&params, &x));
    }

    #[test]
    fn test_elliptic_curve_standard_verification() {
        // Initializing random number generator.
        // Creating a secret value x.
        let x = Scalar::from(3u32);
        // Setting up the group parameters.
        let params = EC25519_GROUP_PARAMS.to_owned();

        // Executing the protocol and asserting the verification is successful.
        assert!(test_execute_protocol::<Curve25519ChaumPedersen>(&params, &x));
    }

    #[test]
    fn test_fail_elliptic_curve_verification() {
        let mut rng = OsRng;
        // Setting up the group parameters.
        let params = EC25519_GROUP_PARAMS.to_owned();
        let x = Scalar::random(&mut rng);

        let (cp, _) = Curve25519ChaumPedersen::commitment(&params, &x);
        let c = Curve25519ChaumPedersen::challenge(&params);
        let fake_response = Scalar::generate_random().unwrap();
        let verified = Curve25519ChaumPedersen::verify(&params, &fake_response, &c, &cp);
        assert!(!verified);
    }

    #[test]
    fn test_fail_elliptic_curve_verification_with_ec_params() {
        let mut rng = OsRng;
        // Setting up the group parameters.
        let params = EC25519_GROUP_PARAMS.to_owned();
        // Creating a secret value x.
        let x = Scalar::random(&mut rng);

        let (cp, _) = Curve25519ChaumPedersen::commitment(&params, &x);
        let c = Curve25519ChaumPedersen::challenge(&params);
        let fake_response = Scalar::generate_random().unwrap();
        let verified = Curve25519ChaumPedersen::verify(&params, &fake_response, &c, &cp);
        assert!(!verified);
    }

    /// Tests the serialization and deserialization of Ristretto points, simulating sending over a wire.
    #[test]
    fn test_wire_serialization() {
        // Generating a random scalar and a random Ristretto point.
        let scalar = Scalar::random(&mut rand::thread_rng());
        let point = RistrettoPoint::random(&mut rand::thread_rng());
        // Multiplying the point by the scalar.
        let compressed_point = point * scalar;

        // Converting the point to bytes for sending.
        let bytes_to_send = compressed_point.compress().to_bytes();

        // Simulating sending bytes across the wire.
        let received_bytes = bytes_to_send;

        // On the receiving end, deserializing the bytes back into a CompressedRistretto.
        let received_compressed_point = CompressedRistretto::from_slice(&received_bytes);

        // Optionally, decompressing it back to a RistrettoPoint if needed.
        let received_point = received_compressed_point
            .unwrap()
            .decompress()
            .expect("Invalid point received");

        // Asserting that the received point is equal to the original compressed point.
        assert_eq!(received_point, compressed_point);
    }

    // Test case to ensure round-trip conversion for `Scalar`.
    #[test]
    fn scalar_conversion_round_trip() {
        let original = Scalar::generate_random().unwrap();
        let bytes = Scalar::convert_to(&original);
        let recovered = Scalar::convert_from(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

     // Test case to check for proper error handling with invalid byte length for `Scalar`.
     #[test]
     fn scalar_invalid_bytes_length() {
         let bytes: Vec<u8> = vec![0; 64]; // Invalid length for Scalar conversion
         let result = Scalar::convert_from(&bytes);
         assert!(result.is_err());
     }
}
