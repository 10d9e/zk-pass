use crate::conversion::ByteConvertible;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use num_bigint::BigUint;
use rand::RngCore;

/// Defines a trait for generating random values of a given type.
///
/// This trait is intended to abstract the generation of random values
/// for different types, providing a uniform interface.
pub trait RandomGenerator<T> {
    /// Generates a random value of type `T`.
    ///
    /// # Returns
    /// A `Result` containing the random value of type `T`, or an error
    /// if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the random value generation fails.
    fn generate_random() -> Result<T, Box<dyn std::error::Error>>;
}

// Implementation of `RandomGenerator` trait for `BigUint`.
impl RandomGenerator<BigUint> for BigUint {
    /// Generates a random `BigUint`.
    ///
    /// # Returns
    /// A `Result` containing the random `BigUint`, or an error if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the conversion from bytes to `BigUint` fails.
    fn generate_random() -> Result<BigUint, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        BigUint::from_bytes(&bytes)
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
    fn generate_random() -> Result<Scalar, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes(&bytes)
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
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        RistrettoPoint::from_bytes(&bytes)
    }
}
