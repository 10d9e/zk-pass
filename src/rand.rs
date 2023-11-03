use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use num_bigint::BigUint;
use pasta_curves::group::ff::Field;
use pasta_curves::Fq;
use pasta_curves::Eq;
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;
use pasta_curves::group::Group;
use pasta_curves::Ep;
use pasta_curves::Fp;

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
    fn generate_random() -> Result<T, Box<dyn Error>>;
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
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Ok(BigUint::from_bytes_be(&bytes))
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

// Implementation of `RandomGenerator` trait for `Fq`.
impl RandomGenerator<Fq> for Fq {
    /// Generates a random `Fq`.
    ///
    /// # Returns
    /// A `Result` containing the random `Fq`, or an error if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the conversion from bytes to `Fq` fails.
    fn generate_random() -> Result<Fq, Box<dyn std::error::Error>> {
        Ok(Fq::random(&mut OsRng))
    }
}

impl RandomGenerator<Eq> for Eq {
    /// Generates a random `Fq`.
    ///
    /// # Returns
    /// A `Result` containing the random `Fq`, or an error if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the conversion from bytes to `Fq` fails.
    fn generate_random() -> Result<Eq, Box<dyn std::error::Error>> {
        Ok(Eq::random(&mut OsRng))
    }
}

impl RandomGenerator<Ep> for Ep {
    /// Generates a random `Ep`.
    ///
    /// # Returns
    /// A `Result` containing the random `Ep`, or an error if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the conversion from bytes to `Ep` fails.
    fn generate_random() -> Result<Ep, Box<dyn std::error::Error>> {
        Ok(Ep::random(&mut OsRng))
    }
}

impl RandomGenerator<Fp> for Fp {
    /// Generates a random `Fp`.
    ///
    /// # Returns
    /// A `Result` containing the random `Fp`, or an error if the generation fails.
    ///
    /// # Errors
    /// Returns an error if the conversion from bytes to `Fp` fails.
    fn generate_random() -> Result<Fp, Box<dyn std::error::Error>> {
        Ok(Fp::random(&mut OsRng))
    }
}
