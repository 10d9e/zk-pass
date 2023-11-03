use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use num_bigint::BigUint;
use pasta_curves::group::ff::{FromUniformBytes, PrimeField};
use pasta_curves::{pallas, vesta};
use std::error::Error;
use pasta_curves::group::GroupEncoding;

/// A trait for converting types to and from byte representations.
///
/// This trait provides a common interface for types that can be converted
/// to a byte array and constructed back from a byte array. It is particularly
/// useful for cryptographic operations where serialization and deserialization
/// of objects like points on an elliptic curve or scalars are needed.
pub trait ByteConvertible<T> {
    /// Converts the provided object to a byte array.
    ///
    /// # Arguments
    /// - `t`: A reference to the object to be converted.
    ///
    /// # Returns
    /// A `Vec<u8>` representing the byte array of the object.
    fn convert_to(t: &T) -> Vec<u8>;

    /// Constructs an object from a byte array.
    ///
    /// # Arguments
    /// - `bytes`: A slice of bytes from which the object should be constructed.
    ///
    /// # Returns
    /// A `Result` which is `Ok` containing the constructed object if successful,
    /// or an `Err` containing an error if the conversion failed.
    fn convert_from(bytes: &[u8]) -> Result<T, Box<dyn Error>>
    where
        Self: Sized;
}

/// Implementation of `ByteConvertible` for `BigUint`.
///
/// This implementation provides methods to convert `BigUint` objects to and from
/// byte arrays, using big-endian byte order.
impl ByteConvertible<BigUint> for BigUint {
    fn convert_to(t: &BigUint) -> Vec<u8> {
        t.to_bytes_be()
    }

    fn convert_from(bytes: &[u8]) -> Result<BigUint, Box<dyn Error>> {
        Ok(BigUint::from_bytes_be(bytes))
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

impl ByteConvertible<pallas::Point> for pallas::Point {
    fn convert_to(t: &pallas::Point) -> Vec<u8> {
        t.to_bytes().to_vec()
    }

    fn convert_from(bytes: &[u8]) -> Result<pallas::Point, Box<dyn Error>> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid bytes length for Scalar",
            ))
        })?;
        
        Ok(pallas::Point::from_bytes(&array).unwrap())
    }
}

impl ByteConvertible<pallas::Scalar> for pallas::Scalar {
    fn convert_to(t: &pallas::Scalar) -> Vec<u8> {
        t.to_repr().as_slice().to_vec()
    }

    fn convert_from(bytes: &[u8]) -> Result<pallas::Scalar, Box<dyn Error>> {
        // pad the array with zeros
        let array = |input: &[u8]| -> [u8; 64] {
            let mut output = [0u8; 64];
            let len = input.len().min(64);
            output[..len].copy_from_slice(&input[..len]);
            output // Return the new array
        };
        Ok(pallas::Scalar::from_uniform_bytes(&array(bytes)))
    }
}

impl ByteConvertible<vesta::Point> for vesta::Point {
    fn convert_to(t: &vesta::Point) -> Vec<u8> {
        t.to_bytes().to_vec()
    }

    fn convert_from(bytes: &[u8]) -> Result<vesta::Point, Box<dyn Error>> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid bytes length for Scalar",
            ))
        })?;
        
        Ok(vesta::Point::from_bytes(&array).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::RandomGenerator;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use num_bigint::ToBigUint;

    // Test case to ensure round-trip conversion for `BigUint`.
    #[test]
    fn biguint_conversion_round_trip() {
        let original = 123456789u64.to_biguint().unwrap();
        let bytes = BigUint::convert_to(&original);
        let recovered = BigUint::convert_from(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    // Test case to ensure round-trip conversion for `RistrettoPoint`.
    #[test]
    fn ristretto_point_conversion_round_trip() {
        let original = RISTRETTO_BASEPOINT_POINT * Scalar::generate_random().unwrap();
        let bytes = RistrettoPoint::convert_to(&original);
        let recovered = RistrettoPoint::convert_from(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    // Test case to ensure round-trip conversion for `Scalar`.
    #[test]
    fn scalar_conversion_round_trip() {
        let original = Scalar::generate_random().unwrap();
        let bytes = Scalar::convert_to(&original);
        let recovered = Scalar::convert_from(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn pallas_point_conversion_round_trip() {
        let original = pallas::Point::generate_random().unwrap();
        let bytes = pallas::Point::convert_to(&original);
        let recovered = pallas::Point::convert_from(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn pallas_scalar_conversion_round_trip() {
        let original = pallas::Scalar::generate_random().unwrap();
        let bytes = pallas::Scalar::convert_to(&original);
        let recovered = pallas::Scalar::convert_from(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn vesta_point_conversion_round_trip() {
        let original = vesta::Point::generate_random().unwrap();
        let bytes = vesta::Point::convert_to(&original);
        let recovered = vesta::Point::convert_from(&bytes).unwrap();
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
