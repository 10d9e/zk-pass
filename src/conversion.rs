use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use num_bigint::BigUint;
use std::error::Error;

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
    fn to_bytes(t: &T) -> Vec<u8>;

    /// Constructs an object from a byte array.
    ///
    /// # Arguments
    /// - `bytes`: A slice of bytes from which the object should be constructed.
    ///
    /// # Returns
    /// A `Result` which is `Ok` containing the constructed object if successful,
    /// or an `Err` containing an error if the conversion failed.
    fn from_bytes(bytes: &[u8]) -> Result<T, Box<dyn Error>> where Self: Sized;
}

/// Implementation of `ByteConvertible` for `BigUint`.
///
/// This implementation provides methods to convert `BigUint` objects to and from
/// byte arrays, using big-endian byte order.
impl ByteConvertible<BigUint> for BigUint {
    fn to_bytes(t: &BigUint) -> Vec<u8> {
        t.to_bytes_be()
    }

    fn from_bytes(bytes: &[u8]) -> Result<BigUint, Box<dyn Error>> {
        Ok(BigUint::from_bytes_be(bytes))
    }
}

/// Implementation of `ByteConvertible` for `RistrettoPoint`.
///
/// This implementation provides methods to convert `RistrettoPoint` objects to and from
/// byte arrays. It uses the compression and decompression features of the Ristretto group
/// to achieve this.
impl ByteConvertible<RistrettoPoint> for RistrettoPoint {
    fn to_bytes(t: &RistrettoPoint) -> Vec<u8> {
        t.compress().to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<RistrettoPoint, Box<dyn Error>> {
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
    fn to_bytes(t: &Scalar) -> Vec<u8> {
        t.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Scalar, Box<dyn Error>> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid bytes length for Scalar",
            )) as Box<dyn Error>
        })?;
        Ok(Scalar::from_bytes_mod_order(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use num_bigint::ToBigUint;
    use rand::rngs::OsRng;

    // Test case to ensure round-trip conversion for `BigUint`.
    #[test]
    fn biguint_conversion_round_trip() {
        let original = 123456789u64.to_biguint().unwrap();
        let bytes = BigUint::to_bytes(&original);
        let recovered = BigUint::from_bytes(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    // Test case to ensure round-trip conversion for `RistrettoPoint`.
    #[test]
    fn ristretto_point_conversion_round_trip() {
        let original = RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng);
        let bytes = RistrettoPoint::to_bytes(&original);
        let recovered = RistrettoPoint::from_bytes(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    // Test case to ensure round-trip conversion for `Scalar`.
    #[test]
    fn scalar_conversion_round_trip() {
        let original = Scalar::random(&mut OsRng);
        let bytes = Scalar::to_bytes(&original);
        let recovered = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    // Test case to check for proper error handling with invalid byte length for `Scalar`.
    #[test]
    fn scalar_invalid_bytes_length() {
        let bytes: Vec<u8> = vec![0; 64]; // Invalid length for Scalar conversion
        let result = Scalar::from_bytes(&bytes);
        assert!(result.is_err());
    }
}
