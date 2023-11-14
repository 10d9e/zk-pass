
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
