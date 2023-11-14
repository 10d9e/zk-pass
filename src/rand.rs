use std::error::Error;

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
