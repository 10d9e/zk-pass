/// This module defines various constants used throughout the application. These may include cryptographic constants, default values, or other static data that are integral to the operation of the system.
pub mod constants;

/// This module provides functionality related to the Curve25519 elliptic curve, often used in cryptographic operations, particularly in the elliptic curve implementation of the Chaum-Pedersen protocol.
pub mod curve25519;

/// This module focuses on the discrete logarithm problem and related cryptographic operations. It is particularly relevant for the discrete log implementation of the Chaum-Pedersen protocol.
pub mod discretelog;

/// A module dedicated to testing various components of the application. It includes test cases, utility functions for testing, and other resources needed to ensure the correctness and reliability of the system.
pub mod test;

/// A struct representing group parameters in cryptographic protocols.
///
/// This struct is generic over a type `T`, allowing flexibility in the types of the parameters.
/// It's typically used in cryptographic protocols like Chaum-Pedersen where specific group parameters are required.
#[derive(Copy, Clone, Debug)]
pub struct GroupParams<T> {
    /// The generator `g` of the group.
    pub g: T,
    /// An additional generator `h` of the group, ensuring it's independent from `g`.
    pub h: T,
    /// The prime modulus `p` defining the size of the group.
    pub p: T,
    /// The order `q` of the subgroup generated by `g` and `h`.
    pub q: T,
}

/// A trait defining the interface for the Chaum-Pedersen zero-knowledge protocol.
///
/// This trait provides the necessary methods for implementing the Chaum-Pedersen protocol,
/// which is a cryptographic protocol for proving knowledge of a secret without revealing it.
pub trait ChaumPedersen {
    /// The type representing the secret to be proven.
    type Secret;
    /// The type representing the response in the protocol.
    type Response;
    /// The type representing the challenge in the protocol.
    type Challenge;
    /// The type representing the group parameters used in the protocol.
    type GroupParameters;
    /// The type representing the commitment parameters in the protocol.
    type CommitParameters;
    /// The type representing the commitment randomness in the protocol.
    type CommitmentRandom;

    /// Calculates the commitment in the Chaum-Pedersen protocol.
    ///
    /// # Arguments
    /// * `params` - Group parameters used in the protocol.
    /// * `x` - The secret value for which the commitment is calculated.
    ///
    /// # Returns
    /// A tuple containing the commitment parameters and the commitment randomness.
    fn commitment(
        params: &Self::GroupParameters, x: &Self::Secret,
    ) -> (Self::CommitParameters, Self::CommitmentRandom)
    where
        Self: Sized;

    /// Generates a challenge in the Chaum-Pedersen protocol.
    ///
    /// # Arguments
    /// * `params` - Group parameters used in the protocol.
    ///
    /// # Returns
    /// The challenge value used in the protocol.
    fn challenge(params: &Self::GroupParameters) -> Self::Challenge
    where
        Self: Sized;

    /// Calculates the challenge response in the Chaum-Pedersen protocol.
    ///
    /// # Arguments
    /// * `params` - Group parameters used in the protocol.
    /// * `k` - The commitment randomness used in the protocol.
    /// * `c` - The challenge value used in the protocol.
    /// * `x` - The secret value for which the response is calculated.
    ///
    /// # Returns
    /// The response value in the protocol.
    fn challenge_response(
        params: &Self::GroupParameters, k: &Self::CommitmentRandom, c: &Self::Challenge,
        x: &Self::Secret,
    ) -> Self::Response
    where
        Self: Sized;

    /// Verifies the response in the Chaum-Pedersen protocol.
    ///
    /// # Arguments
    /// * `params` - Group parameters used in the protocol.
    /// * `s` - The response value to be verified.
    /// * `c` - The challenge value used in the protocol.
    /// * `cp` - The commitment parameters used in the protocol.
    ///
    /// # Returns
    /// A boolean indicating whether the verification was successful.
    fn verify(
        params: &Self::GroupParameters, s: &Self::Response, c: &Self::Challenge,
        cp: &Self::CommitParameters,
    ) -> bool
    where
        Self: Sized;
}
