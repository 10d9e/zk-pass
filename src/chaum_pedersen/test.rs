use crate::chaum_pedersen::ChaumPedersen;

/// Executes the Chaum-Pedersen protocol using a generic implementation.
///
/// This function demonstrates a typical execution flow of the Chaum-Pedersen
/// cryptographic protocol. It encapsulates the roles of both the client and
/// the server, illustrating the generation of commitment, challenge, response,
/// and the verification process.
///
/// The function is generic over a type `T` that implements the `ChaumPedersen`
/// trait, allowing it to work with any specific cryptographic scheme that
/// conforms to the protocol.
///
/// # Arguments
/// * `params` - Reference to the group parameters. These parameters are essential
///   for the cryptographic operations and depend on the specific implementation
///   of the Chaum-Pedersen protocol.
/// * `x` - Reference to the secret value. This is the secret that the client
///   wants to prove knowledge of without revealing it.
///
/// # Type Parameters
/// * `T` - A type that implements the `ChaumPedersen` trait. This type dictates
///   the specifics of the cryptographic operations used in the protocol.
///
/// # Returns
/// Returns a boolean indicating whether the verification was successful. A value
/// of `true` means that the client successfully proved knowledge of the secret
/// without revealing it, while `false` indicates a failure in the protocol execution.
///
/// # Example
/// ```
/// // Assume `EllipticCurveChaumPedersen` implements `ChaumPedersen`.
/// let params = EllipticCurveChaumPedersen::default_group_parameters();
/// let secret = EllipticCurveChaumPedersen::generate_secret();
///
/// let result = execute_protocol::<EllipticCurveChaumPedersen>(&params, &secret);
/// assert_eq!(result, true);
/// ```
pub fn execute_protocol<T>(params: &T::GroupParameters, x: &T::Secret) -> bool
where
    T: ChaumPedersen,
{
    // The client calculates the commitment using their secret and the group parameters.
    let (cp, k) = T::calculate_commitment(params, x);

    // The server (simulated here) sends a challenge to the client.
    let c = T::challenge(params);

    // The client calculates the response based on the commitment random, challenge,
    // and their secret.
    let s = T::calculate_response(params, &k, &c, &x);

    // The server (simulated here) verifies the response against the challenge and
    // commitment parameters.
    T::verify(params, &s, &c, &cp)
}
