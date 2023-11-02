use tonic::codegen::StdError;
use tonic::transport::Channel;

use crate::chaum_pedersen::GroupParams;
use crate::chaum_pedersen::ChaumPedersen;
use crate::conversion::ByteConvertible;
use std::error::Error;

/// A module that contains the auto-generated gRPC code for the Zero-Knowledge Proof (ZKP) authentication service.
pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

// Importing specific structures from the `zkp_auth` module.
use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    RegisterRequest,
};

/// A client library for interacting with the ZKP authentication service.
///
/// This struct encapsulates the functionality for connecting to the service and performing
/// operations like user registration and authentication.
pub struct AuthClientLib {
    /// The gRPC client for the ZKP authentication service.
    client: AuthClient<Channel>,
}

impl AuthClientLib {
    /// Connects to the ZKP authentication service.
    ///
    /// # Arguments
    /// * `dst` - The destination where the ZKP authentication service is hosted.
    ///
    /// # Returns
    /// A result containing the `AuthClientLib` instance if the connection is successful,
    /// or an error if the connection fails.
    pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
    where
        D: std::convert::TryInto<tonic::transport::Endpoint>,
        D::Error: Into<StdError>,
    {
        let client = AuthClient::connect(dst).await?;
        Ok(Self { client })
    }

    /// Registers a new user with the ZKP authentication service.
    ///
    /// # Arguments
    /// * `user` - The username of the user to be registered.
    /// * `y1` - The first part of the user's cryptographic credential.
    /// * `y2` - The second part of the user's cryptographic credential.
    ///
    /// # Returns
    /// A result indicating success or an error if the registration fails.
    pub async fn register(
        &mut self, user: String, y1: Vec<u8>, y2: Vec<u8>,
    ) -> Result<(), tonic::Status> {
        let request = RegisterRequest { user, y1, y2 };
        self.client.register(request).await?;
        Ok(())
    }

    /// Creates an authentication challenge for a user.
    ///
    /// # Arguments
    /// * `user` - The username of the user for whom the challenge is being created.
    /// * `r1` - The first part of the randomness used in the challenge.
    /// * `r2` - The second part of the randomness used in the challenge.
    ///
    /// # Returns
    /// A result containing the challenge and an authentication ID if successful,
    /// or an error if the operation fails.
    pub async fn create_authentication_challenge(
        &mut self, user: String, r1: Vec<u8>, r2: Vec<u8>,
    ) -> Result<(Vec<u8>, String), tonic::Status> {
        let request = AuthenticationChallengeRequest { user, r1, r2 };
        let response = self.client.create_authentication_challenge(request).await?;
        let inner = response.into_inner();
        Ok((inner.c, inner.auth_id))
    }

    /// Verifies an authentication challenge for a user.
    ///
    /// # Arguments
    /// * `auth_id` - The authentication ID associated with the challenge.
    /// * `s` - The user's response to the challenge.
    ///
    /// # Returns
    /// A result containing a session ID if the verification is successful,
    /// or an error if the verification fails.
    pub async fn verify_authentication(
        &mut self, auth_id: String, s: Vec<u8>,
    ) -> Result<String, tonic::Status> {
        let request = AuthenticationAnswerRequest { auth_id, s };
        let response = self.client.verify_authentication(request).await?;
        Ok(response.into_inner().session_id)
    }
}

/// Executes the Chaum-Pedersen protocol for client authentication.
///
/// This function handles the client side of the Chaum-Pedersen protocol, including
/// registering the commitment, creating an authentication challenge, and verifying
/// the authentication response.
///
/// # Type Parameters
/// * `T`: The type of Chaum-Pedersen protocol (either Discrete Log or Elliptic Curve).
/// * `P`: The type of the group parameters (either `BigUint` for Discrete Log or `RistrettoPoint` for Elliptic Curve).
/// * `S`: The type of the response and challenge (usually `BigUint`).
///
/// # Arguments
/// * `params` - Group parameters for the cryptographic operations.
/// * `x` - The secret value used in the protocol.
/// * `user` - The username for authentication.
/// * `client` - The client object for communication with the ZKPass server.
///
/// # Returns
/// Returns a `Result` which is `Ok(())` on successful execution or an error
/// if any part of the process fails.
pub async fn execute_protocol<T, P, S>(
    params: &GroupParams<P>, x: &T::Secret, user: &String, client: &mut AuthClientLib,
) -> Result<(), Box<dyn Error>>
where
    T: ChaumPedersen<
        GroupParameters = GroupParams<P>,
        CommitParameters = (P, P, P, P),
        Response = S,
        Challenge = S,
    >,
    P: ByteConvertible<P>,
    S: ByteConvertible<S>,
{
    // Client calculates the commitment.
    let ((y1, y2, r1, r2), k) = T::calculate_commitment(params, x);

    // Registers the commitment with the server.
    client
        .register(user.clone(), P::to_bytes(&y1), P::to_bytes(&y2))
        .await?;

    // Creates an authentication challenge.
    let (c, auth_id) = client
        .create_authentication_challenge(user.clone(), P::to_bytes(&r1), P::to_bytes(&r2))
        .await?;

    // Converts the challenge from bytes to the appropriate type.
    let challenge = S::from_bytes(&c)?;

    // Calculates the response to the challenge.
    let s = T::calculate_response(&params, &k, &challenge, &x);

    // Sends the response to the server and receives a session ID.
    let session_id = client
        .verify_authentication(auth_id, S::to_bytes(&s))
        .await?;

    // Displays the session ID.
    println!("🔑 Authentication successful! 🔑");
    println!("Session ID: {}", session_id);

    // The server verifies the authentication attempt.
    T::verify(&params, &s, &challenge, &(y1, y2, r1, r2));

    Ok(())
}
