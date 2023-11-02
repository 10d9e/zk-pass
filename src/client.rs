use tonic::codegen::StdError;
use tonic::transport::Channel;

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
