
use crate::chaum_pedersen::curve25519::EllipticCurveChaumPedersen;
use crate::conversion::ByteConvertible;
use crate::repository::daoimpl::InMemoryUserDao;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use num_bigint::BigUint;
use std::sync::Mutex;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use log::{debug, error, trace, info};

use crate::{
    chaum_pedersen::{
        discretelog::DiscreteLogChaumPedersen,
        ChaumPedersen, GroupParams,
    },
    repository::{dao::UserDao, models::User, session::update_session},
};

// Protobuf generated module
pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

// Protobuf imports
use zkp_auth::{
    auth_server::Auth, AuthenticationAnswerRequest, AuthenticationAnswerResponse,
    AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse,
};

/// A struct representing the zero-knowledge authentication service.
/// It supports different types of Chaum-Pedersen protocols.
///
/// # Type Parameters
///
/// * `C`: Represents the type of Chaum-Pedersen protocol.
/// * `T`: The type used for group elements.
/// * `S`: The type used for scalar values.
pub struct ZkAuth<C, T, S> {
    params: GroupParams<T>,
    dao: Mutex<Box<dyn UserDao<T, S> + Send + Sync>>,
    _type_phantom: std::marker::PhantomData<C>,
    _scalar_phantom: std::marker::PhantomData<S>,
}

// Implementations for different Chaum-Pedersen protocols
impl ZkAuth<DiscreteLogChaumPedersen, BigUint, BigUint> {
    /// Creates a new instance of `ZkAuth` using the Discrete Log Chaum-Pedersen protocol.
    pub fn new_discrete_log_chaum_pedersen(params: GroupParams<BigUint>) -> Self {
        let dao = Mutex::new(Box::new(InMemoryUserDao::<BigUint, BigUint>::new())
            as Box<dyn UserDao<BigUint, BigUint> + Send + Sync>);
        Self {
            params,
            dao,
            _type_phantom: std::marker::PhantomData,
            _scalar_phantom: std::marker::PhantomData,
        }
    }
}

impl ZkAuth<EllipticCurveChaumPedersen, RistrettoPoint, Scalar> {
    /// Creates a new instance of `ZkAuth` using the Elliptic Curve Chaum-Pedersen protocol.
    pub fn new_elliptic_curve_chaum_pedersen(params: GroupParams<RistrettoPoint>) -> Self {
        let dao = Mutex::new(Box::new(InMemoryUserDao::<RistrettoPoint, Scalar>::new())
            as Box<dyn UserDao<RistrettoPoint, Scalar> + Send + Sync>);
        Self {
            params,
            dao,
            _type_phantom: std::marker::PhantomData,
            _scalar_phantom: std::marker::PhantomData,
        }
    }
}

/// Implementation of the `Auth` trait for `ZkAuth`.
///
/// This implementation provides the necessary methods for user registration,
/// creating authentication challenges, and verifying authentication answers.
/// It uses generic parameters `C`, `T`, and `S` to work with different cryptographic protocols and data types.
///
/// `C` represents a specific Chaum-Pedersen protocol implementation.
/// `T` is the type for group parameters and public information.
/// `S` is the scalar type used for cryptographic operations.
#[tonic::async_trait]
impl<C, T, S> Auth for ZkAuth<C, T, S>
where
    T: Send + Sync + 'static + Clone + ByteConvertible<T>,
    S: Send + Sync + 'static + Clone + ByteConvertible<S>,
    C: ChaumPedersen<
            Response = S,
            CommitmentRandom = S,
            Challenge = S,
            Secret = S,
            GroupParameters = GroupParams<T>,
            CommitParameters = (T, T, T, T),
        >
        + 'static
        + std::marker::Sync
        + std::marker::Send,
{
    // Register a user with provided credentials.
    // This method accepts a `RegisterRequest` and returns a `RegisterResponse`.
    //
    // # Arguments
    // * `request` - A `Request<RegisterRequest>` containing the user's registration information.
    //
    // # Returns
    // A `Result` containing a `Response<RegisterResponse>` on success, or a `Status` error on failure.
    async fn register(
        &self, request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        trace!("register: {:?}", request);
        let req = request.into_inner();

        let y1 = T::from_bytes(&req.y1).or_else(|_| Err(Status::invalid_argument("Invalid y1")))?;
        let y2 = T::from_bytes(&req.y2).or_else(|_| Err(Status::invalid_argument("Invalid y2")))?;

        let user = User {
            username: req.user.clone(),
            y1,
            y2,
            r1: None,
            r2: None,
        };

        {
            let mut dao = self.dao.lock().unwrap();
            dao.create(user);
        }

        let reply = RegisterResponse {};
        trace!("register reply: {:?}", reply);
        Ok(Response::new(reply))
    }

    // Create an authentication challenge for a user.
    // This method accepts an `AuthenticationChallengeRequest` and returns an `AuthenticationChallengeResponse`.
    //
    // # Arguments
    // * `request` - A `Request<AuthenticationChallengeRequest>` containing the user's information.
    //
    // # Returns
    // A `Result` containing a `Response<AuthenticationChallengeResponse>` on success, or a `Status` error on failure.
    async fn create_authentication_challenge(
        &self, request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        trace!("create_authentication_challenge request: {:?}", request);
        let req = request.into_inner();
        let challenge = C::challenge(&self.params);

        let user = {
            //let mut dao = USER_DAO.lock().unwrap();
            let mut dao = self.dao.lock().unwrap();
            let mut user = dao
                .read(&req.user)
                .ok_or_else(|| Status::not_found("User not found"))?;
            user.r1 = Some(
                T::from_bytes(&req.r1).or_else(|_| Err(Status::invalid_argument("Invalid r1")))?,
            );
            user.r2 = Some(
                T::from_bytes(&req.r2).or_else(|_| Err(Status::invalid_argument("Invalid r2")))?,
            );
            user.clone()
        };

        let auth_id = {
            let mut dao = self.dao.lock().unwrap();
            dao.update(&user.username, user.clone());
            dao.create_auth_challenge(&req.user, &challenge)
        };

        let reply = AuthenticationChallengeResponse {
            auth_id,
            c: S::to_bytes(&challenge),
        };
        trace!("create_authentication_challenge reply: {:?}", reply);
        Ok(Response::new(reply))
    }

    // Verify an authentication challenge answer from a user.
    // This method accepts an `AuthenticationAnswerRequest` and returns an `AuthenticationAnswerResponse`.
    //
    // # Arguments
    // * `request` - A `Request<AuthenticationAnswerRequest>` containing the user's authentication answer.
    //
    // # Returns
    // A `Result` containing a `Response<AuthenticationAnswerResponse>` on success, or a `Status` error on failure.
    async fn verify_authentication(
        &self, request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        trace!("verify_authentication: {:?}", request);
        let req = request.into_inner();

        let challenge = {
            let mut dao = self.dao.lock().unwrap();
            dao.get_authentication_challenge(&req.auth_id)
                .ok_or_else(|| Status::not_found("Challenge not found"))?
        };

        let user = {
            let mut dao = self.dao.lock().unwrap();
            dao.read(&challenge.user)
                .ok_or_else(|| Status::not_found("User not found"))?
        };

        let s = S::from_bytes(&req.s).or_else(|_| Err(Status::invalid_argument("Invalid s")))?;
        let params = self.params.clone();
        let verified = C::verify(
            &params,
            &s,
            &challenge.c,
            &(user.y1, user.y2, user.r1.unwrap(), user.r2.unwrap()),
        );

        debug!("User: {} verified", user.username);
        if !verified {
            error!("Invalid authentication for user: {}", user.username);
            return Err(Status::invalid_argument("Invalid authentication"));
        }
        let session_id = Uuid::new_v4().to_string();
        update_session(user.username.clone(), session_id.clone()); // Clone session_id before moving it
        let reply = AuthenticationAnswerResponse { session_id };

        {
            let mut dao = self.dao.lock().unwrap();
            dao.delete_auth_challenge(&req.auth_id);
        }

        info!("🔑 User: {} authenticated, session id: {}", user.username, req.auth_id);
        trace!("verify_authentication reply: {:?}", reply);
        Ok(Response::new(reply))
    }
}
