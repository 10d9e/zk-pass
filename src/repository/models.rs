/// Represents a user within the system.
///
/// This struct is generic over `T`, allowing for flexibility in the type of data associated with a user.
///
/// # Fields
/// - `username`: A `String` representing the username of the user.
/// - `y1`: A generic field of type `T`.
/// - `y2`: Another generic field of type `T`.
/// - `r1`: An `Option<T>` representing an optional field of type `T`.
/// - `r2`: Another `Option<T>` representing an optional field of type `T`.
#[derive(Debug, Clone)]
pub struct User<T> {
    pub username: String,
    pub y1: T,
    pub y2: T,
    pub r1: Option<T>,
    pub r2: Option<T>,
}

/// Represents an authentication challenge for a user.
///
/// This struct is generic over `S`, allowing different types of challenges to be used.
///
/// # Fields
/// - `id`: A `String` representing the unique identifier of the challenge.
/// - `user`: A `String` representing the username of the user this challenge is associated with.
/// - `c`: A generic field of type `S` representing the challenge data.
#[derive(Debug, Clone)]
pub struct AuthChallenge<S> {
    pub id: String,
    pub user: String,
    pub c: S,
}
