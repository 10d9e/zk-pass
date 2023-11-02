// Importing necessary structs from the repository's models module.
use crate::repository::models::AuthChallenge;
use crate::repository::models::User;

/// Trait defining the operations for User Data Access Object (DAO).
///
/// This trait abstracts the CRUD (Create, Read, Update, Delete) operations
/// and authentication challenge related operations for user data.
///
/// # Type Parameters
/// - `T`: Type parameter for User related data.
/// - `S`: Type parameter for Authentication Challenge related data.
pub trait UserDao<T, S> {
    /// Creates a new user.
    ///
    /// # Arguments
    /// * `user` - User object to be created.
    fn create(&mut self, user: User<T>);

    /// Reads user data based on the provided username.
    ///
    /// # Arguments
    /// * `username` - The username for which user data is to be retrieved.
    ///
    /// # Returns
    /// An `Option` containing the `User` if found, or `None` if not.
    fn read(&mut self, username: &str) -> Option<User<T>>;

    /// Updates the user data.
    ///
    /// # Arguments
    /// * `name` - The name of the user to be updated.
    /// * `user` - The new user data to update.
    ///
    /// # Returns
    /// An `Option` containing `()` if the operation was successful, or `None` if not.
    fn update(&mut self, name: &String, user: User<T>) -> Option<()>;

    /// Deletes a user based on the provided name.
    ///
    /// # Arguments
    /// * `name` - The name of the user to be deleted.
    ///
    /// # Returns
    /// An `Option` containing the deleted `User` if successful, or `None` if not.
    fn delete(&mut self, name: &String) -> Option<User<T>>;

    /// Creates an authentication challenge for a user.
    ///
    /// # Arguments
    /// * `user` - The user for whom the authentication challenge is being created.
    /// * `c` - The challenge data.
    ///
    /// # Returns
    /// A `String` representing the created authentication challenge.
    fn create_auth_challenge(&mut self, user: &String, c: &S) -> String;

    /// Deletes an authentication challenge based on its ID.
    ///
    /// # Arguments
    /// * `id` - The ID of the authentication challenge to be deleted.
    fn delete_auth_challenge(&mut self, id: &String);

    /// Retrieves an authentication challenge based on its ID.
    ///
    /// # Arguments
    /// * `id` - The ID of the authentication challenge to be retrieved.
    ///
    /// # Returns
    /// An `Option` containing the `AuthChallenge` if found, or `None` if not.
    fn get_authentication_challenge(&mut self, id: &String) -> Option<AuthChallenge<S>>;
}
