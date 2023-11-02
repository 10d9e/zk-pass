// Importing necessary traits, structs, and modules.
use crate::conversion::ByteConvertible;
use crate::repository::dao::UserDao;
use crate::repository::models::User;
use std::collections::HashMap;
use uuid::Uuid;

use super::models::AuthChallenge;

/// A struct representing an in-memory User Data Access Object (DAO).
///
/// This struct provides an in-memory implementation of the `UserDao` trait,
/// storing user data and authentication challenges in hash maps.
///
/// # Type Parameters
/// - `T`: Type parameter for User related data.
/// - `S`: Type parameter for Authentication Challenge related data.
pub struct InMemoryUserDao<T, S> {
    users: HashMap<String, User<T>>,
    auth_challenges: HashMap<String, AuthChallenge<S>>,
}

impl<T, S> InMemoryUserDao<T, S> {
    /// Constructs a new instance of `InMemoryUserDao`.
    ///
    /// Initializes the internal hash maps for users and authentication challenges.
    pub fn new() -> Self {
        InMemoryUserDao {
            users: HashMap::new(),
            auth_challenges: HashMap::new(),
        }
    }
}

impl<T, S> UserDao<T, S> for InMemoryUserDao<T, S>
where
    T: Send + Sync + 'static + Clone + ByteConvertible<T>,
    S: Send + Sync + 'static + Clone + ByteConvertible<S>,
{
    /// Implements the `create` method for user data.
    ///
    /// Inserts the provided user into the internal users hash map.
    fn create(&mut self, user: User<T>) {
        self.users.insert(user.username.clone(), user);
    }

    /// Implements the `read` method for user data.
    ///
    /// Retrieves the user based on the provided username from the internal users hash map.
    fn read(&mut self, username: &str) -> Option<User<T>> {
        self.users.get(username).cloned()
    }

    /// Implements the `update` method for user data.
    ///
    /// Updates the user data based on the provided name.
    fn update(&mut self, name: &String, new_user: User<T>) -> Option<()> {
        if let Some(user) = self.users.get_mut(name) {
            *user = new_user;
            Some(())
        } else {
            None
        }
    }

    /// Implements the `delete` method for user data.
    ///
    /// Deletes the user based on the provided name from the internal users hash map.
    fn delete(&mut self, name: &String) -> Option<User<T>> {
        self.users.remove(name)
    }

    /// Implements the `create_auth_challenge` method.
    ///
    /// Creates and stores an authentication challenge for a user.
    fn create_auth_challenge(&mut self, user: &String, c: &S) -> String {
        let uid = Uuid::new_v4().to_string();
        let auth_challenge = AuthChallenge {
            id: uid.clone(),
            user: user.clone(),
            c: c.clone(),
        };
        self.auth_challenges.insert(uid.clone(), auth_challenge);
        uid
    }

    /// Implements the `delete_auth_challenge` method.
    ///
    /// Deletes an authentication challenge based on its ID.
    fn delete_auth_challenge(&mut self, id: &String) {
        self.auth_challenges.remove(id);
    }

    /// Implements the `get_authentication_challenge` method.
    ///
    /// Retrieves an authentication challenge based on its ID.
    fn get_authentication_challenge(&mut self, id: &String) -> Option<AuthChallenge<S>> {
        self.auth_challenges.get(id).cloned()
    }
}
