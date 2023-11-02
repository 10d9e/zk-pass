//! # Chaum-Pedersen Zero-Knowledge Interactive Proof Authentication Protocol
//!
//! This crate provides a comprehensive implementation of the Chaum-Pedersen zero-knowledge interactive proof authentication scheme. 
//! It is designed to facilitate secure and private authentication processes by leveraging the principles of zero-knowledge proofs.
//! This scheme allows a prover to convince a verifier that they know a secret without revealing the secret itself.
//!
//! ## Overview
//!
//! The Chaum-Pedersen authentication protocol is a zero-knowledge proof mechanism that enhances security in authentication processes. 
//! This crate offers a robust and efficient implementation of this protocol, suitable for scenarios where privacy and security are paramount.
//!
//! The primary components of this crate include:
//!
//! - **Server**: Provides the server-side functionality necessary for the Chaum-Pedersen authentication. 
//!   It includes the logic to handle authentication requests and validate proofs without ever knowing the client's secret.
//!
//! - **Client**: Implements the client-side logic for generating and sending zero-knowledge proofs to the server. 
//!   It ensures that the client's secret is never exposed during the authentication process.
//!
//! - **gRPC Integration**: The crate uses gRPC for communication between the client and the server. 
//!   This provides a robust, efficient, and language-agnostic way to handle remote procedure calls.
//!
//! ## Modules
//!
//! - `chaum_pedersen`: Core module that implements the Chaum-Pedersen zero-knowledge proof algorithm. 
//!   It contains the cryptographic primitives and logic for both the prover (client) and verifier (server).
//!
//! - `client`: Contains the implementation of the client-side logic for the authentication process. 
//!   It provides functions to generate zero-knowledge proofs and communicate with the server via gRPC.
//!
//! - `cmdutil`: Utility module that aids in command-line operations and parameter handling. 
//!   It simplifies the process of parsing command-line arguments and configuring the client or server.
//!
//! - `conversion`: Offers functionality to convert between different data types and formats. 
//!   This module is essential for handling cryptographic operations and data serialization/deserialization.
//!
//! - `rand`: Provides utilities for secure random number generation, which is a critical component in cryptographic operations.
//!
//! - `service`: Contains the gRPC service definitions and implementations. 
//!   It defines the remote procedure calls and their respective request and response structures.
//!
//! - `repository`: An internal module that may contain data storage and retrieval logic, potentially for managing user data or cryptographic keys.
//!
//! ## Usage
//!
//! This crate can be integrated into applications that require secure authentication mechanisms. 
//! By leveraging the Chaum-Pedersen protocol, it offers a high degree of privacy and security, ensuring that sensitive information remains confidential.
//!
//! ## Dependencies
//!
//! This crate relies on various cryptographic libraries and gRPC for its functionality. 
//! Ensure that all dependencies are properly installed and configured for seamless operation.
//!
//! ## Contributing
//!
//! Contributions are welcome. Please refer to the `CONTRIBUTING.md` file for guidelines on how to contribute to this project.
//!
//! ## License
//!
//! This project is licensed under the [MIT License](LICENSE).

/// Implements the Chaum-Pedersen zero-knowledge proof protocol.
pub mod chaum_pedersen;

/// Handles client-side operations and interactions.
pub mod client;

/// Utilities for command line argument parsing and handling.
pub mod cmdutil;

/// Functions for type conversions and data formatting.
pub mod conversion;

/// Cryptographically secure random number generation utilities.
pub mod rand;

/// Core services and business logic implementation.
pub mod service;

/// Data storage and retrieval mechanisms.
mod repository;
