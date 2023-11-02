use curve25519_dalek::{RistrettoPoint, Scalar};
use num_bigint::BigUint;
use sha2::{Digest, Sha512};
use std::str::FromStr;
use structopt::StructOpt;
use strum::VariantNames;
use zk_pass::conversion::ByteConvertible;

use std::error::Error;
use zk_pass::chaum_pedersen::GroupParams;
use zk_pass::chaum_pedersen::{
    curve25519::EllipticCurveChaumPedersen, discretelog::DiscreteLogChaumPedersen, ChaumPedersen,
};
use zk_pass::client::AuthClientLib;
use zk_pass::cmdutil::{ChaumPedersenType, EllipticCurveType, RfcModpType};
use zk_pass::rand::RandomGenerator;

/// Command-line options structure for the ZKPass client.
#[derive(Debug, StructOpt)]
#[structopt(name = "client", about = "A client for the ZKPass server")]
struct Opt {
    /// The host address of the ZKPass server.
    #[structopt(short, long, default_value = "[::1]")]
    host: String,

    /// The port number to connect to the ZKPass server.
    #[structopt(short, long, default_value = "50051")]
    port: i32,

    /// Optional secret passcode for authentication.
    #[structopt(short, long)]
    secret: Option<String>,

    /// Username for identification.
    #[structopt(short, long, default_value = "foo")]
    user: String,

    /// Type of RFC log group to use for the Discrete Log implementation of Chaum-Pedersen.
    #[structopt(short, long, possible_values = RfcModpType::VARIANTS, default_value = "rfc5114_modp_1024_160", required_if("stereotype", "discrete_log"))]
    modp: RfcModpType,

    /// Underlying type of the Chaum-Pedersen protocol to use.
    #[structopt(short, long, possible_values = ChaumPedersenType::VARIANTS, default_value = "discrete_log")]
    r#type: ChaumPedersenType,

    /// Elliptic curve type for the Elliptic Curve implementation of Chaum-Pedersen.
    #[structopt(short, long, possible_values = EllipticCurveType::VARIANTS, default_value = "ec25519", required_if("stereotype", "elliptic_curve"))]
    curve: EllipticCurveType,
}

/// Hashes the provided secret string or generates a random value.
///
/// This function takes an optional secret string and performs one of two actions:
/// - If a secret string is provided, it hashes the string using SHA-512 and then
///   converts the hash to the specified type `T`.
/// - If no secret is provided (i.e., `None`), it generates a random value of type `T`.
///
/// # Type Parameters
/// * `T`: The target type for the hashed or random value. The type must implement
///   `ByteConvertible` to allow conversion from bytes to `T`, and `RandomGenerator`
///   to allow generation of a random value of type `T`.
///
/// # Parameters
/// * `secret`: An `Option<&String>` representing the secret string to hash.
///   - `Some(&String)`: The string to hash.
///   - `None`: Indicates that a random value should be generated instead of hashing.
///
/// # Returns
/// Returns a value of type `T`. The value is either:
/// - The hash of the provided secret string, converted to type `T`, or
/// - A randomly generated value of type `T`, if no secret string was provided.
///
/// # Panics
/// This function may panic in the following cases:
/// - If conversion from the hash bytes to the target type `T` fails.
/// - If random value generation for the target type `T` fails.
///
/// # Examples
/// ```
/// let secret = Some(String::from("my_secret"));
/// let hashed_secret: [u8; 64] = hash_or_randomize_secret(secret.as_ref());
/// // hashed_secret is now the SHA-512 hash of "my_secret", as an array of bytes.
///
/// let random_secret: [u8; 64] = hash_or_randomize_secret(None);
/// // random_secret is now a randomly generated array of bytes.
/// ```
fn hash_or_randomize_secret<T: ByteConvertible<T> + RandomGenerator<T>>(
    secret: Option<&String>,
) -> T {
    match secret {
        Some(s) => {
            let mut hasher = Sha512::new();
            hasher.update(s);
            let result = hasher.finalize();
            T::from_bytes(&result).expect("Failed to convert hash to target type")
        }
        None => T::generate_random().expect("Failed to generate random value"),
    }
}

/// Main entry point for the ZKPass client.
///
/// ## Usage
/// This program starts a client to interact with a server implementing the ZKPass Chaum-Pedersen protocol.
/// It requires command-line arguments to specify its configuration and to perform authentication.
///
/// ### Starting the Client from the Command Line
///
/// 1. **Open Terminal or Command Prompt:**
///    Ensure you have a terminal or command prompt window open.
///
/// 2. **Navigate to the Project Directory:**
///    Use the `cd` command to navigate to the directory where the client code is located.
///    ```bash
///    cd path/to/project_directory
///    ```
///
/// 3. **Build the Project (if needed):**
///    If you haven't already built your Rust project, build it using the `cargo build` command.
///    ```bash
///    cargo build
///    ```
///
/// 4. **Run the Client:**
///    Start the client using the `cargo run` command followed by the necessary options.
///    ```bash
///    cargo run -- --host <host_address> --port <port_number> --secret <secret_passcode> --user <user_name> --modp <modp_type> --type <protocol_type> --curve <elliptic_curve_type>
///    ```
///
///    Replace `<host_address>`, `<port_number>`, `<secret_passcode>`, `<user_name>`, `<modp_type>`, `<protocol_type>`, and `<elliptic_curve_type>` with appropriate values.
///
/// ### Command Line Options
///
/// - `--host` or `-h`: Sets the host address of the ZKPass server. Defaults to "[::1]" if not specified.
/// - `--port` or `-p`: Sets the port number of the ZKPass server. Defaults to 50051 if not specified.
/// - `--secret` or `-s`: Sets the secret passcode for authentication. Optional.
/// - `--user` or `-u`: Sets the username for authentication. Defaults to "foo" if not specified.
/// - `--modp` or `-m`: Sets the type of the RFC log group to use. Required if `--type` is "discrete_log".
/// - `--type` or `-t`: Sets the type of the Chaum-Pedersen protocol to use. Possible values: "discrete_log", "elliptic_curve".
/// - `--curve` or `-c`: Sets the elliptic curve type. Required if `--type` is "elliptic_curve".
///
/// ### Example Usage
///
/// To connect to a server on localhost, port 50051, using the elliptic curve protocol with user "alice":
/// ```bash
/// cargo run -- --host [::1] --port 50051 --user alice --type elliptic_curve --curve ec25519
/// ```
///
/// Remember to replace the values in the command with those suitable for your setup, and that the server must be serving the same protocol (type, modp, curve) as the client.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args(); // Parses command-line arguments.

    // Parses group parameters for Discrete Log and Elliptic Curve implementations.
    let dl_params = GroupParams::<BigUint>::from_str(&opt.modp.to_string()).map_err(|_| {
        "Invalid discrete log group parameters provided in command-line arguments".to_string()
    })?;
    let ec_params =
        GroupParams::<RistrettoPoint>::from_str(&opt.curve.to_string()).map_err(|_| {
            "Invalid elliptic curve group parameters provided in command-line arguments".to_string()
        })?;

    // Displays initial client information.
    println!("🔥 Starting ZK_PASS server 🔥");
    println!("      🤖 host: {}", opt.host);
    println!("      🔌 port: {}", opt.port);
    println!("      💥 stereotype: {}", opt.r#type);
    if opt.r#type == ChaumPedersenType::EllipticCurve {
        println!("      📈 elliptic curve: {}", opt.curve)
    } else {
        println!("      🔢 modp group: {}", opt.modp)
    }

    let x = hash_or_randomize_secret(opt.secret.as_ref()); // Generates a secret value for the protocol.

    println!("🔑 secret: {}", x); // Displays the secret value.

    // Establishes a connection to the ZKPass server.
    let mut client = AuthClientLib::connect(format!("http://{}:{}", opt.host, opt.port)).await?;

    // Executes the selected Chaum-Pedersen protocol.
    match opt.r#type {
        ChaumPedersenType::DiscreteLog => {
            // Secret generation for Discrete Log implementation.
            //let x = hash_string::<BigUint>(opt.secret);
            // Executes the protocol.
            execute_protocol::<DiscreteLogChaumPedersen, _, _>(
                &dl_params,
                &x,
                &opt.user,
                &mut client,
            )
            .await?;
        }
        ChaumPedersenType::EllipticCurve => {
            // TODO: Replace this with a secure implementation for secret generation.
            let x = Scalar::from(3u32);

            // Executes the protocol.
            execute_protocol::<EllipticCurveChaumPedersen, _, _>(
                &ec_params,
                &x,
                &opt.user,
                &mut client,
            )
            .await?;
        }
    }

    Ok(())
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
async fn execute_protocol<T, P, S>(
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
    println!("Session ID: {}", session_id);

    // The server verifies the authentication attempt.
    T::verify(&params, &s, &challenge, &(y1, y2, r1, r2));

    Ok(())
}
