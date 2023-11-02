use curve25519_dalek::RistrettoPoint;
use num_bigint::BigUint;
use sha2::{Digest, Sha512};
use std::str::FromStr;
use structopt::StructOpt;
use strum::VariantNames;
use zk_pass::conversion::ByteConvertible;

use std::error::Error;
use zk_pass::chaum_pedersen::{
    curve25519::EllipticCurveChaumPedersen, discretelog::DiscreteLogChaumPedersen, GroupParams,
};
use zk_pass::client::execute_protocol;
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

    // Displays initial client information.
    println!("🔥 Starting ZK_PASS client 🔥");
    println!("      🤖 host: {}", opt.host);
    println!("      🔌 port: {}", opt.port);
    println!("      💥 stereotype: {}", opt.r#type);
    if opt.r#type == ChaumPedersenType::EllipticCurve {
        println!("      📈 elliptic curve: {}", opt.curve)
    } else {
        println!("      🔢 modp group: {}", opt.modp)
    }
    println!("      🔑 user: {}", opt.user);

    // Establishes a connection to the ZKPass server.
    let mut client = AuthClientLib::connect(format!("http://{}:{}", opt.host, opt.port)).await?;

    // Executes the selected Chaum-Pedersen protocol.
    match opt.r#type {
        ChaumPedersenType::DiscreteLog => {
            // Executes the discrete log version of the protocol
            // Parses group parameters for Discrete Log and Elliptic Curve implementations.
            let dl_params =
                GroupParams::<BigUint>::from_str(&opt.modp.to_string()).map_err(|_| {
                    "Invalid discrete log group parameters provided in command-line arguments"
                        .to_string()
                })?;

            execute_protocol::<DiscreteLogChaumPedersen, _, _>(
                &dl_params,
                &hash_or_randomize_secret(opt.secret.as_ref()),
                &opt.user,
                &mut client,
            )
            .await?;
        }
        ChaumPedersenType::EllipticCurve => {
            // Executes the elliptic curve version of the protocol
            let ec_params = GroupParams::<RistrettoPoint>::from_str(&opt.curve.to_string())
                .map_err(|_| {
                    "Invalid elliptic curve group parameters provided in command-line arguments"
                        .to_string()
                })?;

            execute_protocol::<EllipticCurveChaumPedersen, _, _>(
                &ec_params,
                &hash_or_randomize_secret(opt.secret.as_ref()),
                &opt.user,
                &mut client,
            )
            .await?;
        }
    }

    Ok(())
}
