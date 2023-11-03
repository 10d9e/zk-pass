use curve25519_dalek::RistrettoPoint;
use num_bigint::BigUint;
use pasta_curves::pallas::Point;
use std::str::FromStr;
use structopt::StructOpt;
use strum::VariantNames;
use tonic::transport::Server;
use zk_pass::chaum_pedersen::curve25519::Curve25519ChaumPedersen;
use zk_pass::chaum_pedersen::discretelog::DiscreteLogChaumPedersen;
use zk_pass::chaum_pedersen::pallas::PallasCurveChaumPedersen;
use zk_pass::chaum_pedersen::GroupParams;
use zk_pass::cmdutil::{ChaumPedersenType, EllipticCurveType, RfcModpType};
use zk_pass::service::zkp_auth::auth_server::AuthServer;
use zk_pass::service::ZkAuth;

/// Struct representing command line options for the server.
#[derive(StructOpt, Debug)]
#[structopt(
    name = "server",
    about = "A server for the ZKPass Chaum-Pedersen protocol service"
)]
struct Opt {
    /// Command line option to set the host address for the server.
    /// Defaults to "[::1]" if not specified.
    #[structopt(short, long, default_value = "[::1]")]
    host: String,

    /// Command line option to set the port for the server.
    /// Defaults to 50051 if not specified.
    #[structopt(short, long, default_value = "50051")]
    port: i32,

    /// Command line option to set the type of the RFC log group to use.
    /// Required if the stereotype is set to "discrete_log".
    #[structopt(short, long, possible_values = RfcModpType::VARIANTS, default_value = "rfc5114_modp_1024_160", required_if("stereotype", "discrete_log"))]
    modp: RfcModpType,

    /// Command line option to set the underlying type of the Chaum-Pedersen protocol to use.
    #[structopt(short, long, possible_values = ChaumPedersenType::VARIANTS, default_value = "discrete_log")]
    r#type: ChaumPedersenType,

    /// Command line option to set the elliptic curve type.
    /// Required if the stereotype is set to "elliptic_curve".
    #[structopt(short, long, possible_values = EllipticCurveType::VARIANTS, default_value = "ec25519", required_if("stereotype", "elliptic_curve"))]
    curve: EllipticCurveType,
}

/// Main entry point for the ZKPass Chaum-Pedersen protocol server.
///
/// ## Usage
/// This program starts a server implementing the ZKPass Chaum-Pedersen protocol.
/// It requires command-line arguments to specify its configuration.
///
/// ### Starting the Server from the Command Line
///
/// 1. **Open Terminal or Command Prompt:**
///    Ensure you have a terminal or command prompt window open.
///
/// 2. **Navigate to the Project Directory:**
///    Use the `cd` command to navigate to the directory where the server code is located.
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
/// 4. **Run the Server:**
///    Start the server using the `cargo run` command followed by the necessary options.
///    ```bash
///    cargo run -- --host <host_address> --port <port_number> --modp <modp_type> --type <protocol_type> --curve <elliptic_curve_type>
///    ```
///
///    Replace `<host_address>`, `<port_number>`, `<modp_type>`, `<protocol_type>`, and `<elliptic_curve_type>` with appropriate values.
///
/// ### Command Line Options
///
/// - `--host` or `-h`: Sets the host address for the server. Defaults to "[::1]" if not specified.
/// - `--port` or `-p`: Sets the port number for the server. Defaults to 50051 if not specified.
/// - `--modp` or `-m`: Sets the type of the RFC log group to use. Required if `--type` is "discrete_log".
/// - `--type` or `-t`: Sets the type of the Chaum-Pedersen protocol to use. Possible values: "discrete_log", "elliptic_curve".
/// - `--curve` or `-c`: Sets the elliptic curve type. Required if `--type` is "elliptic_curve".
///
/// ### Example Usage
///
/// To start the server on localhost, port 50051, using the discrete log protocol:
/// ```bash
/// cargo run -- --host [::1] --port 50051 --type discrete_log
/// ```
///
/// Remember to replace the values in the command with those suitable for your setup.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments using struct destructuring.
    let Opt {
        host,
        port,
        r#type: stereotype,
        curve,
        modp,
        ..
    } = Opt::from_args();

    // Print server start information.
    println!("🔥 Starting ZK_PASS server 🔥");
    println!("      🤖 host: {}", host);
    println!("      🔌 port: {}", port);
    println!("      💥 stereotype: {}", stereotype);
    match stereotype {
        ChaumPedersenType::EllipticCurve => println!("      📈 elliptic curve: {}", curve),
        _ => println!("      🔢 modp group: {}", modp),
    }

    // Parse the address and handle errors informatively.
    let addr = format!("{}:{}", host, port)
        .parse()
        .map_err(|_| "Failed to parse server address")?;

    // Initialize and start the server based on stereotype.
    match stereotype {
        ChaumPedersenType::DiscreteLog => {
            let params = GroupParams::<BigUint>::from_str(&modp.to_string()).map_err(|_| {
                "Invalid discrete log group parameters provided in command-line arguments"
                    .to_string()
            })?;
            let auth = ZkAuth::<DiscreteLogChaumPedersen, _, _>::new(params);
            Server::builder()
                .add_service(AuthServer::new(auth))
                .serve(addr)
                .await?;
        }
        ChaumPedersenType::EllipticCurve => match curve {
            EllipticCurveType::Ec25519 => {
                let params =
                    GroupParams::<RistrettoPoint>::from_str(&curve.to_string()).map_err(|_| {
                        "Invalid elliptic curve group parameters provided in command-line arguments"
                            .to_string()
                    })?;
                let auth = ZkAuth::<Curve25519ChaumPedersen, _, _>::new(params);
                Server::builder()
                    .add_service(AuthServer::new(auth))
                    .serve(addr)
                    .await?;
            }

            EllipticCurveType::Pallas => {
                let params = GroupParams::<Point>::from_str(&curve.to_string()).map_err(|_| {
                    "Invalid elliptic curve group parameters provided in command-line arguments"
                        .to_string()
                })?;
                let auth = ZkAuth::<PallasCurveChaumPedersen, _, _>::new(params);
                Server::builder()
                    .add_service(AuthServer::new(auth))
                    .serve(addr)
                    .await?;
            }
        },
    }

    Ok(())
}
