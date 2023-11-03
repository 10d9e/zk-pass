# ZKPass 🔑

[![build-badge](https://github.com/jlogelin/zk_pass/actions/workflows/build.yml/badge.svg)](https://nightly.link/jlogelin/zk_pass/workflows/build/main/binaries.zip)
[![document-badge](https://github.com/jlogelin/zk_pass/actions/workflows/doc.yml/badge.svg)](https://jlogelin.github.io/zk_pass)
[![license-badge](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

## Overview
The ZKPass server is a command-line application that facilitates a secret verification [Chaum-Pedersen protocol](PROTOCOL.md) service. It offers support for both Discrete Log and Elliptic Curve implementations of the protocol.

The following table shows the possible combinations of stereotype(discrete log and elliptic curve) group configurations:

| Type              | Modp                    | Curve        |
|-------------------|-------------------------|--------------|
| discrete_log      | rfc5114_modp_1024_160   | N/A          |
| discrete_log      | rfc5114_modp_2048_224   | N/A          |
| discrete_log      | rfc5114_modp_2048_256   | N/A          |
| elliptic_curve    | N/A                     | ec25519      |
| elliptic_curve    | N/A                     | pallas       |
| elliptic_curve    | N/A                     | vesta        |

Note: This table shows a subset of possible combinations focusing on `type`, `curve`, and `modp` options as they must match between the server and client.

## Quick Start

0. **Install Prerequesites**
   ```bash
   brew install protoc
   ```

1. **Run the build**
   Open a terminal and navigate to the root directory of the project.

   ```bash
   cd path/to/your/zk_pass
   cargo build --release
   ```
2. **Start the server with default parameters**
   ```bash
   ❯ ./target/release/server
   🔥 Starting ZK_PASS server 🔥
         🤖 host: [::1]
         🔌 port: 50051
         💥 stereotype: discrete_log
         🔢 modp group: rfc5114_modp_1024_160
   ```

3. **In another terminal send a request with the client using default parameters**
   ```bash
   ❯ ./target/release/client
   🔥 Starting ZK_PASS client 🔥
         🤖 host: [::1]
         🔌 port: 50051
         💥 stereotype: discrete_log
         🔢 modp group: rfc5114_modp_1024_160
         🔑 user: foo
   🔑 Authentication successful! 🔑
   Session ID: 97f6e2e1-19d5-404e-ad03-aa3a96d10fc1
   ```
4. **Read about more configuration options by asking for --help**

  **Server:**
   ```bash
   ❯ ./target/release/server --help
   server 0.1.0
   A server for the ZKPass Chaum-Pedersen protocol service
   
   USAGE:
       server [OPTIONS]
   
   FLAGS:
           --help       Prints help information
       -V, --version    Prints version information
   
   OPTIONS:
       -c, --curve <curve>    Command line option to set the elliptic curve type. Required if the stereotype is set to
                              "elliptic_curve" [default: ec25519]  [possible values: ec25519, pallas, vesta]
       -h, --host <host>      Command line option to set the host address for the server. Defaults to "[::1]" if not
                              specified [default: [::1]]
       -m, --modp <modp>      Command line option to set the type of the RFC log group to use. Required if the stereotype
                              is set to "discrete_log" [default: rfc5114_modp_1024_160]  [possible values:
                              rfc5114_modp_1024_160, rfc5114_modp_2048_224, rfc5114_modp_2048_256]
       -p, --port <port>      Command line option to set the port for the server. Defaults to 50051 if not specified
                              [default: 50051]
       -t, --type <type>      Command line option to set the underlying type of the Chaum-Pedersen protocol to use
                              [default: discrete_log]  [possible values: discrete_log, elliptic_curve]
   ```

   **Client:**
   ```bash
   ❯ ./target/release/client --help
   client 0.1.0
   A client for the ZKPass server
   
   USAGE:
       client [OPTIONS]
   
   FLAGS:
           --help       Prints help information
       -V, --version    Prints version information
   
   OPTIONS:
       -c, --curve <curve>      Elliptic curve type for the Elliptic Curve implementation of Chaum-Pedersen [default:
                                ec25519]  [possible values: ec25519, pallas, vesta]
       -h, --host <host>        The host address of the ZKPass server [default: [::1]]
       -m, --modp <modp>        Type of RFC log group to use for the Discrete Log implementation of Chaum-Pedersen
                                [default: rfc5114_modp_1024_160]  [possible values: rfc5114_modp_1024_160,
                                rfc5114_modp_2048_224, rfc5114_modp_2048_256]
       -p, --port <port>        The port number to connect to the ZKPass server [default: 50051]
       -s, --secret <secret>    Optional secret passcode for authentication
       -t, --type <type>        Underlying type of the Chaum-Pedersen protocol to use [default: discrete_log]  [possible
                                values: discrete_log, elliptic_curve]
       -u, --user <user>        Username for identification [default: foo]
   ```


# Docker

### Running the docker-compose Setup

1. **Navigate to Your Project Directory:**
   Open a terminal and navigate to the root directory of the project, where the `docker-compose.yml` file is located.

   ```bash
   cd path/to/your/zk_pass
   ```

2. **Build the Docker Images:**
   Run the following command to build the Docker images as defined in your `docker-compose.yml` file.

   ```bash
   docker-compose build
   ```

3. **Start the Services:**
   To start the services (server and client containers) as defined in the `docker-compose.yml`, run:

   ```bash
   docker-compose up
   ```

4. **Shutting Down:**
   When you're done, you can shut down the containers by pressing `Ctrl+C` in the terminal where `docker-compose up` is running. Alternatively, you can run the following command in another terminal (still in the project root):

   ```bash
   docker-compose down
   ```

### Building and Running the Container Integration Tests

There are a comprehensive set of dockerized tests for all of the different stereotype configutations. To run them

0. **Make sure Docker is installed**

1. **Navigate to Your Project Directory:**
   Open a terminal and navigate to the root directory of the project.

   ```bash
   cd path/to/your/zk_pass
   ```

2. **Build the Test Container:**
   Build the Docker image for your test container. Replace `test-container` with your desired image name.

   ```bash
   docker build -f docker/Dockerfile.test -t test-container .
   ```

3. **Run the Test Container:**
   Once the build is complete, you can run the test container. This will execute the tests as defined in your test setup.

   ```bash
   docker run test-container
   ```

The test will execute and validate the full set of integration test with the client and server, the output will look something like:

```bash
❯ docker run test-container
Testing configuration: type=discrete_log, curve=ec25519, modp=rfc5114_modp_1024_160
🔥 Starting ZK_PASS server 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: discrete_log
      🔢 modp group: rfc5114_modp_1024_160
🔥 Starting ZK_PASS client 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: discrete_log
      🔢 modp group: rfc5114_modp_1024_160
      🔑 user: foo
🔑 Authentication successful! 🔑
Session ID: c78dd9a6-d8e7-4d5d-8ae3-84e4b3779a87
Test passed for configuration: type=discrete_log, curve=ec25519, modp=rfc5114_modp_1024_160
Testing configuration: type=discrete_log, curve=ec25519, modp=rfc5114_modp_2048_224
🔥 Starting ZK_PASS server 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: discrete_log
      🔢 modp group: rfc5114_modp_2048_224
🔥 Starting ZK_PASS client 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: discrete_log
      🔢 modp group: rfc5114_modp_2048_224
      🔑 user: foo
🔑 Authentication successful! 🔑
Session ID: 6567c805-a57f-41e6-bd02-304b4c8b8b65
Test passed for configuration: type=discrete_log, curve=ec25519, modp=rfc5114_modp_2048_224
Testing configuration: type=discrete_log, curve=ec25519, modp=rfc5114_modp_1024_160
🔥 Starting ZK_PASS server 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: discrete_log
      🔢 modp group: rfc5114_modp_1024_160
🔥 Starting ZK_PASS client 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: discrete_log
      🔢 modp group: rfc5114_modp_1024_160
      🔑 user: foo
🔑 Authentication successful! 🔑
Session ID: 41560d5c-ca8e-49e5-8f2e-1d077b300dbf
Test passed for configuration: type=discrete_log, curve=ec25519, modp=rfc5114_modp_1024_160
Testing configuration: type=elliptic_curve, curve=ec25519, modp=rfc5114_modp_1024_160
🔥 Starting ZK_PASS server 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: elliptic_curve
      📈 elliptic curve: ec25519
🔥 Starting ZK_PASS client 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: elliptic_curve
      📈 elliptic curve: ec25519
      🔑 user: foo
🔑 Authentication successful! 🔑
Session ID: a47b981e-2b85-4316-a573-d51bb4427e1d
Test passed for configuration: type=elliptic_curve, curve=ec25519, modp=rfc5114_modp_1024_160
Testing configuration: type=elliptic_curve, curve=pallas, modp=rfc5114_modp_1024_160
🔥 Starting ZK_PASS server 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: elliptic_curve
      📈 elliptic curve: pallas
🔥 Starting ZK_PASS client 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: elliptic_curve
      📈 elliptic curve: pallas
      🔑 user: foo
🔑 Authentication successful! 🔑
Session ID: e03ee7b0-eae9-43de-816d-528e43aae8f2
Test passed for configuration: type=elliptic_curve, curve=pallas, modp=rfc5114_modp_1024_160
Testing configuration: type=elliptic_curve, curve=vesta, modp=rfc5114_modp_1024_160
🔥 Starting ZK_PASS server 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: elliptic_curve
      📈 elliptic curve: vesta
🔥 Starting ZK_PASS client 🔥
      🤖 host: 0.0.0.0
      🔌 port: 50051
      💥 stereotype: elliptic_curve
      📈 elliptic curve: vesta
      🔑 user: foo
🔑 Authentication successful! 🔑
Session ID: 227c090b-85dc-44b7-987a-091be0278248
Test passed for configuration: type=elliptic_curve, curve=vesta, modp=rfc5114_modp_1024_160
All tests passed successfully!
```
