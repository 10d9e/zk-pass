# ZKPass Server

[![build-badge](https://github.com/jlogelin/zk_pass/actions/workflows/build.yml/badge.svg)](https://nightly.link/jlogelin/zk_pass/workflows/build/main/binaries.zip)
[![document-badge](https://github.com/jlogelin/zk_pass/actions/workflows/doc.yml/badge.svg)](https://jlogelin.github.io/zk_pass)
[![license-badge](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

## Overview
The ZKPass server is a command-line application that facilitates the [ZKPass Chaum-Pedersen protocol](PROTOCOL.md) service. It offers support for both Discrete Log and Elliptic Curve implementations of the protocol.

The following table shows the possible combinations of client and server configurations:

| Combination | Server Type       | Server Modp             | Server Curve | Client Type       | Client Modp             | Client Curve |
|-------------|-------------------|-------------------------|--------------|-------------------|-------------------------|--------------|
| 1           | discrete_log      | rfc5114_modp_1024_160   | N/A          | discrete_log      | rfc5114_modp_1024_160   | N/A          |
| 2           | discrete_log      | rfc5114_modp_2048_224   | N/A          | discrete_log      | rfc5114_modp_2048_224   | N/A          |
| 3           | discrete_log      | rfc5114_modp_2048_256   | N/A          | discrete_log      | rfc5114_modp_2048_256   | N/A          |
| 4           | elliptic_curve    | N/A                     | ec25519      | elliptic_curve    | N/A                     | ec25519      |

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

```bash
cargo build --release
```

## Installation
Ensure that the ZKPass server application is installed on your system. If it's not already installed, follow the provided installation instructions.

## Usage
To start the server, open your command-line interface and enter the `server` command followed by the appropriate options.

### Basic Command Structure
```bash
server [OPTIONS]
```

### Flags
- `--help`: Prints help information.
- `-V, --version`: Prints version information.

### Options
- `-c, --curve <curve>`: Sets the elliptic curve type. Required if the stereotype is set to "elliptic_curve". Default is `ec25519`. Possible values: `ec25519`.
- `-h, --host <host>`: Specifies the host address for the server. Defaults to `[::1]` if not specified.
- `-m, --modp <modp>`: Selects the type of the RFC log group to use. Required if the stereotype is set to "discrete_log". Default is `rfc5114_modp_1024_160`. Possible values: `rfc5114_modp_1024_160`, `rfc5114_modp_2048_224`, `rfc5114_modp_2048_256`.
- `-p, --port <port>`: Specifies the port for the server. Defaults to `50051` if not specified.
- `-t, --type <type>`: Determines the underlying type of the Chaum-Pedersen protocol to use. Default is `discrete_log`. Possible values: `discrete_log`, `elliptic_curve`.

## Examples

### Start the Server with Default Settings
```bash
server
```

### Specify a Host and Port
```bash
server --host 192.168.1.1 --port 6000
```

### Use Elliptic Curve Implementation
```bash
server --type elliptic_curve
```

### Specify an Elliptic Curve Type
```bash
server --curve ec25519
```

## Notes
- Ensure that the appropriate options are set according to your requirements. For instance, if you select the `elliptic_curve` type, the `--curve` option becomes mandatory.
- The default values will be applied for any options not explicitly set.
- The host and port should be configured according to your network setup to ensure accessibility from client applications.

# ZKPass Client

## Overview
The ZKPass client is a command-line application that enables users to interact with the ZKPass server using the Chaum-Pedersen protocol. It supports both Discrete Log and Elliptic Curve implementations of the protocol.

## Installation
Before you begin, ensure that the ZKPass client is installed on your system. If not, follow the installation instructions provided with the software.

## Usage
To run the client, open your command-line interface and enter the `client` command followed by the appropriate options.

### Basic Command Structure
```bash
client [OPTIONS]
```

### Flags
- `--help`: Prints help information.
- `-V, --version`: Prints version information.

### Options
- `-c, --curve <curve>`: Specifies the elliptic curve type for the Elliptic Curve implementation of Chaum-Pedersen. Default is `ec25519`. Possible values: `ec25519`.
- `-h, --host <host>`: Sets the host address of the ZKPass server. Default is `[::1]`.
- `-m, --modp <modp>`: Selects the type of RFC log group for the Discrete Log implementation of Chaum-Pedersen. Default is `rfc5114_modp_1024_160`. Possible values: `rfc5114_modp_1024_160`, `rfc5114_modp_2048_224`, `rfc5114_modp_2048_256`.
- `-p, --port <port>`: Specifies the port number to connect to the ZKPass server. Default is `50051`.
- `-s, --secret <secret>`: (Optional) Secret passcode for authentication.
- `-t, --type <type>`: Determines the underlying type of the Chaum-Pedersen protocol to use. Default is `discrete_log`. Possible values: `discrete_log`, `elliptic_curve`.
- `-u, --user <user>`: Username for identification. Default is `foo`.

## Examples

### Connect to the ZKPass Server with Default Settings
```bash
client
```

### Specify a Host and Port
```bash
client --host 192.168.1.1 --port 6000
```

### Use Elliptic Curve Implementation
```bash
client --type elliptic_curve
```

### Use a Specific Elliptic Curve and User
```bash
client --curve ec25519 --user alice
```

### Connect with a Secret Passcode
```bash
client --secret mySecretPasscode
```

## Notes
- Ensure that the ZKPass server is running and accessible at the specified host and port.
- The default values will be used for any options not explicitly set.
- The `--secret` option provides additional security and is recommended for sensitive operations.


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
Session ID: dc2ab7c3-ad1f-40a2-9a53-f387812e1037
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
Session ID: 774bf05c-0305-4ac1-beb0-4f3c3aee30f0
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
Session ID: 43e03574-9c01-4b63-b43c-092f2cc38211
Test passed for configuration: type=discrete_log, curve=ec25519, modp=rfc5114_modp_1024_160
Testing configuration: type=elliptic_curve, curve=ec25519, modp=rfc5114_modp_2048_256
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
Session ID: fb1ff58f-161b-47a0-9c27-676dd19eea54
Test passed for configuration: type=elliptic_curve, curve=ec25519, modp=rfc5114_modp_2048_256
All tests passed successfully!
```
