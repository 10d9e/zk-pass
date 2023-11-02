# ZKPass Server

[![build-badge](https://github.com/jlogelin/zk_pass/actions/workflows/build.yml/badge.svg)](https://nightly.link/jlogelin/zk_pass/workflows/build/main/binaries.zip)
[![document-badge](https://github.com/jlogelin/zk_pass/actions/workflows/doc.yml/badge.svg)](https://jlogelin.github.io/zk_pass)
[![license-badge](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

## Overview
The ZKPass server is a command-line application that facilitates the ZKPass Chaum-Pedersen protocol service. It offers support for both Discrete Log and Elliptic Curve implementations of the protocol.

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
