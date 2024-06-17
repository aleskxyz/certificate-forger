# Certificate Forger

Certificate Forger is a Python script designed to fetch SSL certificates from specified hosts, providing options to update or replace them with newly generated certificates. It supports both `selfsign` and `replacekey` operations, allowing users to either create self-signed certificates or replace the public key in existing certificates while preserving original fields and extensions.

## Usage

### Prerequisites

- Python 3.x
- Required Python packages (`cryptography`, `pyOpenSSL`)

### Installation

No installation steps are required beyond ensuring Python and the necessary packages are installed.

### Usage Example

To fetch and update a certificate, run the script with the following command:

```bash
git clone https://github.com/aleskxyz/certificate-forger.git
cd certificate-forger
pip install -r requirements.txt
python certificate-forger.py example.com:443
```

### Docker

You can also run the script using Docker:

```bash
docker run --rm ghcr.io/aleskxyz/certificate-forger:latest example.com:443
```

Replace `example.com:443` with your desired hostname and port.

### Command Line Arguments

- `hostname_port`: Specify the hostname and port in the format `<hostname:port>`.
- `--operation`: Optional argument to specify the operation:
  - `selfsign` (default): Generate a self-signed certificate.
  - `replacekey`: Replace the public key in the original certificate with a newly generated key pair.

### Handling Original Certificate Fields and Extensions

#### Replace Key (`replacekey` Operation)

When using the `replacekey` operation, the script replaces the public key in the original certificate while attempting to preserve all other fields and extensions. This approach ensures the replaced certificate maintains as much similarity to the original as possible. However, please note that the replaced certificate may not work by browsers due to the invalid certificate signature.

#### Self-Sign (`selfsign` Operation)

In `selfsign` mode, the script generates a new self-signed certificate using a newly generated private key. The self-signed certificate preserves all fields and extensions of the original certificate. This makes it suitable for testing and development purposes but may not be trusted by production systems unless its certificate authority (CA) is explicitly trusted.

### License

This script is licensed under the GNU General Public License (GPLv3). See [LICENSE](LICENSE) for more details.

### Disclaimer

This script is provided as-is without any warranty. Use at your own risk.

## Features

- **Certificate Fetching**: Fetches SSL certificates from specified hosts.
- **Key Generation**: Generates RSA or ECDSA key pairs for certificate operations.
- **Certificate Operations**: Supports self-signing or replacing public keys in certificates.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## Authors

- [aleskxyz](https://github.com/aleskxyz)

## Acknowledgments

- Built using Python and libraries such as `cryptography` and `pyOpenSSL`.
