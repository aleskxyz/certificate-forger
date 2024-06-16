"""
certificate-forger
Copyright (C) 2024 aleskxyz

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import ssl
import socket
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from OpenSSL import crypto


class SSLFetchError(Exception):
    """Exception raised for errors in fetching SSL certificate."""

    pass


class PublicKeyExtractionError(Exception):
    """Exception raised for errors in extracting public key."""

    pass


class KeyPairGenerationError(Exception):
    """Exception raised for errors in key pair generation."""

    pass


class CertificateUpdateError(Exception):
    """Exception raised for errors in updating the certificate."""

    pass


def fetch_ssl_certificate(hostname, port=443):
    """Fetch the SSL certificate from the specified hostname and port."""
    context = ssl.create_default_context()
    try:
        resolved_ip = socket.gethostbyname(hostname)
        with socket.create_connection((resolved_ip, port), timeout=3) as connection:
            connection.settimeout(3)
            try:
                with context.wrap_socket(
                    connection, server_hostname=hostname
                ) as secure_socket:
                    return secure_socket.getpeercert(binary_form=True)
            except ssl.SSLError:
                raise SSLFetchError("Failed to establish SSL connection.")
    except (socket.error, socket.timeout, socket.gaierror) as e:
        raise SSLFetchError(f"Failed to fetch SSL certificate: {e}")


def extract_public_key_info(certificate_der):
    """Extract public key information from the certificate bytes."""
    try:
        certificate = x509.load_der_x509_certificate(certificate_der, default_backend())
        public_key = certificate.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size, public_key.public_numbers().e, None, "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.curve.key_size, None, public_key.curve.name, "ECDSA"
        else:
            raise PublicKeyExtractionError("Unsupported public key type.")
    except Exception as e:
        raise PublicKeyExtractionError(f"Failed to extract public key: {e}")


def generate_rsa_key_pair(key_size, public_exponent):
    """Generate an RSA key pair."""
    try:
        return rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend(),
        )
    except Exception as e:
        raise KeyPairGenerationError(f"Failed to generate RSA key pair: {e}")


def generate_ecdsa_key_pair(curve_name):
    """Generate an ECDSA key pair."""
    try:
        curve = getattr(ec, curve_name.upper())()
        return ec.generate_private_key(curve=curve, backend=default_backend())
    except AttributeError:
        raise KeyPairGenerationError(f"Unsupported ECC curve name: {curve_name}")
    except Exception as e:
        raise KeyPairGenerationError(f"Failed to generate ECDSA key pair: {e}")


def generate_key_pair(algorithm, key_size=None, public_exponent=None, curve_name=None):
    """Generate a key pair based on the specified algorithm and parameters."""
    try:
        if algorithm == "RSA":
            if key_size is None or public_exponent is None:
                raise KeyPairGenerationError(
                    "RSA key size and exponent must be provided."
                )
            private_key = generate_rsa_key_pair(key_size, public_exponent)
        elif algorithm == "ECDSA":
            if curve_name is None:
                raise KeyPairGenerationError("ECC curve name must be provided.")
            private_key = generate_ecdsa_key_pair(curve_name)
        else:
            raise KeyPairGenerationError("Unsupported algorithm.")

        public_key = private_key.public_key()
        return public_key, private_key
    except KeyPairGenerationError as e:
        raise e
    except Exception as e:
        raise KeyPairGenerationError(f"Failed to generate key pair: {e}")


def serialize_private_key(private_key):
    """Serialize a private key to PEM format."""
    try:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception as e:
        raise KeyPairGenerationError(f"Failed to serialize private key: {e}")


def replace_certificate_public_key(original_certificate_der, new_public_key):
    """Replace the public key in the original certificate with the new public key."""
    try:
        new_public_key_pem = new_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        new_openssl_public_key = crypto.load_publickey(
            crypto.FILETYPE_PEM, new_public_key_pem
        )
        original_certificate = crypto.load_certificate(
            crypto.FILETYPE_ASN1, original_certificate_der
        )
        original_certificate.set_pubkey(new_openssl_public_key)
        updated_certificate = original_certificate.to_cryptography()
        return updated_certificate.public_bytes(serialization.Encoding.PEM)
    except Exception as e:
        raise CertificateUpdateError(
            f"Failed to update certificate public key: {e}"
        )


def generate_self_signed_certificate(original_certificate_der, new_private_key):
    """Resign the original certificate with the new private key."""
    try:
        original_cert = x509.load_der_x509_certificate(
            original_certificate_der, default_backend()
        )
        builder = x509.CertificateBuilder(
            issuer_name=original_cert.subject,
            subject_name=original_cert.subject,
            public_key=new_private_key.public_key(),
            serial_number=original_cert.serial_number,
            not_valid_before=original_cert.not_valid_before_utc,
            not_valid_after=original_cert.not_valid_after_utc,
        )
        subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(
            new_private_key.public_key()
        )
        authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            new_private_key.public_key()
        )
        for extension in original_cert.extensions:
            if extension.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                builder = builder.add_extension(
                    subject_key_identifier, extension.critical
                )
            elif extension.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                builder = builder.add_extension(
                    authority_key_identifier, extension.critical
                )
            else:
                builder = builder.add_extension(extension.value, extension.critical)
        new_cert = builder.sign(
            private_key=new_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        return new_cert.public_bytes(serialization.Encoding.PEM)
    except Exception as e:
        raise CertificateUpdateError(f"Failed to sign certificate: {e}")


def handle_arguments():
    """Handle command line arguments."""
    parser = argparse.ArgumentParser(description="Fetch and update SSL certificate.")
    parser.add_argument(
        "hostname_port",
        type=str,
        help="Hostname and port in the format <hostname:port>",
    )
    parser.add_argument(
        "--operation",
        choices=["selfsign", "replacekey"],
        default="selfsign",
        help="Operation to perform: 'selfsign' or 'replacekey' (default: 'selfsign')",
    )
    args = parser.parse_args()

    try:
        hostname_port = args.hostname_port.split(":")
        hostname = hostname_port[0]
        port = int(hostname_port[1]) if len(hostname_port) > 1 else 443
        return hostname, port, args.operation
    except ValueError:
        parser.error(
            "Invalid format. Use <hostname:port> where port must be an integer."
        )


def main():
    """Main function to handle SSL certificate fetching and updating."""
    try:
        hostname, port, operation = handle_arguments()

        certificate_der = fetch_ssl_certificate(hostname, port)

        key_size, public_exponent, curve_name, algorithm = extract_public_key_info(
            certificate_der
        )

        new_public_key, new_private_key = generate_key_pair(
            algorithm, key_size, public_exponent, curve_name
        )

        if operation == "replacekey":
            new_certificate_pem = replace_certificate_public_key(
                certificate_der, new_public_key
            )
        elif operation == "selfsign":
            new_certificate_pem = generate_self_signed_certificate(
                certificate_der, new_private_key
            )

        new_private_key_pem = serialize_private_key(new_private_key)

        print(new_certificate_pem.decode("utf-8"))
        print(new_private_key_pem.decode("utf-8"))

    except (
        SSLFetchError,
        PublicKeyExtractionError,
        KeyPairGenerationError,
        CertificateUpdateError,
    ) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
