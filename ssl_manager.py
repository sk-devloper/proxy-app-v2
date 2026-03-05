import logging
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console

console = Console()


class SSLCertificateManager:
    """Manages SSL certificates for MITM proxy"""

    def __init__(self, cert_dir: str = "certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        self.ca_cert_path = self.cert_dir / "ca.crt"
        self.ca_key_path = self.cert_dir / "ca.key"
        self.cert_cache: Dict[str, Tuple[str, str]] = {}

        # Create CA if it doesn't exist
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            self._create_ca()

    def _create_ca(self):
        """Create Certificate Authority"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtensionOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization

            # Generate private key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Malibu"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Stark Industries"),
                x509.NameAttribute(NameOID.COMMON_NAME, "J.A.R.V.I.S. Proxy CA"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=3650))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        key_encipherment=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
            )

            # Write private key
            with open(self.ca_key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Write certificate
            with open(self.ca_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            console.print(f"[green]✓[/green] Created CA certificate: {self.ca_cert_path}")
            console.print(f"[yellow]⚠[/yellow] Import {self.ca_cert_path} to your browser's trusted certificates!")

        except ImportError:
            console.print("[red]✗[/red] cryptography library not installed. Install with: pip install cryptography")
            console.print("[yellow]Running in CONNECT-only mode (no SSL inspection)[/yellow]")

    def get_cert_for_host(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """Get or create certificate for hostname"""
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtensionOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization

            # Load CA
            with open(self.ca_key_path, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)

            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            # Generate private key for host
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Create certificate for host
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Stark Industries"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(hostname),
                    ]),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            # Save to files
            cert_path = self.cert_dir / f"{hostname}.crt"
            key_path = self.cert_dir / f"{hostname}.key"

            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            self.cert_cache[hostname] = (str(cert_path), str(key_path))
            return (str(cert_path), str(key_path))

        except ImportError:
            return (None, None)
        except Exception as e:
            logging.error(f"Error creating certificate for {hostname}: {e}")
            return (None, None)
