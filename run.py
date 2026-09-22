"""Container-Einstiegspunkt: erzeugt bei Bedarf ein selbstsigniertes TLS-Zertifikat und startet uvicorn."""
import datetime
import ipaddress
import os
import socket
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
TLS_DIR = DATA_DIR / "tls"


def ensure_self_signed() -> tuple[Path, Path]:
    cert_path, key_path = TLS_DIR / "cert.pem", TLS_DIR / "key.pem"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    hostname = socket.gethostname()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vpnmanager")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("vpnmanager"),
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def main():
    tls = os.environ.get("TLS_ENABLED", "true").lower() in ("1", "true", "yes")
    port = int(os.environ.get("PORT", "8443"))
    kwargs = {"host": "0.0.0.0", "port": port, "proxy_headers": True, "forwarded_allow_ips": "*"}
    if tls:
        cert, key = ensure_self_signed()
        kwargs.update(ssl_certfile=str(cert), ssl_keyfile=str(key))
    uvicorn.run("app.main:app", **kwargs)


if __name__ == "__main__":
    main()
