"""Eigene kleine PKI pro Tunnel.

Die CA wird im Tool erzeugt; auf die OPNsense wird nur das CA-Zertifikat (ohne Key) sowie das
Server-Zertifikat importiert. Client-Zertifikate existieren nur im Tool und im .ovpn-Profil.
Da jede Instanz ihre eigene CA hat, funktioniert ein Profil nur für den Tunnel, für den es
ausgestellt wurde.
"""
import datetime
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS = 3650
SERVER_DAYS = 3650
CLIENT_DAYS = 1825


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def new_refid() -> str:
    """OPNsense-Referenz-ID (13 Hex-Zeichen, wie uniqid())."""
    return secrets.token_hex(7)[:13]


def create_ca(common_name: str) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpnmanager"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _cert_pem(cert), _key_pem(key)


def issue_cert(
    ca_cert_pem: str, ca_key_pem: str, common_name: str, *, server: bool
) -> tuple[str, str, datetime.datetime]:
    """Stellt ein Server- oder Client-Zertifikat aus. Rückgabe: (cert_pem, key_pem, not_after)."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    not_after = now + datetime.timedelta(days=SERVER_DAYS if server else CLIENT_DAYS)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vpnmanager"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            # digitalSignature + keyAgreement (0x88) wird von OpenVPN 2 und OpenVPN 3 (Connect) für EC akzeptiert
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
    )
    if server:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return _cert_pem(cert), _key_pem(key), not_after.replace(tzinfo=None)


def cert_serial_hex(cert_pem: str) -> str:
    return format(x509.load_pem_x509_certificate(cert_pem.encode()).serial_number, "x")


def build_crl(ca_cert_pem: str, ca_key_pem: str, serials_hex: list[str]) -> str:
    """Signierte Sperrliste. Lange Gültigkeit, weil sie bei jeder Änderung neu erzeugt wird
    (eine abgelaufene CRL würde OpenVPN alle Verbindungen ablehnen lassen)."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
    now = _now()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(minutes=5))
        .next_update(now + datetime.timedelta(days=CA_DAYS))
        .add_extension(x509.CRLNumber(int(now.timestamp())), critical=False)
    )
    for serial in sorted(set(serials_hex)):
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(int(serial, 16)).revocation_date(now).build()
        )
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def generate_static_key() -> str:
    """OpenVPN-Static-Key (2048 Bit) im Format von 'openvpn --genkey secret' – für tls-crypt."""
    hexdata = secrets.token_hex(256)
    lines = [hexdata[i:i + 32] for i in range(0, len(hexdata), 32)]
    return (
        "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n"
        + "\n".join(lines)
        + "\n-----END OpenVPN Static key V1-----\n"
    )
