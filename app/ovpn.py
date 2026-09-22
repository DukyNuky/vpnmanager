import re

from .db import Tunnel, VpnUser
from .security import decrypt

OTP_PROMPT = "Code aus der Authenticator-App"


def profile_basename(company: str, tunnel: Tunnel, user: VpnUser) -> str:
    raw = f"{company or 'VPN'}-{tunnel.name}-{user.username}"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")


def render_ovpn(tunnel: Tunnel, user: VpnUser, company: str) -> str:
    proto = "udp" if tunnel.proto.startswith("udp") else "tcp-client"
    lines = [
        f"# {company or 'VPN'} – {tunnel.name}",
        f"# Benutzer: {user.username}",
        "client",
        "dev tun",
        f"proto {proto}",
        f"remote {tunnel.public_host} {tunnel.port}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        f'verify-x509-name "{tunnel.server_cn}" name',
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        "auth-user-pass",
        "auth-nocache",
        # separates Eingabefeld für den TOTP-Code (wird von OPNsense als SCRV1 ausgewertet)
        f'static-challenge "{OTP_PROMPT}" 1',
        "verb 3",
        "<ca>",
        tunnel.ca_cert.strip(),
        "</ca>",
        "<cert>",
        user.cert_pem.strip(),
        "</cert>",
        "<key>",
        decrypt(user.key_enc).strip(),
        "</key>",
        "<tls-crypt>",
        decrypt(tunnel.tls_key_enc).strip(),
        "</tls-crypt>",
    ]
    return "\n".join(lines) + "\n"
