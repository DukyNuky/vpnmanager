import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    secret_key: str
    data_dir: Path
    app_title: str
    tls_enabled: bool

    @property
    def db_path(self) -> Path:
        return self.data_dir / "vpnmanager.db"


def _secret_key(data_dir: Path) -> str:
    """SECRET_KEY aus der Umgebung, sonst beim ersten Start erzeugen und im Datenverzeichnis ablegen."""
    secret = os.environ.get("SECRET_KEY", "").strip()
    if secret:
        if len(secret) < 32:
            raise RuntimeError("SECRET_KEY ist zu kurz (mind. 32 Zeichen, z.B. 'openssl rand -hex 32').")
        return secret
    key_file = data_dir / ".secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        key_file.chmod(0o600)
        logging.getLogger("vpnmanager").warning(
            "Kein SECRET_KEY gesetzt – neuer Schlüssel wurde in %s erzeugt. Diese Datei mitsichern!", key_file
        )
    return key_file.read_text().strip()


def _load() -> Settings:
    data_dir = Path(os.environ.get("DATA_DIR", "./data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    secret = _secret_key(data_dir)
    return Settings(
        secret_key=secret,
        data_dir=data_dir,
        app_title=os.environ.get("APP_TITLE", "VPN-Manager"),
        tls_enabled=os.environ.get("TLS_ENABLED", "true").lower() in ("1", "true", "yes"),
    )


settings = _load()
