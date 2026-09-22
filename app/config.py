import os
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


def _load() -> Settings:
    secret = os.environ.get("SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("SECRET_KEY fehlt oder ist zu kurz (mind. 32 Zeichen, z.B. 'openssl rand -hex 32').")
    data_dir = Path(os.environ.get("DATA_DIR", "./data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return Settings(
        secret_key=secret,
        data_dir=data_dir,
        app_title=os.environ.get("APP_TITLE", "VPN-Manager"),
        tls_enabled=os.environ.get("TLS_ENABLED", "true").lower() in ("1", "true", "yes"),
    )


settings = _load()
