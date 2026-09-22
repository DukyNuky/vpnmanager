import json
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, event, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import settings


def utcnow() -> datetime:
    """Naive UTC-Zeit (SQLite speichert keine Zeitzonen)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Admin(Base):
    """Benutzer der Weboberfläche (nicht VPN-Benutzer)."""
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)


class Tunnel(Base):
    """Eine OpenVPN-Server-Instanz auf der OPNsense."""
    __tablename__ = "tunnels"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    public_host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="udp")
    network: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(8), default="split")  # split | full
    routes: Mapped[str] = mapped_column(Text, default="")  # ein Netz pro Zeile
    dns_servers: Mapped[str] = mapped_column(Text, default="")
    dns_domain: Mapped[str] = mapped_column(String(255), default="")
    session_hours: Mapped[int] = mapped_column(Integer, default=12)
    auth_server: Mapped[str] = mapped_column(String(128))

    # PKI – CA-Key bleibt ausschließlich im Tool
    ca_cert: Mapped[str] = mapped_column(Text)
    ca_key_enc: Mapped[str] = mapped_column(Text)
    ca_serial: Mapped[int] = mapped_column(Integer, default=1)
    server_cn: Mapped[str] = mapped_column(String(128))
    tls_key_enc: Mapped[str] = mapped_column(Text)

    # Referenzen auf der OPNsense
    opn_instance_uuid: Mapped[str | None] = mapped_column(String(64))
    opn_ca_uuid: Mapped[str | None] = mapped_column(String(64))
    opn_ca_refid: Mapped[str | None] = mapped_column(String(32))
    opn_cert_uuid: Mapped[str | None] = mapped_column(String(64))
    opn_cert_refid: Mapped[str | None] = mapped_column(String(32))
    opn_statickey_uuid: Mapped[str | None] = mapped_column(String(64))
    opn_fw_rules: Mapped[str] = mapped_column(Text, default="[]")  # JSON-Liste von Regel-UUIDs

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    users: Mapped[list["VpnUser"]] = relationship(
        back_populates="tunnel", cascade="all, delete-orphan", order_by="VpnUser.username"
    )

    @property
    def route_list(self) -> list[str]:
        return [r.strip() for r in self.routes.splitlines() if r.strip()]

    @property
    def dns_list(self) -> list[str]:
        return [r.strip() for r in self.dns_servers.replace(",", "\n").splitlines() if r.strip()]

    @property
    def fw_rule_list(self) -> list[str]:
        return json.loads(self.opn_fw_rules or "[]")


class VpnUser(Base):
    """Mitarbeiter-Zugang zu genau einem Tunnel (= OPNsense-Benutzer + Client-Zertifikat)."""
    __tablename__ = "vpn_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tunnel_id: Mapped[int] = mapped_column(ForeignKey("tunnels.id"))
    username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    platform: Mapped[str] = mapped_column(String(16), default="all")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)

    opn_user_uuid: Mapped[str | None] = mapped_column(String(64))
    cert_pem: Mapped[str] = mapped_column(Text)
    key_enc: Mapped[str] = mapped_column(Text)
    cert_not_after: Mapped[datetime | None] = mapped_column(DateTime)

    # Einmalig anzuzeigende Zugangsdaten (verschlüsselt, werden nach Übergabe gelöscht)
    pending_password_enc: Mapped[str | None] = mapped_column(Text)
    pending_otp_enc: Mapped[str | None] = mapped_column(Text)
    pending_until: Mapped[datetime | None] = mapped_column(DateTime)

    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    tunnel: Mapped[Tunnel] = relationship(back_populates="users")

    @property
    def has_pending(self) -> bool:
        return bool(self.pending_password_enc or self.pending_otp_enc) and (
            self.pending_until is None or self.pending_until > utcnow()
        )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")


engine = create_engine(f"sqlite:///{settings.db_path}", connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.close()


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)
    settings.db_path.chmod(0o600)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_setting(db: Session, key: str, default: str | None = None) -> str | None:
    row = db.get(Setting, key)
    return row.value if row and row.value is not None else default


def set_setting(db: Session, key: str, value: str | None) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def audit(db: Session, actor: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, detail=detail))


def admin_count(db: Session) -> int:
    return len(db.scalars(select(Admin.id)).all())
