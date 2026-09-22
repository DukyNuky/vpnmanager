"""Geschäftslogik: verbindet Datenbank, PKI und OPNsense-API."""
import ipaddress
import json
import logging
import re
import unicodedata
from datetime import timedelta

import pyotp
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import pki
from .db import Tunnel, VpnUser, audit, get_setting, utcnow
from .opnsense import OPNsense, OPNsenseError
from .security import decrypt, encrypt, generate_password

log = logging.getLogger("vpnmanager")

PENDING_DAYS = 7
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
DESCR_PREFIX = "vpnmanager"


class ValidationError(ValueError):
    pass


# ------------------------------------------------------------------ Hilfen

def client(db: Session) -> OPNsense:
    url = get_setting(db, "opn_url")
    key = decrypt(get_setting(db, "opn_key_enc"))
    secret = decrypt(get_setting(db, "opn_secret_enc"))
    if not (url and key and secret):
        raise OPNsenseError("Die Verbindung zur OPNsense ist noch nicht eingerichtet (siehe Einstellungen).")
    verify = get_setting(db, "opn_verify_tls", "1") == "1"
    return OPNsense(url, key, secret, verify_tls=verify)


def opn_configured(db: Session) -> bool:
    return bool(get_setting(db, "opn_url") and get_setting(db, "opn_key_enc"))


def company(db: Session) -> str:
    return get_setting(db, "company", "") or ""


def support_contact(db: Session) -> str:
    return get_setting(db, "support", "") or ""


def slugify(text: str) -> str:
    text = text.lower().replace("ä", "ae").replace("ö", "oe").replace("ü", "ue").replace("ß", "ss")
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def suggest_username(full_name: str) -> str:
    parts = [slugify(p) for p in full_name.split() if p.strip()]
    parts = [p for p in parts if p]
    return ".".join(parts)[:32]


def _networks(text: str, field: str) -> list[str]:
    result = []
    for raw in re.split(r"[\s,;]+", text or ""):
        if not raw:
            continue
        try:
            result.append(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError:
            raise ValidationError(f"{field}: „{raw}“ ist kein gültiges Netz (z. B. 192.168.1.0/24).")
    return result


def _ips(text: str, field: str) -> list[str]:
    result = []
    for raw in re.split(r"[\s,;]+", text or ""):
        if not raw:
            continue
        try:
            result.append(str(ipaddress.ip_address(raw)))
        except ValueError:
            raise ValidationError(f"{field}: „{raw}“ ist keine gültige IP-Adresse.")
    return result


def suggest_tunnel_defaults(db: Session) -> dict:
    tunnels = db.scalars(select(Tunnel)).all()
    used_nets = {t.network for t in tunnels}
    used_ports = {t.port for t in tunnels}
    net = next(f"10.8.{i}.0/24" for i in range(0, 255) if f"10.8.{i}.0/24" not in used_nets)
    port = next(p for p in range(1194, 1294) if p not in used_ports)
    return {"network": net, "port": port}


def validate_tunnel(db: Session, form: dict, existing: Tunnel | None = None) -> dict:
    name = (form.get("name") or "").strip()
    if not name or len(name) > 48:
        raise ValidationError("Bitte einen Namen (max. 48 Zeichen) angeben.")
    public_host = (form.get("public_host") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9.\-:]+", public_host):
        raise ValidationError("Öffentliche Adresse: Bitte DNS-Name oder IP angeben, unter der die OPNsense erreichbar ist.")
    try:
        port = int(form.get("port") or 0)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise ValidationError("Port muss zwischen 1 und 65535 liegen.")
    mode = form.get("mode", "split")
    if mode not in ("split", "full"):
        raise ValidationError("Ungültiger Tunnel-Modus.")
    routes = _networks(form.get("routes", ""), "Freigegebene Netze")
    if mode == "split" and not routes:
        raise ValidationError("Beim Split-Tunnel muss mindestens ein freigegebenes Netz angegeben werden.")
    dns = _ips(form.get("dns_servers", ""), "DNS-Server")
    dns_domain = (form.get("dns_domain") or "").strip()
    if dns_domain and not re.fullmatch(r"[A-Za-z0-9.\-]+", dns_domain):
        raise ValidationError("DNS-Domain ist ungültig.")
    try:
        session_hours = int(form.get("session_hours") or 12)
    except ValueError:
        session_hours = 0
    if not 1 <= session_hours <= 168:
        raise ValidationError("Sitzungsdauer muss zwischen 1 und 168 Stunden liegen.")

    for other in db.scalars(select(Tunnel)).all():
        if existing and other.id == existing.id:
            continue
        if other.port == port and other.proto == (existing.proto if existing else form.get("proto", "udp")):
            raise ValidationError(f"Port {port} wird bereits vom Tunnel „{other.name}“ verwendet.")

    data = {
        "name": name, "public_host": public_host, "port": port, "mode": mode,
        "routes": "\n".join(routes), "dns_servers": "\n".join(dns), "dns_domain": dns_domain,
        "session_hours": session_hours,
    }
    if existing is None:
        proto = form.get("proto", "udp")
        if proto not in ("udp", "tcp"):
            raise ValidationError("Ungültiges Protokoll.")
        net = _networks(form.get("network", ""), "Tunnel-Netz")
        if len(net) != 1:
            raise ValidationError("Bitte genau ein Tunnel-Netz angeben (z. B. 10.8.0.0/24).")
        network = ipaddress.ip_network(net[0])
        if network.version != 4 or network.prefixlen > 28:
            raise ValidationError("Tunnel-Netz muss ein IPv4-Netz mit /28 oder größer sein.")
        for other in db.scalars(select(Tunnel)).all():
            if ipaddress.ip_network(other.network).overlaps(network):
                raise ValidationError(f"Tunnel-Netz überschneidet sich mit „{other.name}“.")
        for r in routes:
            if ipaddress.ip_network(r).overlaps(network):
                raise ValidationError("Tunnel-Netz darf sich nicht mit freigegebenen Netzen überschneiden.")
        auth_server = (form.get("auth_server") or "").strip()
        if not auth_server:
            raise ValidationError("Bitte einen Authentifizierungsserver (Local + TOTP) auswählen.")
        data.update(proto=proto, network=str(network), auth_server=auth_server)
    return data


def instance_payload(t: Tunnel) -> dict:
    full = t.mode == "full"
    return {
        "enabled": "1",
        "role": "server",
        "description": f"{DESCR_PREFIX}: {t.name}",
        "dev_type": "tun",
        "proto": t.proto,
        "port": str(t.port),
        "topology": "subnet",
        "server": t.network,
        "ca": t.opn_ca_refid,
        "cert": t.opn_cert_refid,
        "cert_depth": "1",
        "verify_client_cert": "require",
        "remote_cert_tls": "1",
        "tls_key": t.opn_statickey_uuid,
        "authmode": t.auth_server,
        "strictusercn": "1",
        "data-ciphers": "AES-256-GCM,AES-128-GCM,CHACHA20-POLY1305",
        "data-ciphers-fallback": "AES-256-GCM",
        "keepalive_interval": "10",
        "keepalive_timeout": "60",
        # Token statt erneuter TOTP-Abfrage bei Renegotiation/Reconnect (z. B. WLAN ↔ Mobilfunk)
        "auth-gen-token": str(t.session_hours * 3600),
        "push_route": "" if full else ",".join(t.route_list),
        "redirect_gateway": "def1" if full else "",
        "dns_servers": ",".join(t.dns_list),
        "dns_domain": t.dns_domain,
        "register_dns": "1" if t.dns_list else "0",
        "various_push_flags": "block-outside-dns" if full and t.dns_list else "",
    }


def _fw_rules(t: Tunnel) -> list[dict]:
    dest = "any" if t.mode == "full" else ",".join(t.route_list)
    return [
        {
            "enabled": "1", "action": "pass", "quick": "1", "interface": "wan", "direction": "in",
            "ipprotocol": "inet", "protocol": "UDP" if t.proto == "udp" else "TCP",
            "source_net": "any", "destination_net": "(self)", "destination_port": str(t.port),
            "description": f"{DESCR_PREFIX} {t.name}: Einwahl OpenVPN",
        },
        {
            "enabled": "1", "action": "pass", "quick": "1", "interface": "openvpn", "direction": "in",
            "ipprotocol": "inet", "protocol": "any",
            "source_net": t.network, "destination_net": dest,
            "description": f"{DESCR_PREFIX} {t.name}: Zugriff VPN-Benutzer",
        },
    ]


# ------------------------------------------------------------------ Tunnel

async def create_tunnel(db: Session, actor: str, data: dict, fw_rules: bool) -> Tunnel:
    t = Tunnel(**data)
    slug = slugify(t.name) or "vpn"
    ca_cert, ca_key = pki.create_ca(f"{t.name} VPN CA")
    t.server_cn = f"{slug}-server"
    srv_cert, srv_key, _ = pki.issue_cert(ca_cert, ca_key, t.server_cn, server=True)
    tls_key = pki.generate_static_key()
    t.ca_cert, t.ca_key_enc, t.tls_key_enc = ca_cert, encrypt(ca_key), encrypt(tls_key)
    t.opn_ca_refid, t.opn_cert_refid = pki.new_refid(), pki.new_refid()

    async with client(db) as c:
        try:
            t.opn_ca_uuid = await c.import_ca(f"{DESCR_PREFIX}: {t.name} CA", ca_cert, t.opn_ca_refid)
            t.opn_cert_uuid = await c.import_cert(
                f"{DESCR_PREFIX}: {t.name} Server", srv_cert, srv_key, t.opn_cert_refid
            )
            t.opn_statickey_uuid = await c.add_static_key(f"{DESCR_PREFIX}: {t.name}", tls_key)
            t.opn_instance_uuid = await c.add_instance({**instance_payload(t), "vpnid": ""})
            if fw_rules:
                uuids = [await c.add_rule(r) for r in _fw_rules(t)]
                t.opn_fw_rules = json.dumps(uuids)
                await c.apply_firewall()
            await c.reconfigure_openvpn()
        except Exception:
            await _cleanup_tunnel(c, t)
            raise

    db.add(t)
    audit(db, actor, "tunnel.create", f"{t.name} ({t.proto}/{t.port}, {t.network})")
    db.commit()
    return t


async def _cleanup_tunnel(c: OPNsense, t: Tunnel) -> list[str]:
    """Entfernt alle OPNsense-Objekte eines Tunnels (best effort). Gibt Fehlermeldungen zurück."""
    errors = []
    steps = [
        *[(c.delete_rule, u) for u in t.fw_rule_list],
        (c.delete_instance, t.opn_instance_uuid),
        (c.delete_static_key, t.opn_statickey_uuid),
        (c.delete_cert, t.opn_cert_uuid),
        (c.delete_ca, t.opn_ca_uuid),
    ]
    for fn, uuid in steps:
        if not uuid:
            continue
        try:
            await fn(uuid)
        except OPNsenseError as exc:
            errors.append(str(exc))
            log.warning("Aufräumen fehlgeschlagen (%s %s): %s", fn.__name__, uuid, exc)
    for fn in (c.apply_firewall, c.reconfigure_openvpn):
        try:
            await fn()
        except OPNsenseError as exc:
            errors.append(str(exc))
    return errors


async def update_tunnel(db: Session, actor: str, t: Tunnel, data: dict) -> list[str]:
    """Ändert einen Tunnel. Gibt Hinweise zurück (z. B. dass Profile neu verteilt werden müssen)."""
    notes = []
    if data["port"] != t.port or data["public_host"] != t.public_host:
        notes.append("Adresse/Port wurden geändert – alle Benutzer benötigen ein neues Download-Paket.")
    for k, v in data.items():
        setattr(t, k, v)
    async with client(db) as c:
        await c.set_instance(t.opn_instance_uuid, instance_payload(t))
        rules = t.fw_rule_list
        if rules:
            for uuid, rule in zip(rules, _fw_rules(t)):
                await c.set_rule(uuid, rule)
            await c.apply_firewall()
        await c.reconfigure_openvpn()
    audit(db, actor, "tunnel.update", f"{t.name}: Modus={t.mode}, Netze={', '.join(t.route_list) or '-'}")
    db.commit()
    return notes


async def delete_tunnel(db: Session, actor: str, t: Tunnel) -> list[str]:
    async with client(db) as c:
        errors = []
        for u in t.users:
            try:
                await c.delete_user(u.opn_user_uuid)
            except OPNsenseError as exc:
                errors.append(f"Benutzer {u.username}: {exc}")
        errors += await _cleanup_tunnel(c, t)
    audit(db, actor, "tunnel.delete", t.name)
    db.delete(t)
    db.commit()
    return errors


async def restart_tunnel(db: Session, actor: str, t: Tunnel) -> None:
    async with client(db) as c:
        await c.restart_instance(t.opn_instance_uuid)
    audit(db, actor, "tunnel.restart", t.name)
    db.commit()


# ------------------------------------------------------------------ Status

def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


async def fetch_status(db: Session) -> dict[str, dict]:
    """Status pro OPNsense-Instanz-UUID: {'running': bool, 'known': bool, 'sessions': [...]}."""
    async with client(db) as c:
        rows = await c.sessions()
    status: dict[str, dict] = {}
    for row in rows:
        inst = str(row.get("id", "")).split("_", 1)[0]
        entry = status.setdefault(inst, {"running": False, "known": True, "sessions": []})
        if row.get("status") == "ok" or row.get("is_client"):
            entry["running"] = True
        if row.get("is_client"):
            entry["sessions"].append({
                "common_name": row.get("common_name") or "",
                "username": row.get("username") or row.get("common_name") or "",
                "real_address": row.get("real_address") or "",
                "virtual_address": row.get("virtual_address") or "",
                "bytes_received": _int(row.get("bytes_received")),
                "bytes_sent": _int(row.get("bytes_sent")),
                "connected_since": row.get("connected_since") or "",
            })
    # "zuletzt online" für bekannte Benutzer merken
    online = {s["common_name"] for e in status.values() for s in e["sessions"]}
    if online:
        now = utcnow()
        for u in db.scalars(select(VpnUser).where(VpnUser.username.in_(online))).all():
            u.last_seen = now
        db.commit()
    return status


async def kill_session(db: Session, actor: str, t: Tunnel, session_id: str) -> None:
    async with client(db) as c:
        await c.kill_session(t.opn_instance_uuid, session_id)
    audit(db, actor, "session.kill", f"{t.name}: {session_id}")
    db.commit()


async def _kill_user_sessions(c: OPNsense, t: Tunnel, username: str) -> None:
    try:
        await c.kill_session(t.opn_instance_uuid, username)
    except OPNsenseError as exc:
        log.info("Keine Session für %s beendet: %s", username, exc)


# ------------------------------------------------------------------ Benutzer

def _set_pending(u: VpnUser, password: str | None, otp_seed: str | None) -> None:
    if password:
        u.pending_password_enc = encrypt(password)
    if otp_seed:
        u.pending_otp_enc = encrypt(otp_seed)
    u.pending_until = utcnow() + timedelta(days=PENDING_DAYS)


def clear_pending(u: VpnUser) -> None:
    u.pending_password_enc = u.pending_otp_enc = u.pending_until = None


async def create_user(db: Session, actor: str, t: Tunnel, form: dict) -> VpnUser:
    full_name = (form.get("full_name") or "").strip()
    username = (form.get("username") or "").strip().lower() or suggest_username(full_name)
    email = (form.get("email") or "").strip()
    platform = form.get("platform", "all")
    if not full_name:
        raise ValidationError("Bitte den Namen des Mitarbeiters angeben.")
    if not USERNAME_RE.fullmatch(username):
        raise ValidationError("Benutzername: 2–32 Zeichen, nur a–z, 0–9, Punkt, Minus, Unterstrich.")
    if platform not in ("all", "windows", "macos", "android", "ios"):
        platform = "all"
    if db.scalar(select(VpnUser).where(VpnUser.username == username)):
        raise ValidationError(f"Der Benutzername „{username}“ ist bereits vergeben.")

    password = generate_password()
    otp_seed = pyotp.random_base32()
    cert, key, not_after = pki.issue_cert(t.ca_cert, decrypt(t.ca_key_enc), username, server=False)
    u = VpnUser(
        tunnel=t, username=username, full_name=full_name, email=email, platform=platform,
        cert_pem=cert, key_enc=encrypt(key), cert_not_after=not_after,
    )
    async with client(db) as c:
        if await c.find_user(username):
            raise ValidationError(f"Auf der OPNsense existiert bereits ein Benutzer „{username}“.")
        u.opn_user_uuid = await c.add_user(
            username, password, otp_seed, full_name, email
        )
    _set_pending(u, password, otp_seed)
    db.add(u)
    audit(db, actor, "user.create", f"{username} → {t.name}")
    db.commit()
    return u


async def reset_password(db: Session, actor: str, u: VpnUser) -> None:
    password = generate_password()
    async with client(db) as c:
        await c.set_user(u.opn_user_uuid, u.username, password=password)
    _set_pending(u, password, None)
    audit(db, actor, "user.password", u.username)
    db.commit()


async def reset_otp(db: Session, actor: str, u: VpnUser) -> None:
    seed = pyotp.random_base32()
    async with client(db) as c:
        await c.set_user(u.opn_user_uuid, u.username, otp_seed=seed)
    _set_pending(u, None, seed)
    audit(db, actor, "user.otp", u.username)
    db.commit()


async def reissue_profile(db: Session, actor: str, u: VpnUser) -> None:
    """Neues Client-Zertifikat (z. B. nach Ablauf). Das alte Profil ist ohne Passwort+Code wertlos."""
    t = u.tunnel
    cert, key, not_after = pki.issue_cert(t.ca_cert, decrypt(t.ca_key_enc), u.username, server=False)
    u.cert_pem, u.key_enc, u.cert_not_after = cert, encrypt(key), not_after
    audit(db, actor, "user.reissue", u.username)
    db.commit()


async def set_user_disabled(db: Session, actor: str, u: VpnUser, disabled: bool) -> None:
    async with client(db) as c:
        await c.set_user(u.opn_user_uuid, u.username, disabled="1" if disabled else "0")
        if disabled:
            await _kill_user_sessions(c, u.tunnel, u.username)
    u.disabled = disabled
    audit(db, actor, "user.disable" if disabled else "user.enable", u.username)
    db.commit()


async def delete_user(db: Session, actor: str, u: VpnUser) -> None:
    async with client(db) as c:
        await c.delete_user(u.opn_user_uuid)
        await _kill_user_sessions(c, u.tunnel, u.username)
    audit(db, actor, "user.delete", f"{u.username} ({u.tunnel.name})")
    db.delete(u)
    db.commit()
