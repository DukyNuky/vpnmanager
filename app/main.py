import io
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pyotp
import qrcode
import qrcode.image.svg
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import package, services
from .config import settings
from .db import Admin, AuditLog, Tunnel, VpnUser, admin_count, audit, get_db, get_setting, init_db, set_setting, utcnow
from .opnsense import OPNsense, OPNsenseError
from .security import (
    SESSION_KEY, csrf_matches, decrypt, encrypt, hash_password, new_csrf_token, verify_password,
)
from .services import ValidationError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vpnmanager")
logging.getLogger("httpx").setLevel(logging.WARNING)

BASE = Path(__file__).parent
TZ = ZoneInfo(os.environ.get("TZ", "Europe/Berlin"))
SESSION_HOURS = 8

app = FastAPI(title=settings.app_title, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware, secret_key=SESSION_KEY, session_cookie="vpnm_session",
    max_age=SESSION_HOURS * 3600, same_site="strict", https_only=settings.tls_enabled,
)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


@app.on_event("startup")
def _startup():
    init_db()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


# ------------------------------------------------------------------ Template-Helfer

def fmt_dt(value: datetime | None) -> str:
    if not value:
        return "–"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(TZ).strftime("%d.%m.%Y %H:%M")


def fmt_bytes(n: int | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


templates.env.filters["dt"] = fmt_dt
templates.env.filters["bytes"] = fmt_bytes
templates.env.globals["platforms"] = package.PLATFORM_LABELS
templates.env.globals["windows_clients"] = package.WINDOWS_CLIENTS


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = request.session["csrf"] = new_csrf_token()
    return token


def flash(request: Request, message: str, kind: str = "ok") -> None:
    request.session.setdefault("flash", []).append([kind, message])


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    ctx.setdefault("admin", getattr(request.state, "admin", None))
    ctx.update(
        request=request,
        csrf=csrf_token(request),
        flashes=request.session.pop("flash", []),
        app_title=settings.app_title,
    )
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


async def form_data(request: Request) -> dict:
    """Liest das Formular und prüft das CSRF-Token."""
    form = await request.form()
    token = form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not csrf_matches(request.session.get("csrf"), token):
        raise CsrfError()
    return {k: v for k, v in form.items() if isinstance(v, str)}


# ------------------------------------------------------------------ Authentifizierung

class LoginRequired(Exception):
    pass


class TotpSetupRequired(Exception):
    pass


class CsrfError(Exception):
    pass


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, _exc):
    if request.headers.get("HX-Request"):
        return Response(status_code=204, headers={"HX-Redirect": "/login"})
    return redirect("/login")


@app.exception_handler(TotpSetupRequired)
async def _totp_required(request: Request, _exc):
    return redirect("/account/totp")


@app.exception_handler(CsrfError)
async def _csrf_error(request: Request, _exc):
    return HTMLResponse("Sitzung abgelaufen oder ungültige Anfrage. Bitte Seite neu laden.", status_code=400)


def require_admin(request: Request, db: Session = Depends(get_db)) -> Admin:
    uid = request.session.get("uid")
    admin = db.get(Admin, uid) if uid else None
    if admin is None:
        request.session.pop("uid", None)
        raise LoginRequired()
    if not admin.totp_enabled and request.url.path != "/account/totp":
        raise TotpSetupRequired()
    request.state.admin = admin
    return admin


# einfacher Schutz gegen Passwort-Raten: 5 Fehlversuche → 5 Minuten Sperre
_failures: dict[str, list[float]] = {}


def _locked(key: str) -> bool:
    now = time.time()
    attempts = [t for t in _failures.get(key, []) if now - t < 300]
    _failures[key] = attempts
    return len(attempts) >= 5


def _fail(key: str) -> None:
    _failures.setdefault(key, []).append(time.time())


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request, db: Session = Depends(get_db)):
    if admin_count(db):
        return redirect("/login")
    return render(request, "setup.html")


@app.post("/setup")
async def setup_submit(request: Request, db: Session = Depends(get_db)):
    if admin_count(db):
        return redirect("/login")
    form = await form_data(request)
    username = form.get("username", "").strip()
    pw, pw2 = form.get("password", ""), form.get("password2", "")
    error = _check_new_password(pw, pw2) or (None if username else "Bitte einen Benutzernamen angeben.")
    if error:
        return render(request, "setup.html", error=error, username=username, status_code=400)
    admin = Admin(username=username, password_hash=hash_password(pw))
    db.add(admin)
    audit(db, username, "admin.setup", "Erster Administrator angelegt")
    db.commit()
    request.session.clear()
    request.session["uid"] = admin.id
    return redirect("/account/totp")


def _check_new_password(pw: str, pw2: str) -> str | None:
    if len(pw) < 12:
        return "Das Passwort muss mindestens 12 Zeichen lang sein."
    if pw != pw2:
        return "Die Passwörter stimmen nicht überein."
    return None


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)):
    if not admin_count(db):
        return redirect("/setup")
    return render(request, "login.html")


@app.post("/login")
async def login_submit(request: Request, db: Session = Depends(get_db)):
    form = await form_data(request)
    username = form.get("username", "").strip()
    key = f"{request.client.host if request.client else '-'}:{username.lower()}"
    if _locked(key):
        return render(request, "login.html", error="Zu viele Fehlversuche. Bitte 5 Minuten warten.",
                      username=username, status_code=429)
    admin = db.scalar(select(Admin).where(Admin.username == username))
    if not admin or not verify_password(admin.password_hash, form.get("password", "")):
        _fail(key)
        return render(request, "login.html", error="Benutzername oder Passwort falsch.",
                      username=username, status_code=401)
    request.session.clear()
    if admin.totp_enabled:
        request.session["pending_uid"] = admin.id
        request.session["pending_since"] = time.time()
        return redirect("/login/totp")
    # noch keine 2FA eingerichtet → direkt zur Einrichtung
    request.session["uid"] = admin.id
    return redirect("/account/totp")


@app.get("/login/totp", response_class=HTMLResponse)
def login_totp_form(request: Request):
    if not request.session.get("pending_uid"):
        return redirect("/login")
    return render(request, "login_totp.html")


@app.post("/login/totp")
async def login_totp_submit(request: Request, db: Session = Depends(get_db)):
    form = await form_data(request)
    uid = request.session.get("pending_uid")
    if not uid or time.time() - request.session.get("pending_since", 0) > 300:
        request.session.clear()
        return redirect("/login")
    admin = db.get(Admin, uid)
    key = f"totp:{uid}"
    if _locked(key):
        request.session.clear()
        flash(request, "Zu viele Fehlversuche. Bitte 5 Minuten warten.", "error")
        return redirect("/login")
    code = form.get("code", "").replace(" ", "")
    if not admin or not pyotp.TOTP(decrypt(admin.totp_secret_enc)).verify(code, valid_window=1):
        _fail(key)
        return render(request, "login_totp.html", error="Code ungültig.", status_code=401)
    request.session.clear()
    request.session["uid"] = admin.id
    admin.last_login = utcnow()
    audit(db, admin.username, "admin.login")
    db.commit()
    return redirect("/")


@app.post("/logout")
async def logout(request: Request):
    await form_data(request)
    request.session.clear()
    return redirect("/login")


def _svg_qr(data: str) -> str:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode()
    return svg[svg.index("<svg"):]


@app.get("/account/totp", response_class=HTMLResponse)
def totp_setup_form(request: Request, admin: Admin = Depends(require_admin)):
    secret = request.session.get("totp_setup") or pyotp.random_base32()
    request.session["totp_setup"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=admin.username, issuer_name=settings.app_title)
    return render(request, "totp_setup.html", secret=secret, qr_svg=_svg_qr(uri))


@app.post("/account/totp")
async def totp_setup_submit(request: Request, db: Session = Depends(get_db),
                            admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    secret = request.session.get("totp_setup")
    if not secret:
        return redirect("/account/totp")
    if not pyotp.TOTP(secret).verify(form.get("code", "").replace(" ", ""), valid_window=1):
        uri = pyotp.TOTP(secret).provisioning_uri(name=admin.username, issuer_name=settings.app_title)
        return render(request, "totp_setup.html", secret=secret, qr_svg=_svg_qr(uri),
                      error="Code ungültig – bitte erneut versuchen.", status_code=400)
    admin.totp_secret_enc = encrypt(secret)
    admin.totp_enabled = True
    request.session.pop("totp_setup", None)
    audit(db, admin.username, "admin.totp", "2FA eingerichtet")
    db.commit()
    flash(request, "Zwei-Faktor-Anmeldung ist eingerichtet.")
    return redirect("/")


# ------------------------------------------------------------------ Dashboard

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    tunnels = db.scalars(select(Tunnel).order_by(Tunnel.name)).all()
    log_entries = db.scalars(select(AuditLog).order_by(AuditLog.ts.desc()).limit(10)).all()
    return render(request, "dashboard.html", tunnels=tunnels, log_entries=log_entries,
                  configured=services.opn_configured(db))


@app.get("/partials/overview", response_class=HTMLResponse)
async def overview_partial(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    tunnels = db.scalars(select(Tunnel).order_by(Tunnel.name)).all()
    error, status = None, {}
    try:
        status = await services.fetch_status(db)
    except OPNsenseError as exc:
        error = str(exc)
    return render(request, "partials/overview.html", tunnels=tunnels, status=status, error=error)


# ------------------------------------------------------------------ Einstellungen

def _settings_ctx(db: Session) -> dict:
    return {
        "opn_url": get_setting(db, "opn_url", ""),
        "has_key": bool(get_setting(db, "opn_key_enc")),
        "verify_tls": get_setting(db, "opn_verify_tls", "1") == "1",
        "public_host": get_setting(db, "public_host", ""),
        "company": get_setting(db, "company", ""),
        "support": get_setting(db, "support", ""),
        "windows_client": services.windows_client(db),
    }


@app.get("/settings", response_class=HTMLResponse)
async def settings_form(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    auth_servers = (await _auth_servers(db, timeout=5))[0] if services.opn_configured(db) else []
    return render(request, "settings.html", s=_settings_ctx(db), tpl=services.tunnel_template(db),
                  auth_servers=auth_servers)


@app.post("/settings/tunnel-defaults")
async def settings_tunnel_defaults(request: Request, db: Session = Depends(get_db),
                                   admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    try:
        tpl = services.validate_template(form)
    except ValidationError as exc:
        flash(request, f"Vorgaben nicht gespeichert: {exc}", "error")
        return redirect("/settings#vorgaben")
    for key, value in tpl.items():
        set_setting(db, f"tpl_{key}", value)
    audit(db, admin.username, "settings.tunnel_defaults",
          f"{tpl['proto']}/{tpl['port']}, {tpl['network']}, {tpl['mode']}")
    db.commit()
    flash(request, "Vorgaben für neue Tunnel gespeichert.")
    return redirect("/settings#vorgaben")


@app.post("/settings")
async def settings_submit(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    url = form.get("opn_url", "").strip().rstrip("/")
    if url and not url.startswith(("https://", "http://")):
        flash(request, "Die OPNsense-URL muss mit https:// beginnen.", "error")
        return redirect("/settings")
    set_setting(db, "opn_url", url)
    set_setting(db, "opn_verify_tls", "1" if form.get("verify_tls") else "0")
    if form.get("api_key", "").strip():
        set_setting(db, "opn_key_enc", encrypt(form["api_key"].strip()))
    if form.get("api_secret", "").strip():
        set_setting(db, "opn_secret_enc", encrypt(form["api_secret"].strip()))
    for key in ("public_host", "company", "support"):
        set_setting(db, key, form.get(key, "").strip())
    if form.get("windows_client") in package.WINDOWS_CLIENTS:
        set_setting(db, "windows_client", form["windows_client"])
    audit(db, admin.username, "settings.update", f"OPNsense: {url}")
    db.commit()
    flash(request, "Einstellungen gespeichert.")
    return redirect("/settings")


@app.post("/settings/test", response_class=HTMLResponse)
async def settings_test(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    """Testet die Verbindung – mit den Werten aus dem Formular (noch nicht gespeichert) oder den gespeicherten."""
    form = await form_data(request)
    url = form.get("opn_url", "").strip().rstrip("/") or get_setting(db, "opn_url", "")
    key = form.get("api_key", "").strip() or decrypt(get_setting(db, "opn_key_enc"))
    secret = form.get("api_secret", "").strip() or decrypt(get_setting(db, "opn_secret_enc"))
    if not (url and key and secret):
        return render(request, "partials/test_result.html", error="Bitte URL, API-Key und Secret angeben.")
    checks, auth_servers, error = [], [], None
    async with OPNsense(url, key, secret, verify_tls=bool(form.get("verify_tls"))) as c:
        try:
            checks = await c.check_access()
            if checks and checks[0][1]:
                auth_servers = await c.auth_servers()
        except OPNsenseError as exc:
            error = str(exc)
    totp_servers = [a for a in auth_servers if a != "Local Database"]
    failed = [label for label, ok, _ in checks if not ok]
    all_ok = bool(checks) and len(checks) == len(OPNsense.ACCESS_CHECKS) and not failed
    only_fw_missing = len(checks) == len(OPNsense.ACCESS_CHECKS) and failed == ["Firewall-Regeln"]
    return render(request, "partials/test_result.html", checks=checks, auth_servers=auth_servers,
                  totp_servers=totp_servers, error=error, all_ok=all_ok, only_fw_missing=only_fw_missing)


# ------------------------------------------------------------------ Administratoren

@app.get("/admins", response_class=HTMLResponse)
def admins_list(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    return render(request, "admins.html", admins=db.scalars(select(Admin).order_by(Admin.username)).all())


@app.post("/admins/new")
async def admins_new(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    username = form.get("username", "").strip()
    error = _check_new_password(form.get("password", ""), form.get("password2", ""))
    if not username:
        error = "Bitte einen Benutzernamen angeben."
    elif db.scalar(select(Admin).where(Admin.username == username)):
        error = "Benutzername existiert bereits."
    if error:
        flash(request, error, "error")
        return redirect("/admins")
    db.add(Admin(username=username, password_hash=hash_password(form["password"])))
    audit(db, admin.username, "admin.create", username)
    db.commit()
    flash(request, f"Administrator „{username}“ angelegt. Die 2FA wird bei der ersten Anmeldung eingerichtet.")
    return redirect("/admins")


@app.post("/admins/{admin_id}/delete")
async def admins_delete(admin_id: int, request: Request, db: Session = Depends(get_db),
                        admin: Admin = Depends(require_admin)):
    await form_data(request)
    target = db.get(Admin, admin_id)
    if target and target.id != admin.id:
        audit(db, admin.username, "admin.delete", target.username)
        db.delete(target)
        db.commit()
        flash(request, f"Administrator „{target.username}“ gelöscht.")
    return redirect("/admins")


@app.post("/admins/{admin_id}/reset-2fa")
async def admins_reset_2fa(admin_id: int, request: Request, db: Session = Depends(get_db),
                           admin: Admin = Depends(require_admin)):
    await form_data(request)
    target = db.get(Admin, admin_id)
    if target and target.id != admin.id:
        target.totp_enabled, target.totp_secret_enc = False, None
        audit(db, admin.username, "admin.reset2fa", target.username)
        db.commit()
        flash(request, f"2FA von „{target.username}“ zurückgesetzt – wird bei nächster Anmeldung neu eingerichtet.")
    return redirect("/admins")


@app.post("/account/password")
async def account_password(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    if not verify_password(admin.password_hash, form.get("current", "")):
        flash(request, "Aktuelles Passwort ist falsch.", "error")
    elif error := _check_new_password(form.get("password", ""), form.get("password2", "")):
        flash(request, error, "error")
    else:
        admin.password_hash = hash_password(form["password"])
        audit(db, admin.username, "admin.password")
        db.commit()
        flash(request, "Passwort geändert.")
    return redirect("/admins")


@app.get("/log", response_class=HTMLResponse)
def audit_log(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    entries = db.scalars(select(AuditLog).order_by(AuditLog.ts.desc()).limit(500)).all()
    return render(request, "log.html", entries=entries)


# ------------------------------------------------------------------ Tunnel

def _get_tunnel(db: Session, tunnel_id: int) -> Tunnel:
    t = db.get(Tunnel, tunnel_id)
    if t is None:
        raise NotFound()
    return t


class NotFound(Exception):
    pass


@app.exception_handler(NotFound)
async def _not_found(request: Request, _exc):
    return render(request, "error.html", message="Nicht gefunden.", status_code=404)


async def _auth_servers(db: Session, timeout: float = 30) -> tuple[list[str], str | None]:
    try:
        async with services.client(db, timeout=timeout) as c:
            return await c.auth_servers(), None
    except OPNsenseError as exc:
        return [], str(exc)


@app.get("/tunnels/new", response_class=HTMLResponse)
async def tunnel_new_form(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    if not services.opn_configured(db):
        flash(request, "Bitte zuerst die Verbindung zur OPNsense einrichten.", "error")
        return redirect("/settings")
    auth_servers, error = await _auth_servers(db)
    f = services.suggest_tunnel_defaults(db)
    return render(request, "tunnel_form.html", f=f, auth_servers=auth_servers, error=error, new=True)


@app.post("/tunnels/new")
async def tunnel_new_submit(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    try:
        data = services.validate_tunnel(db, form)
        t, notes = await services.create_tunnel(db, admin.username, data, fw_rules=bool(form.get("fw_rules")))
    except (ValidationError, OPNsenseError) as exc:
        auth_servers, _ = await _auth_servers(db)
        return render(request, "tunnel_form.html", f=form, auth_servers=auth_servers, error=str(exc),
                      new=True, status_code=400)
    flash(request, f"Tunnel „{t.name}“ wurde auf der OPNsense angelegt und gestartet.")
    for n in notes:
        flash(request, n, "warn")
    return redirect(f"/tunnels/{t.id}")


@app.get("/tunnels/{tunnel_id}", response_class=HTMLResponse)
def tunnel_detail(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                  admin: Admin = Depends(require_admin)):
    return render(request, "tunnel.html", t=_get_tunnel(db, tunnel_id))


@app.get("/tunnels/{tunnel_id}/status", response_class=HTMLResponse)
async def tunnel_status(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                        admin: Admin = Depends(require_admin)):
    t = _get_tunnel(db, tunnel_id)
    error, st = None, None
    try:
        st = (await services.fetch_status(db)).get(t.opn_instance_uuid, {"running": False, "known": False,
                                                                         "sessions": []})
    except OPNsenseError as exc:
        error = str(exc)
    db.refresh(t)
    online = {s["common_name"] for s in (st or {}).get("sessions", [])}
    return render(request, "partials/tunnel_status.html", t=t, st=st, online=online, error=error)


@app.get("/tunnels/{tunnel_id}/edit", response_class=HTMLResponse)
def tunnel_edit_form(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                     admin: Admin = Depends(require_admin)):
    t = _get_tunnel(db, tunnel_id)
    f = {k: getattr(t, k) for k in ("name", "public_host", "port", "proto", "network", "mode", "routes",
                                     "dns_servers", "dns_domain", "session_hours", "auth_server")}
    return render(request, "tunnel_form.html", f=f, t=t, new=False)


@app.post("/tunnels/{tunnel_id}/edit")
async def tunnel_edit_submit(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                             admin: Admin = Depends(require_admin)):
    t = _get_tunnel(db, tunnel_id)
    form = await form_data(request)
    try:
        data = services.validate_tunnel(db, form, existing=t)
        notes = await services.update_tunnel(db, admin.username, t, data)
    except (ValidationError, OPNsenseError) as exc:
        db.rollback()
        f = {**form, "proto": t.proto, "network": t.network, "auth_server": t.auth_server}
        return render(request, "tunnel_form.html", f=f, t=t, new=False, error=str(exc), status_code=400)
    flash(request, "Tunnel gespeichert und auf der OPNsense übernommen.")
    for n in notes:
        flash(request, n, "warn")
    return redirect(f"/tunnels/{t.id}")


@app.post("/tunnels/{tunnel_id}/check", response_class=HTMLResponse)
async def tunnel_check(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                       admin: Admin = Depends(require_admin)):
    await form_data(request)
    t = _get_tunnel(db, tunnel_id)
    try:
        checks, error = await services.check_tunnel(db, t), None
    except OPNsenseError as exc:
        checks, error = [], str(exc)
    return render(request, "partials/test_result.html", checks=checks, error=error, all_ok=False,
                  only_fw_missing=False, auth_servers=[], totp_servers=[])


@app.post("/tunnels/{tunnel_id}/fw-rules")
async def tunnel_fw_rules(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                          admin: Admin = Depends(require_admin)):
    await form_data(request)
    t = _get_tunnel(db, tunnel_id)
    try:
        await services.create_fw_rules(db, admin.username, t)
        flash(request, "Firewall-Regeln wurden angelegt und aktiviert.")
    except OPNsenseError as exc:
        db.rollback()
        flash(request, f"Firewall-Regeln konnten nicht angelegt werden: {exc}", "error")
    return redirect(f"/tunnels/{t.id}")


@app.post("/tunnels/{tunnel_id}/restart")
async def tunnel_restart(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                         admin: Admin = Depends(require_admin)):
    await form_data(request)
    t = _get_tunnel(db, tunnel_id)
    try:
        await services.restart_tunnel(db, admin.username, t)
        flash(request, "Tunnel wird neu gestartet. Verbundene Benutzer verbinden sich automatisch neu.")
    except OPNsenseError as exc:
        flash(request, str(exc), "error")
    return redirect(f"/tunnels/{t.id}")


@app.get("/tunnels/{tunnel_id}/delete", response_class=HTMLResponse)
def tunnel_delete_form(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                       admin: Admin = Depends(require_admin)):
    return render(request, "tunnel_delete.html", t=_get_tunnel(db, tunnel_id))


@app.post("/tunnels/{tunnel_id}/delete")
async def tunnel_delete(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                        admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    t = _get_tunnel(db, tunnel_id)
    if form.get("confirm_name", "").strip() != t.name:
        flash(request, "Zum Löschen bitte den Tunnelnamen exakt eingeben.", "error")
        return redirect(f"/tunnels/{t.id}/delete")
    try:
        errors = await services.delete_tunnel(db, admin.username, t, force=bool(form.get("force")))
    except OPNsenseError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/tunnels/{t.id}/delete")
    flash(request, f"Tunnel „{t.name}“ und alle zugehörigen Benutzer wurden gelöscht.")
    for e in errors:
        flash(request, f"Hinweis: {e}", "warn")
    return redirect("/")


@app.post("/tunnels/{tunnel_id}/kill", response_class=HTMLResponse)
async def tunnel_kill(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                      admin: Admin = Depends(require_admin)):
    form = await form_data(request)
    t = _get_tunnel(db, tunnel_id)
    try:
        await services.kill_session(db, admin.username, t, form.get("session_id", ""))
    except OPNsenseError as exc:
        flash(request, str(exc), "error")
    return await tunnel_status(tunnel_id, request, db, admin)


# ------------------------------------------------------------------ VPN-Benutzer

def _get_user(db: Session, user_id: int) -> VpnUser:
    u = db.get(VpnUser, user_id)
    if u is None:
        raise NotFound()
    return u


@app.get("/tunnels/{tunnel_id}/users/new", response_class=HTMLResponse)
def user_new_form(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                  admin: Admin = Depends(require_admin)):
    return render(request, "user_form.html", t=_get_tunnel(db, tunnel_id), f={"platform": "all"})


@app.post("/tunnels/{tunnel_id}/users/new")
async def user_new_submit(tunnel_id: int, request: Request, db: Session = Depends(get_db),
                          admin: Admin = Depends(require_admin)):
    t = _get_tunnel(db, tunnel_id)
    form = await form_data(request)
    try:
        u = await services.create_user(db, admin.username, t, form)
    except (ValidationError, OPNsenseError) as exc:
        db.rollback()
        return render(request, "user_form.html", t=t, f=form, error=str(exc), status_code=400)
    flash(request, f"Benutzer „{u.username}“ wurde angelegt.")
    return redirect(f"/users/{u.id}")


@app.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(user_id: int, request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    u = _get_user(db, user_id)
    ctx = {"u": u, "t": u.tunnel}
    if u.has_pending:
        ctx["password"] = decrypt(u.pending_password_enc)
        seed = decrypt(u.pending_otp_enc)
        if seed:
            ctx["otp_seed"] = seed
            ctx["otp_qr"] = _svg_qr(package.otp_uri(u, seed, services.company(db)))
    return render(request, "user.html", **ctx)


@app.get("/users/{user_id}/package.zip")
def user_package(user_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_admin)):
    u = _get_user(db, user_id)
    filename, data = package.build_zip(u.tunnel, u, services.company(db), services.support_contact(db),
                                       services.windows_client(db))
    audit(db, admin.username, "user.download", u.username)
    db.commit()
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/users/{user_id}/zugangsdaten.pdf")
def user_credentials_pdf(user_id: int, request: Request, db: Session = Depends(get_db),
                         admin: Admin = Depends(require_admin)):
    u = _get_user(db, user_id)
    if not u.has_pending:
        flash(request, "Die Zugangsdaten sind nicht mehr abrufbar. Bitte Passwort bzw. 2FA neu erzeugen.", "error")
        return redirect(f"/users/{u.id}")
    pdf = package.credentials_pdf(u.tunnel, u, services.company(db), services.support_contact(db),
                                  decrypt(u.pending_password_enc), decrypt(u.pending_otp_enc))
    audit(db, admin.username, "user.credentials", u.username)
    db.commit()
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="Zugangsdaten_{u.username}.pdf"'})


USER_ACTIONS = {
    "password": (services.reset_password, "Neues Passwort erzeugt."),
    "otp": (services.reset_otp, "Neuer 2FA-Schlüssel erzeugt. Der Mitarbeiter muss den QR-Code neu scannen."),
    "reissue": (services.reissue_profile, "Neues VPN-Profil ausgestellt. Bitte das neue Paket weitergeben."),
    "disable": (lambda db, a, u: services.set_user_disabled(db, a, u, True), "Benutzer gesperrt."),
    "enable": (lambda db, a, u: services.set_user_disabled(db, a, u, False), "Benutzer entsperrt."),
}


@app.post("/users/{user_id}/done")
async def user_pending_done(user_id: int, request: Request, db: Session = Depends(get_db),
                            admin: Admin = Depends(require_admin)):
    await form_data(request)
    u = _get_user(db, user_id)
    services.clear_pending(u)
    audit(db, admin.username, "user.handover", u.username)
    db.commit()
    flash(request, "Zugangsdaten wurden aus dem Tool entfernt.")
    return redirect(f"/users/{u.id}")


@app.post("/users/{user_id}/delete")
async def user_delete(user_id: int, request: Request, db: Session = Depends(get_db),
                      admin: Admin = Depends(require_admin)):
    await form_data(request)
    u = _get_user(db, user_id)
    tunnel_id = u.tunnel_id
    try:
        await services.delete_user(db, admin.username, u)
        flash(request, f"Benutzer „{u.username}“ gelöscht.")
    except OPNsenseError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/users/{user_id}")
    return redirect(f"/tunnels/{tunnel_id}")


@app.post("/users/{user_id}/{action}")
async def user_action(user_id: int, action: str, request: Request, db: Session = Depends(get_db),
                      admin: Admin = Depends(require_admin)):
    await form_data(request)
    u = _get_user(db, user_id)
    if action not in USER_ACTIONS:
        raise NotFound()
    fn, message = USER_ACTIONS[action]
    try:
        await fn(db, admin.username, u)
        flash(request, message)
    except OPNsenseError as exc:
        db.rollback()
        flash(request, str(exc), "error")
    return redirect(f"/users/{u.id}")
