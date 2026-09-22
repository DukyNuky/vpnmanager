"""SMTP-Versand (Einstellungen → E-Mail)."""
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from sqlalchemy.orm import Session

from .db import get_setting
from .security import decrypt

SECURITY_OPTIONS = {
    "starttls": "STARTTLS (meist Port 587)",
    "ssl": "SSL/TLS (meist Port 465)",
    "none": "Keine Verschlüsselung (Port 25, nur intern)",
}


class MailError(Exception):
    pass


@dataclass
class SmtpConfig:
    host: str
    port: int
    security: str
    username: str
    password: str
    sender: str
    sender_name: str
    verify_tls: bool


def smtp_config(db: Session) -> SmtpConfig | None:
    host = get_setting(db, "smtp_host", "")
    sender = get_setting(db, "smtp_sender", "")
    if not host or not sender:
        return None
    return SmtpConfig(
        host=host,
        port=int(get_setting(db, "smtp_port", "587") or 587),
        security=get_setting(db, "smtp_security", "starttls") or "starttls",
        username=get_setting(db, "smtp_username", "") or "",
        password=decrypt(get_setting(db, "smtp_password_enc")) or "",
        sender=sender,
        sender_name=get_setting(db, "smtp_sender_name", "") or "",
        verify_tls=get_setting(db, "smtp_verify_tls", "1") == "1",
    )


def mail_configured(db: Session) -> bool:
    return smtp_config(db) is not None


def send_mail(cfg: SmtpConfig, to: str, subject: str, body: str,
              attachments: list[tuple[str, bytes, str]] | None = None) -> None:
    """Versendet eine Text-Mail (blockierend – aus async-Code per run_in_threadpool aufrufen)."""
    msg = EmailMessage()
    msg["From"] = formataddr((cfg.sender_name, cfg.sender)) if cfg.sender_name else cfg.sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=cfg.sender.split("@")[-1] or None)
    msg.set_content(body)
    for filename, data, mime in attachments or []:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    context = ssl.create_default_context()
    if not cfg.verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        if cfg.security == "ssl":
            server = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=20, context=context)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=20)
        with server:
            server.ehlo()
            if cfg.security == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if cfg.username:
                server.login(cfg.username, cfg.password)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError("SMTP-Anmeldung fehlgeschlagen – Benutzername/Passwort prüfen.") from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise MailError(f"Empfänger „{to}“ wurde vom Mailserver abgelehnt.") from exc
    except smtplib.SMTPSenderRefused as exc:
        raise MailError(f"Absender „{cfg.sender}“ wurde vom Mailserver abgelehnt (darf das Konto so senden?).") from exc
    except ssl.SSLError as exc:
        raise MailError(f"TLS-Fehler: {exc.reason or exc}. Verschlüsselungsart/Port prüfen.") from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"Mailversand fehlgeschlagen: {exc}") from exc
