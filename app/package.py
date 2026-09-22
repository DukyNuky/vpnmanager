"""Erzeugt das Download-Paket (ZIP) und das Zugangsdatenblatt (PDF) für einen VPN-Benutzer."""
import io
import zipfile
from datetime import datetime
from pathlib import Path

import pyotp
import qrcode
from fpdf import FPDF

from .db import Tunnel, VpnUser
from .ovpn import OTP_PROMPT, profile_basename, render_ovpn

FONT_DIRS = [Path("/usr/share/fonts/truetype/dejavu"), Path("/usr/share/fonts/dejavu")]

PLATFORM_LABELS = {
    "all": "Alle Geräte",
    "windows": "Windows",
    "macos": "macOS",
    "android": "Android",
    "ios": "iPhone / iPad",
}

CLIENT_URL = "https://openvpn.net/client/"
COMMUNITY_URL = "https://openvpn.net/community-downloads/"

# Welcher Windows-Client in der Anleitung beschrieben wird (Einstellung "windows_client")
WINDOWS_CLIENTS = {
    "connect": "OpenVPN Connect (Standard)",
    "gui": "OpenVPN GUI (Community, Open Source)",
    "both": "Beide (Connect, GUI als Alternative)",
}

GUIDES: dict[str, list[str]] = {
    "windows": [
        f"Laden Sie die App „OpenVPN Connect“ für Windows herunter ({CLIENT_URL}) und installieren Sie sie. "
        "Falls Administratorrechte nötig sind, wenden Sie sich an Ihre IT.",
        "Entpacken Sie die ZIP-Datei (Rechtsklick → „Alle extrahieren…“).",
        "Starten Sie OpenVPN Connect und wählen Sie „Upload File“ (Datei hochladen). Ziehen Sie die Datei "
        "„{file}“ in das Fenster oder wählen Sie sie über „Browse“ aus.",
        "Tragen Sie bei „Username“ Ihren Benutzernamen „{user}“ ein. Lassen Sie „Save password“ ausgeschaltet "
        "und klicken Sie auf „Connect“.",
        "Geben Sie Ihr Passwort ein. Danach werden Sie nach dem „{otp}“ gefragt: Tragen Sie den aktuellen "
        "6-stelligen Code aus Ihrer Authenticator-App ein.",
        "Wird der Schalter grün, sind Sie verbunden. Zum Trennen schalten Sie ihn wieder aus.",
    ],
    "windows_gui": [
        f"Laden Sie den Windows-Installer von „OpenVPN Community“ herunter ({COMMUNITY_URL}, "
        "„Windows 64-bit MSI installer“) und installieren Sie ihn mit den Standardeinstellungen. "
        "Dafür sind Administratorrechte nötig – wenden Sie sich ggf. an Ihre IT.",
        "Entpacken Sie die ZIP-Datei (Rechtsklick → „Alle extrahieren…“).",
        "Starten Sie „OpenVPN GUI“ über das Startmenü. Unten rechts in der Taskleiste erscheint ein Symbol "
        "(Bildschirm mit Schloss), ggf. hinter dem Pfeil „^“.",
        "Klicken Sie mit der rechten Maustaste auf das Symbol → „Datei importieren…“ (engl. „Import file…“) "
        "und wählen Sie die Datei „{file}“ aus.",
        "Rechtsklick auf das Symbol → „Verbinden“ (bei mehreren Profilen zuerst das Profil auswählen).",
        "Tragen Sie Benutzername „{user}“ und Ihr Passwort ein und klicken Sie auf „OK“. Danach werden Sie "
        "nach dem „{otp}“ gefragt: Tragen Sie den aktuellen 6-stelligen Code aus Ihrer Authenticator-App ein.",
        "Wird das Symbol grün, sind Sie verbunden. Trennen: Rechtsklick → „Trennen“.",
    ],
    "macos": [
        f"Laden Sie die App „OpenVPN Connect“ für macOS herunter ({CLIENT_URL}) und installieren Sie sie.",
        "Öffnen Sie die ZIP-Datei per Doppelklick. Sie wird automatisch entpackt.",
        "Starten Sie OpenVPN Connect und wählen Sie „Upload File“. Ziehen Sie die Datei „{file}“ in das Fenster.",
        "Tragen Sie bei „Username“ Ihren Benutzernamen „{user}“ ein und klicken Sie auf „Connect“. "
        "macOS fragt ggf. nach der Erlaubnis, eine VPN-Konfiguration hinzuzufügen – bitte erlauben.",
        "Geben Sie Ihr Passwort ein. Danach werden Sie nach dem „{otp}“ gefragt: Tragen Sie den aktuellen "
        "6-stelligen Code aus Ihrer Authenticator-App ein.",
        "Wird der Schalter grün, sind Sie verbunden.",
    ],
    "android": [
        "Installieren Sie aus dem Google Play Store die App „OpenVPN Connect“ (Anbieter: OpenVPN).",
        "Übertragen Sie die Datei „{file}“ auf das Smartphone, z. B. per E-Mail an sich selbst oder über "
        "OneDrive / Google Drive, und speichern Sie sie in „Downloads“.",
        "Öffnen Sie OpenVPN Connect, tippen Sie auf „Upload File“ → „Browse“ und wählen Sie „{file}“ aus. "
        "Bestätigen Sie mit „OK“ bzw. „Import“.",
        "Tragen Sie bei „Username“ Ihren Benutzernamen „{user}“ ein und tippen Sie auf „Connect“.",
        "Bestätigen Sie die Android-Abfrage zur VPN-Verbindung mit „OK“.",
        "Geben Sie Ihr Passwort ein. Danach werden Sie nach dem „{otp}“ gefragt: Tragen Sie den aktuellen "
        "6-stelligen Code aus Ihrer Authenticator-App ein.",
        "Oben in der Statusleiste erscheint ein Schlüssel-Symbol – Sie sind verbunden.",
    ],
    "ios": [
        "Installieren Sie aus dem App Store die App „OpenVPN Connect“ (Anbieter: OpenVPN Inc.).",
        "Übertragen Sie die Datei „{file}“ auf das iPhone/iPad, z. B. per AirDrop, E-Mail oder OneDrive, "
        "und speichern Sie sie in der App „Dateien“.",
        "Tippen Sie die Datei in der App „Dateien“ an → Teilen-Symbol → „OpenVPN“. Alternativ in OpenVPN "
        "Connect: „Upload File“ → „Browse“.",
        "Tippen Sie auf „Add“, tragen Sie bei „Username“ Ihren Benutzernamen „{user}“ ein und tippen Sie auf "
        "„Connect“.",
        "iOS fragt „VPN-Konfigurationen hinzufügen“ – tippen Sie auf „Erlauben“ und bestätigen Sie mit Code "
        "oder Face ID.",
        "Geben Sie Ihr Passwort ein. Danach werden Sie nach dem „{otp}“ gefragt: Tragen Sie den aktuellen "
        "6-stelligen Code aus Ihrer Authenticator-App ein.",
        "Oben in der Statusleiste erscheint „VPN“ – Sie sind verbunden.",
    ],
}

AUTHENTICATOR_STEPS = [
    "Installieren Sie auf Ihrem Smartphone eine Authenticator-App, z. B. „Microsoft Authenticator“ oder "
    "„Google Authenticator“ (kostenlos im App Store / Google Play Store).",
    "Tippen Sie in der App auf „+“ bzw. „Konto hinzufügen“ → „Anderes Konto“ / „QR-Code scannen“.",
    "Scannen Sie den QR-Code auf Ihrem persönlichen Zugangsdatenblatt (erhalten Sie separat von Ihrer IT).",
    "Die App zeigt nun alle 30 Sekunden einen neuen 6-stelligen Code an. Diesen brauchen Sie bei jeder Anmeldung.",
]

HELP_ITEMS = [
    ("„Authentication failed“ / Anmeldung fehlgeschlagen",
     "Benutzername, Passwort und Code prüfen. Der Code ändert sich alle 30 Sekunden – immer den aktuellen "
     "verwenden. Die Uhrzeit des Smartphones muss stimmen (Einstellung „Datum/Uhrzeit automatisch“)."),
    ("Keine Verbindung möglich",
     "Internetverbindung prüfen. In manchen Hotel- oder Gast-WLANs ist VPN gesperrt – testweise den "
     "Mobilfunk-Hotspot verwenden."),
    ("Gerät verloren oder gestohlen",
     "Bitte sofort die IT informieren, damit Ihr Zugang gesperrt wird."),
]


def _font_file(name: str) -> Path | None:
    for d in FONT_DIRS:
        if (d / name).exists():
            return d / name
    return None


class _Pdf(FPDF):
    def __init__(self, footer_text: str):
        super().__init__(format="A4")
        self.footer_text = footer_text
        self.set_margins(18, 18, 18)
        self.set_auto_page_break(True, margin=18)
        regular, bold, mono = (_font_file(f) for f in ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf", "DejaVuSansMono.ttf"))
        if regular and bold and mono:
            self.add_font("body", "", str(regular))
            self.add_font("body", "B", str(bold))
            self.add_font("mono", "", str(mono))
            self.unicode = True
        else:
            self.unicode = False

    def t(self, s: str) -> str:
        if self.unicode:
            return s
        return (s.replace("„", '"').replace("“", '"').replace("–", "-").replace("→", "->")
                .encode("latin-1", "replace").decode("latin-1"))

    def use(self, style: str = "", size: float = 10.5, mono: bool = False):
        if self.unicode:
            self.set_font("mono" if mono else "body", "" if mono else style, size)
        else:
            self.set_font("Courier" if mono else "Helvetica", style, size)

    def footer(self):
        self.set_y(-12)
        self.use(size=8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, self.t(self.footer_text), align="L")
        self.cell(0, 5, f"{self.page_no()}", align="R")
        self.set_text_color(0, 0, 0)

    def title_block(self, title: str, subtitle: str):
        self.set_fill_color(30, 64, 120)
        self.rect(0, 0, 210, 32, style="F")
        self.set_xy(18, 9)
        self.set_text_color(255, 255, 255)
        self.use("B", 18)
        self.cell(0, 9, self.t(title), new_x="LMARGIN", new_y="NEXT")
        self.use(size=11)
        self.cell(0, 6, self.t(subtitle), new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.set_y(40)

    def h2(self, text: str):
        # Überschrift nicht allein am Seitenende stehen lassen
        if self.get_y() > self.h - self.b_margin - 30:
            self.add_page()
        self.ln(3)
        self.use("B", 13)
        self.set_text_color(30, 64, 120)
        self.multi_cell(0, 7, self.t(text), new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def para(self, text: str, size: float = 10.5):
        self.use(size=size)
        self.multi_cell(0, 5.5, self.t(text), align="L", new_x="LMARGIN", new_y="NEXT")
        self.ln(1.5)

    def steps(self, items: list[str]):
        for i, item in enumerate(items, 1):
            self.use("B")
            x = self.get_x()
            self.cell(8, 5.5, f"{i}.")
            self.use()
            self.set_x(x + 8)
            self.multi_cell(0, 5.5, self.t(item), align="L", new_x="LMARGIN", new_y="NEXT")
            self.ln(1.5)

    def kv(self, key: str, value: str, mono: bool = False):
        self.use("B")
        self.cell(45, 7, self.t(key))
        self.use(size=12 if mono else 10.5, mono=mono)
        self.cell(0, 7, self.t(value), new_x="LMARGIN", new_y="NEXT")

    def note(self, text: str):
        self.ln(2)
        self.set_fill_color(255, 244, 214)
        self.use(size=9.5)
        self.multi_cell(0, 5, self.t(text), align="L", fill=True, padding=3, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)


def _qr_png(data: str) -> io.BytesIO:
    img = qrcode.make(data, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def otp_uri(user: VpnUser, seed: str, company: str) -> str:
    return pyotp.TOTP(seed).provisioning_uri(name=user.username, issuer_name=f"{company or 'VPN'} VPN")


def _guide_sections(platform: str, windows_client: str) -> list[tuple[str, str]]:
    """Liste von (Überschrift, Guide-Schlüssel) für die gewählte Plattform."""
    platforms = ["windows", "macos", "android", "ios"] if platform == "all" else [platform]
    sections = []
    for p in platforms:
        if p != "windows":
            sections.append((f"Schritt 2: VPN einrichten – {PLATFORM_LABELS[p]}", p))
        elif windows_client == "gui":
            sections.append(("Schritt 2: VPN einrichten – Windows (OpenVPN GUI)", "windows_gui"))
        elif windows_client == "both":
            sections.append(("Schritt 2: VPN einrichten – Windows (OpenVPN Connect)", "windows"))
            sections.append(("Alternative für Windows: OpenVPN GUI (Community)", "windows_gui"))
        else:
            sections.append(("Schritt 2: VPN einrichten – Windows", "windows"))
    return sections


def _app_names(platform: str, windows_client: str) -> str:
    if platform == "windows" and windows_client == "gui":
        return "OpenVPN GUI"
    if windows_client in ("gui", "both") and platform in ("windows", "all"):
        return "OpenVPN Connect bzw. OpenVPN GUI"
    return "OpenVPN Connect"


def guide_pdf(tunnel: Tunnel, user: VpnUser, company: str, support: str, ovpn_file: str,
              windows_client: str = "connect") -> bytes:
    pdf = _Pdf(f"{company} – VPN-Anleitung für {user.username}")
    pdf.add_page()
    pdf.title_block(f"VPN-Zugang {company}".strip(), f"Anleitung für {user.full_name or user.username}")

    pdf.para(
        "Mit dem VPN-Zugang verbinden Sie sich von unterwegs oder aus dem Homeoffice sicher mit dem Firmennetz. "
        "Für die Anmeldung benötigen Sie drei Dinge:"
    )
    pdf.steps([
        f"die VPN-Datei „{ovpn_file}“ (in diesem Paket),",
        "Ihren Benutzernamen und Ihr Passwort (Zugangsdatenblatt, erhalten Sie separat),",
        "einen wechselnden 6-stelligen Code aus einer Authenticator-App auf Ihrem Smartphone.",
    ])
    pdf.kv("Benutzername:", user.username, mono=True)
    pdf.kv("Verbindung:", tunnel.name)

    pdf.h2("Schritt 1: Authenticator-App einrichten (einmalig)")
    if user.admin_id:
        pdf.para("Nicht nötig: Für diesen Zugang gilt derselbe Code wie bei Ihrer Anmeldung am VPN-Manager. "
                 "Verwenden Sie einfach den vorhandenen Eintrag in Ihrer Authenticator-App.")
    else:
        pdf.steps(AUTHENTICATOR_STEPS)

    for heading, key in _guide_sections(user.platform, windows_client):
        pdf.h2(heading)
        pdf.steps([s.format(file=ovpn_file, user=user.username, otp=OTP_PROMPT) for s in GUIDES[key]])

    pdf.h2("Tägliche Nutzung")
    pdf.para(
        f"Öffnen Sie {_app_names(user.platform, windows_client)} und stellen Sie die Verbindung her. Geben Sie "
        "Passwort und den aktuellen Code aus der Authenticator-App ein. Trennen Sie die Verbindung, wenn Sie sie "
        "nicht mehr benötigen."
    )

    pdf.h2("Hilfe bei Problemen")
    for title, text in HELP_ITEMS:
        pdf.use("B")
        pdf.multi_cell(0, 5.5, pdf.t(title), new_x="LMARGIN", new_y="NEXT")
        pdf.para(text)
    if support:
        pdf.note(f"Ansprechpartner bei Fragen: {support}")
    pdf.note(
        "Sicherheit: Geben Sie die VPN-Datei, Ihr Passwort und Ihre Codes niemals an andere weiter. "
        "Die IT wird Sie nie nach einem Code aus der Authenticator-App fragen."
    )
    return bytes(pdf.output())


def credentials_pdf(tunnel: Tunnel, user: VpnUser, company: str, support: str,
                    password: str | None, otp_seed: str | None) -> bytes:
    pdf = _Pdf(f"{company} – vertraulich – {user.username}")
    pdf.add_page()
    pdf.title_block("Persönliche VPN-Zugangsdaten", f"{company} · vertraulich".strip(" ·"))

    pdf.kv("Name:", user.full_name or "-")
    pdf.kv("Verbindung:", tunnel.name)
    pdf.kv("Benutzername:", user.username, mono=True)
    if password:
        pdf.kv("Passwort:", password, mono=True)
    pdf.kv("Erstellt am:", datetime.now().strftime("%d.%m.%Y"))

    if otp_seed:
        pdf.h2("Authenticator-App einrichten")
        pdf.para("Scannen Sie diesen QR-Code mit Microsoft Authenticator oder Google Authenticator:")
        y = pdf.get_y()
        pdf.image(_qr_png(otp_uri(user, otp_seed, company)), x=18, y=y, w=60, h=60)
        pdf.set_xy(84, y + 4)
        pdf.use(size=9.5)
        pdf.multi_cell(0, 5, align="L", text=pdf.t(
            "Falls das Scannen nicht klappt, wählen Sie in der App „Schlüssel manuell eingeben“ und "
            "tragen Sie diesen Schlüssel ein (Typ: zeitbasiert):"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(84)
        pdf.use(size=10.5, mono=True)
        grouped = " ".join(otp_seed[i:i + 4] for i in range(0, len(otp_seed), 4))
        pdf.multi_cell(0, 6, grouped, new_x="LMARGIN", new_y="NEXT")
        pdf.set_y(y + 64)

    if not otp_seed and user.admin_id:
        pdf.h2("2FA-Code")
        pdf.para("Für diesen Zugang gilt derselbe Code wie bei der Anmeldung am VPN-Manager "
                 "(vorhandener Eintrag in der Authenticator-App).")

    pdf.note(
        "Dieses Blatt ist vertraulich. Bewahren Sie es sicher auf oder vernichten Sie es nach der Einrichtung. "
        "Geben Sie es nicht zusammen mit der VPN-Datei weiter."
    )
    if support:
        pdf.para(f"Fragen: {support}", size=9.5)
    return bytes(pdf.output())


def build_zip(tunnel: Tunnel, user: VpnUser, company: str, support: str,
              windows_client: str = "connect") -> tuple[str, bytes]:
    base = profile_basename(company, tunnel, user)
    ovpn_name = f"{base}.ovpn"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(ovpn_name, render_ovpn(tunnel, user, company))
        zf.writestr("Anleitung.pdf", guide_pdf(tunnel, user, company, support, ovpn_name, windows_client))
        zf.writestr("LIESMICH.txt", (
            f"VPN-Zugang für {user.full_name or user.username}\r\n\r\n"
            f"1. Anleitung.pdf öffnen und den Schritten folgen.\r\n"
            f"2. Die Datei {ovpn_name} in die App \"{_app_names(user.platform, windows_client)}\" importieren.\r\n"
            f"3. Anmelden mit Benutzername, Passwort und Code aus der Authenticator-App.\r\n\r\n"
            f"Die Datei {ovpn_name} ist persönlich und darf nicht weitergegeben werden.\r\n"
        ).encode("utf-8-sig"))
    return f"{base}.zip", buf.getvalue()
