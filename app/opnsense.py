"""Schlanker Client für die OPNsense-REST-API (geprüft gegen OPNsense 26.x)."""
import logging
from typing import Any

import httpx

log = logging.getLogger("vpnmanager.opnsense")


class OPNsenseError(Exception):
    def __init__(self, message: str, validations: dict | None = None):
        self.validations = validations or {}
        if self.validations:
            details = "; ".join(f"{k.split('.')[-1]}: {v}" for k, v in self.validations.items())
            message = f"{message} ({details})"
        super().__init__(message)


class OPNsense:
    def __init__(self, url: str, api_key: str, api_secret: str, verify_tls: bool = True, timeout: float = 30):
        self.base = url.rstrip("/") + "/api/"
        self._client = httpx.AsyncClient(
            auth=(api_key, api_secret), verify=verify_tls, timeout=timeout,
            headers={"Accept": "application/json"},
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self._client.aclose()

    async def _request(self, method: str, path: str, payload: Any = None) -> Any:
        try:
            if method == "GET":
                resp = await self._client.get(self.base + path)
            else:
                resp = await self._client.post(self.base + path, json=payload if payload is not None else {})
        except httpx.ConnectError as exc:
            raise OPNsenseError(f"OPNsense nicht erreichbar: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise OPNsenseError("Zeitüberschreitung bei der Verbindung zur OPNsense") from exc
        except httpx.HTTPError as exc:
            raise OPNsenseError(f"Verbindungsfehler: {exc}") from exc

        log.info("%s %s → HTTP %s", method, path, resp.status_code)
        if resp.status_code in (401, 403):
            raise OPNsenseError(
                f"Zugriff verweigert auf {path} – API-Key/Secret oder Rechte des API-Benutzers prüfen"
            )
        if resp.status_code == 404:
            raise OPNsenseError(f"API-Endpunkt nicht gefunden: {path}")
        if resp.status_code >= 400:
            try:
                msg = resp.json().get("message") or resp.text[:300]
            except ValueError:
                msg = resp.text[:300]
            raise OPNsenseError(f"OPNsense-Fehler (HTTP {resp.status_code}): {msg}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise OPNsenseError("Ungültige Antwort der OPNsense (kein JSON)") from exc
        if isinstance(data, dict) and data.get("result") in ("failed", "not found"):
            log.warning("%s %s abgelehnt: %s", method, path, data)
            if data.get("result") == "not found":
                raise OPNsenseError(f"Objekt nicht gefunden: {path}")
            raise OPNsenseError(f"OPNsense hat die Eingaben abgelehnt ({path})", data.get("validations"))
        if isinstance(data, dict) and data.get("uuid"):
            log.info("%s %s → uuid %s", method, path, data["uuid"])
        return data

    async def get(self, path: str) -> Any:
        return await self._request("GET", path)

    async def post(self, path: str, payload: Any = None) -> Any:
        return await self._request("POST", path, payload)

    async def _add(self, path: str, root: str, obj: dict) -> str:
        data = await self.post(path, {root: obj})
        uuid = data.get("uuid")
        if not uuid:
            raise OPNsenseError(f"Anlegen fehlgeschlagen ({path}): {data}")
        return uuid

    async def _delete(self, path: str, uuid: str | None) -> None:
        if not uuid:
            return
        try:
            await self.post(f"{path}/{uuid}")
        except OPNsenseError as exc:
            if "nicht gefunden" not in str(exc):
                raise

    # ---------------------------------------------------------------- Allgemein

    ACCESS_CHECKS = [
        ("OpenVPN-Instanzen", "POST", "openvpn/instances/search"),
        ("OpenVPN-Status", "POST", "openvpn/service/search_sessions"),
        ("Zertifikate (Trust)", "POST", "trust/cert/search"),
        ("Zertifizierungsstellen (Trust)", "POST", "trust/ca/search"),
        ("Benutzerverwaltung", "POST", "auth/user/search"),
        ("Firewall-Regeln", "POST", "firewall/filter/search_rule"),
    ]

    async def check_access(self) -> list[tuple[str, bool, str]]:
        """Prüft Erreichbarkeit und Rechte. Rückgabe: [(Bereich, ok, Meldung)]."""
        results = []
        for label, method, path in self.ACCESS_CHECKS:
            try:
                await self._request(method, path, {"current": 1, "rowCount": 1})
                results.append((label, True, "OK"))
            except OPNsenseError as exc:
                results.append((label, False, str(exc)))
                if "nicht erreichbar" in str(exc) or "Zeitüberschreitung" in str(exc):
                    break
        return results

    async def auth_servers(self) -> list[str]:
        """Namen der konfigurierten Authentifizierungsserver (aus den Optionen einer leeren Instanz)."""
        data = await self.get("openvpn/instances/get")
        return list((data.get("instance", {}).get("authmode") or {}).keys())

    # ---------------------------------------------------------------- Trust

    async def import_ca(self, descr: str, crt_pem: str, refid: str) -> str:
        return await self._add("trust/ca/add", "ca", {
            "action": "existing", "descr": descr, "crt_payload": crt_pem, "refid": refid,
        })

    async def import_cert(self, descr: str, crt_pem: str, key_pem: str, refid: str) -> str:
        return await self._add("trust/cert/add", "cert", {
            "action": "import", "descr": descr, "crt_payload": crt_pem, "prv_payload": key_pem, "refid": refid,
        })

    async def delete_ca(self, uuid: str | None) -> None:
        await self._delete("trust/ca/del", uuid)

    async def delete_cert(self, uuid: str | None) -> None:
        await self._delete("trust/cert/del", uuid)

    # ---------------------------------------------------------------- OpenVPN

    async def add_static_key(self, descr: str, key: str) -> str:
        return await self._add("openvpn/instances/add_static_key", "statickey", {
            "mode": "crypt", "key": key, "description": descr,
        })

    async def delete_static_key(self, uuid: str | None) -> None:
        await self._delete("openvpn/instances/del_static_key", uuid)

    async def add_instance(self, obj: dict) -> str:
        return await self._add("openvpn/instances/add", "instance", obj)

    async def set_instance(self, uuid: str, obj: dict) -> None:
        await self.post(f"openvpn/instances/set/{uuid}", {"instance": obj})

    async def _get_obj(self, path: str, root: str) -> dict:
        """Liefert ein Objekt per get/<uuid>; {} wenn es nicht existiert (OPNsense antwortet dann mit [])."""
        data = await self.get(path)
        return data.get(root) or {} if isinstance(data, dict) else {}

    async def get_instance(self, uuid: str) -> dict:
        return await self._get_obj(f"openvpn/instances/get/{uuid}", "instance")

    async def get_ca(self, uuid: str) -> dict:
        return await self._get_obj(f"trust/ca/get/{uuid}", "ca")

    async def get_cert(self, uuid: str) -> dict:
        return await self._get_obj(f"trust/cert/get/{uuid}", "cert")

    async def get_static_key(self, uuid: str) -> dict:
        return await self._get_obj(f"openvpn/instances/get_static_key/{uuid}", "statickey")

    async def get_rule(self, uuid: str) -> dict:
        return await self._get_obj(f"firewall/filter/get_rule/{uuid}", "rule")

    async def get_user(self, uuid: str) -> dict:
        return await self._get_obj(f"auth/user/get/{uuid}", "user")

    async def delete_instance(self, uuid: str | None) -> None:
        await self._delete("openvpn/instances/del", uuid)

    async def toggle_instance(self, uuid: str, enabled: bool) -> None:
        await self.post(f"openvpn/instances/toggle/{uuid}/{1 if enabled else 0}")

    async def reconfigure_openvpn(self) -> None:
        await self.post("openvpn/service/reconfigure")

    async def restart_instance(self, uuid: str) -> None:
        await self.post(f"openvpn/service/restart_service/{uuid}")

    async def sessions(self) -> list[dict]:
        data = await self.post("openvpn/service/search_sessions", {"current": 1, "rowCount": 9999, "type": ["server"]})
        return data.get("rows", [])

    async def kill_session(self, instance_uuid: str, session_id: str) -> None:
        await self.post("openvpn/service/kill_session", {"server_id": instance_uuid, "session_id": session_id})

    # ---------------------------------------------------------------- Benutzer

    async def add_user(self, name: str, password: str, otp_seed: str, descr: str, email: str) -> str:
        return await self._add("auth/user/add", "user", {
            "name": name, "password": password, "otp_seed": otp_seed, "descr": descr, "email": email,
            "disabled": "0", "scope": "user", "comment": "verwaltet durch vpnmanager",
        })

    async def set_user(self, uuid: str, name: str, **fields: str) -> None:
        # name wird von der API für Audit/Sync benötigt
        await self.post(f"auth/user/set/{uuid}", {"user": {"name": name, **fields}})

    async def delete_user(self, uuid: str | None) -> None:
        await self._delete("auth/user/del", uuid)

    async def find_user(self, name: str) -> dict | None:
        data = await self.post("auth/user/search", {"current": 1, "rowCount": 9999, "searchPhrase": name})
        for row in data.get("rows", []):
            if row.get("name") == name:
                return row
        return None

    # ---------------------------------------------------------------- Firewall

    async def add_rule(self, obj: dict) -> str:
        return await self._add("firewall/filter/add_rule", "rule", obj)

    async def set_rule(self, uuid: str, obj: dict) -> None:
        await self.post(f"firewall/filter/set_rule/{uuid}", {"rule": obj})

    async def delete_rule(self, uuid: str | None) -> None:
        await self._delete("firewall/filter/del_rule", uuid)

    async def apply_firewall(self) -> None:
        await self.post("firewall/filter/apply")
