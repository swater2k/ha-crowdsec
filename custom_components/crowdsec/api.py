"""Minimaler Client für die CrowdSec-Local-API (Watcher-Login per JWT)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from .bans import parse_time
from .const import DEFAULT_PORT, USER_AGENT

TIMEOUT = aiohttp.ClientTimeout(total=15)
# Token kurz vor Ablauf erneuern, damit kein Abruf mit einem toten Token startet.
TOKEN_MARGIN = timedelta(seconds=60)


class CrowdSecError(Exception):
    """Basisfehler."""


class CrowdSecAuthError(CrowdSecError):
    """Login abgelehnt: Passwort falsch oder Machine nicht validiert."""


class CrowdSecConnectionError(CrowdSecError):
    """LAPI nicht erreichbar oder Antwort nicht lesbar."""


def normalize_url(value: str) -> str:
    """``192.0.2.1`` -> ``http://192.0.2.1:8080``; https bleibt ohne Port, Pfad entfällt."""
    value = value.strip()
    if "://" not in value:
        value = f"http://{value}"
    parts = urlsplit(value)
    host = parts.hostname
    if not host or parts.scheme not in ("http", "https"):
        raise ValueError(value)
    if ":" in host:  # IPv6
        host = f"[{host}]"
    port = parts.port or (DEFAULT_PORT if parts.scheme == "http" else None)
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


class CrowdSecApi:
    def __init__(
        self, session: aiohttp.ClientSession, base_url: str, machine_id: str, password: str
    ) -> None:
        self._session = session
        self._base = base_url.rstrip("/")
        self._machine_id = machine_id
        self._password = password
        self._token: str | None = None
        self._expires: datetime | None = None
        self._login_lock = asyncio.Lock()

    @property
    def machine_id(self) -> str:
        return self._machine_id

    async def _login(self) -> None:
        try:
            async with self._session.post(
                f"{self._base}/v1/watchers/login",
                json={"machine_id": self._machine_id, "password": self._password},
                headers={"User-Agent": USER_AGENT},
                timeout=TIMEOUT,
            ) as resp:
                if resp.status in (401, 403):
                    raise CrowdSecAuthError("login rejected")
                resp.raise_for_status()
                data = await resp.json(content_type=None)
        except (aiohttp.ClientError, TimeoutError, ValueError) as err:
            raise CrowdSecConnectionError(str(err)) from err
        token = data.get("token") if isinstance(data, dict) else None
        if not token:
            raise CrowdSecConnectionError("login response without token")
        self._token = token
        self._expires = parse_time(data.get("expire"))

    def _token_valid(self) -> bool:
        if not self._token:
            return False
        if self._expires is None:
            return True
        return datetime.now(UTC) < self._expires - TOKEN_MARGIN

    async def _ensure_token(self) -> None:
        async with self._login_lock:
            if not self._token_valid():
                await self._login()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        for attempt in (1, 2):
            await self._ensure_token()
            try:
                async with self._session.request(
                    method,
                    f"{self._base}{path}",
                    headers={"Authorization": f"Bearer {self._token}", "User-Agent": USER_AGENT},
                    timeout=TIMEOUT,
                    **kwargs,
                ) as resp:
                    if resp.status == 401 and attempt == 1:
                        self._token = None  # abgelaufen oder widerrufen -> neu anmelden
                        continue
                    if resp.status in (401, 403):
                        raise CrowdSecAuthError(f"{method} {path}: {resp.status}")
                    resp.raise_for_status()
                    # „keine Treffer“ liefert die LAPI je nach Version als null.
                    return await resp.json(content_type=None)
            except (aiohttp.ClientError, TimeoutError, ValueError) as err:
                raise CrowdSecConnectionError(str(err)) from err
        raise CrowdSecConnectionError(f"{method} {path}: no response")  # pragma: no cover

    async def async_check(self) -> None:
        """Für den Config-Flow: nur anmelden."""
        async with self._login_lock:
            await self._login()

    async def async_get_alerts(self, **params: Any) -> list[dict[str, Any]]:
        return await self._request("GET", "/v1/alerts", params=params) or []

    async def async_delete_decisions(
        self, *, ip: str | None = None, range_: str | None = None
    ) -> int:
        """Löscht Sperren; ``ip`` löscht – wie ``cscli`` – auch Bereiche mit dieser Adresse."""
        params = {"ip": ip} if ip else {"range": range_}
        result = await self._request("DELETE", "/v1/decisions", params=params)
        try:
            return int((result or {}).get("nbDeleted", 0))
        except (TypeError, ValueError):
            return 0

    async def async_add_decision(
        self, *, scope: str, value: str, duration: str, reason: str
    ) -> None:
        """Legt eine manuelle Sperre an – derselbe Alert, den ``cscli decisions add`` sendet."""
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        scenario = f"manual '{scope.lower()}' from '{self._machine_id}'"
        alert = {
            "capacity": 0,
            "decisions": [
                {
                    "duration": duration,
                    "origin": "cscli",
                    "scenario": scenario,
                    "scope": scope,
                    "simulated": False,
                    "type": "ban",
                    "value": value,
                }
            ],
            "events": [],
            "events_count": 1,
            "leakspeed": "0",
            "message": reason,
            "remediation": True,
            "scenario": scenario,
            "scenario_hash": "",
            "scenario_version": "",
            "simulated": False,
            "source": {"scope": scope, "value": value},
            "start_at": now,
            "stop_at": now,
        }
        await self._request("POST", "/v1/alerts", json=[alert])
