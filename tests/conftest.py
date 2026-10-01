"""Pytest-Setup."""

from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.crowdsec.const import DOMAIN

FIXTURES = Path(__file__).parent / "fixtures"
URL = "http://192.0.2.144:8080"
MACHINE = "homeassistant"
ENTRY_DATA = {"url": URL, "machine_id": MACHINE, "password": "secret", "verify_ssl": True}
LOGIN_OK = {"code": 200, "expire": "2099-01-01T00:00:00Z", "token": "jwt-token"}


def load(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def mock_api(
    aioclient_mock,
    *,
    active: list | None = None,
    manual: list | None = None,
    recent: list | None = None,
    login_status: int = 200,
    url: str = URL,
    active_effect: Callable | None = None,
) -> None:
    """Registriert Login und die vier Alert-Abfragen (aktiv/24 h je Herkunft).

    ``active`` und ``manual`` sind die Alerts mit aktiver Sperre der Herkunft
    ``crowdsec`` bzw. ``cscli``; ``recent`` ersetzt die 24-Stunden-Abfrage von
    ``crowdsec`` (Standard: wie ``active``).
    """
    aioclient_mock.clear_requests()
    active = load("alerts_crowdsec") if active is None else active
    manual = [] if manual is None else manual
    recent = active if recent is None else recent
    aioclient_mock.post(f"{url}/v1/watchers/login", status=login_status, text=json.dumps(LOGIN_OK))
    if active_effect is not None:
        aioclient_mock.get(
            f"{url}/v1/alerts?has_active_decision=true&origin=crowdsec", side_effect=active_effect
        )
    else:
        aioclient_mock.get(
            f"{url}/v1/alerts?has_active_decision=true&origin=crowdsec", text=json.dumps(active)
        )
    aioclient_mock.get(
        f"{url}/v1/alerts?has_active_decision=true&origin=cscli", text=json.dumps(manual)
    )
    aioclient_mock.get(f"{url}/v1/alerts?since=24h&origin=crowdsec", text=json.dumps(recent))
    # Die LAPI antwortet bei „keine Treffer“ teils mit null statt [].
    aioclient_mock.get(f"{url}/v1/alerts?since=24h&origin=cscli", text="null")


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
def options() -> dict[str, Any]:
    return {"scan_interval": 60}


@pytest.fixture
def config_entry(options) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        title="CrowdSec (192.0.2.144)",
        data=ENTRY_DATA,
        unique_id=MACHINE,
        options=options,
    )
