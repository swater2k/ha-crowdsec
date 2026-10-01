"""Setup, Entitäten, Ereignisse, Fehlerbehandlung, Aktionen und Config-Flow."""

from __future__ import annotations

import json

import aiohttp
from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import area_registry as ar, device_registry as dr
import pytest
from pytest_homeassistant_custom_component.common import async_capture_events
from pytest_homeassistant_custom_component.test_util.aiohttp import (
    AiohttpClientMocker,
    AiohttpClientMockResponse,
)
import voluptuous as vol

from custom_components.crowdsec.const import DOMAIN

from .conftest import ENTRY_DATA, MACHINE, URL, load, mock_api

EVENT = "event.crowdsec_new_ban"


async def _setup(hass: HomeAssistant, entry) -> None:
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


async def _refresh(hass: HomeAssistant, entry) -> None:
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()


def _calls(aioclient_mock: AiohttpClientMocker, path: str, method: str | None = None) -> list:
    return [
        c
        for c in aioclient_mock.mock_calls
        if c[1].path == path and (method is None or c[0].lower() == method.lower())
    ]


def _event_changes(events) -> list:
    return [
        e.data["new_state"]
        for e in events
        if e.data["entity_id"] == EVENT
        and e.data["new_state"].attributes.get("event_type") == "ban"
    ]


# --------------------------------------------------------------------------- #
# Entitäten                                                                    #
# --------------------------------------------------------------------------- #


async def test_entities(hass: HomeAssistant, config_entry, aioclient_mock, freezer) -> None:
    freezer.move_to("2026-10-01T14:00:00+00:00")
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    assert config_entry.state is ConfigEntryState.LOADED

    # Zwei Alerts für dieselbe Adresse ergeben eine Sperre.
    active = hass.states.get("sensor.crowdsec_active_bans")
    assert active.state == "3"
    assert [b["value"] for b in active.attributes["bans"]] == [
        "2001:db8:1003::20",
        "198.51.100.53",
        "203.0.113.46",
    ]
    assert hass.states.get("sensor.crowdsec_bans_last_hour").state == "1"

    alerts = hass.states.get("sensor.crowdsec_alerts_last_24_hours")
    assert alerts.state == "4"
    assert alerts.attributes["top_countries"] == {"LT": 2, "US": 1, "TR": 1}
    assert len(alerts.attributes["top_scenarios"]) == 4

    last = hass.states.get("sensor.crowdsec_last_ban")
    assert last.state == "2001:db8:1003::20"
    assert last.attributes["scenario"] == "crowdsecurity/http-bad-user-agent"
    assert last.attributes["country"] == "US"
    assert last.attributes["scope"] == "Ip"
    assert last.attributes["origin"] == "crowdsec"
    assert last.attributes["decision_id"] == 555094

    assert hass.states.get("binary_sensor.crowdsec_lapi_reachable").state == "on"
    # Der erste Abruf meldet nichts – sonst feuert jeder Neustart für alle Sperren.
    assert hass.states.get(EVENT).state == "unknown"


async def test_only_local_origins_are_requested(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    """Der Filter muss auf dem Server greifen: CAPI-Alerts hängen Tausende Decisions an."""
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    alert_calls = _calls(aioclient_mock, "/v1/alerts", "GET")
    assert len(alert_calls) == 4
    assert {c[1].query["origin"] for c in alert_calls} == {"crowdsec", "cscli"}
    assert all("origin" in c[1].query for c in alert_calls)
    assert all(c[3]["Authorization"] == "Bearer jwt-token" for c in alert_calls)


async def test_stats_polled_less_often(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    since = lambda: [  # noqa: E731
        c for c in _calls(aioclient_mock, "/v1/alerts", "GET") if "since" in c[1].query
    ]
    assert len(since()) == 2
    await _refresh(hass, config_entry)
    await _refresh(hass, config_entry)
    assert len(since()) == 2
    assert len(_calls(aioclient_mock, "/v1/alerts", "GET")) == 2 + 2 * 3


async def test_manual_range_ban_is_listed(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock, manual=load("alerts_manual"))
    await _setup(hass, config_entry)
    assert hass.states.get("sensor.crowdsec_active_bans").state == "4"


# --------------------------------------------------------------------------- #
# Ereignisse                                                                   #
# --------------------------------------------------------------------------- #


async def test_new_ban_fires_one_event_per_value(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    changes = async_capture_events(hass, "state_changed")

    # 192.0.2.77 kommt mit zwei Alerts, 192.0.2.88 mit einem: zwei Ereignisse.
    mock_api(aioclient_mock, active=load("alerts_crowdsec") + load("alerts_new"))
    await _refresh(hass, config_entry)

    fired = _event_changes(changes)
    assert len(fired) == 2
    assert [s.attributes["value"] for s in fired] == ["192.0.2.77", "192.0.2.88"]
    state = hass.states.get(EVENT)
    assert state.attributes["event_type"] == "ban"
    assert state.attributes["value"] == "192.0.2.88"
    assert state.attributes["scope"] == "Ip"
    assert state.attributes["origin"] == "crowdsec"
    assert state.attributes["scenario"] == "crowdsecurity/http-crawl-non_statics"
    assert state.attributes["country"] == "FR"
    assert state.attributes["decision_id"] == 555202
    assert state.attributes["expires_at"] is not None
    assert hass.states.get("sensor.crowdsec_active_bans").state == "5"


async def test_no_event_without_change(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    changes = async_capture_events(hass, "state_changed")
    await _refresh(hass, config_entry)
    await _refresh(hass, config_entry)
    assert _event_changes(changes) == []


async def test_manual_ban_reports_origin_cscli(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    mock_api(aioclient_mock, manual=load("alerts_manual"))
    await _refresh(hass, config_entry)
    state = hass.states.get(EVENT)
    assert state.attributes["origin"] == "cscli"
    assert state.attributes["scope"] == "Range"
    assert state.attributes["value"] == "2001:db8:aa::/64"


async def test_expired_ban_and_return_fires_again(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    mock_api(aioclient_mock, active=load("alerts_crowdsec")[:1])  # zwei Sperren laufen ab
    await _refresh(hass, config_entry)
    assert hass.states.get("sensor.crowdsec_active_bans").state == "1"
    changes = async_capture_events(hass, "state_changed")
    mock_api(aioclient_mock)  # und kommen wieder
    await _refresh(hass, config_entry)
    assert len(_event_changes(changes)) == 2


# --------------------------------------------------------------------------- #
# Fehlerbehandlung                                                             #
# --------------------------------------------------------------------------- #


async def test_login_rejected_starts_reauth(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock, login_status=403)
    config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)


async def test_unreachable_lapi_retries_setup(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    aioclient_mock.post(f"{URL}/v1/watchers/login", exc=aiohttp.ClientError)
    config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    assert config_entry.state is ConfigEntryState.SETUP_RETRY


async def test_expired_token_logs_in_again(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    assert len(_calls(aioclient_mock, "/v1/watchers/login")) == 1

    answers = iter([401])

    async def _active(method, url, data):
        if next(answers, 200) == 401:
            return AiohttpClientMockResponse(method, url, status=401)
        return AiohttpClientMockResponse(method, url, text=json.dumps(load("alerts_crowdsec")))

    mock_api(aioclient_mock, active_effect=_active)
    await _refresh(hass, config_entry)
    assert config_entry.runtime_data.last_update_success
    # mock_api setzt die Aufrufhistorie zurück: der eine Login ist die erneute Anmeldung.
    assert len(_calls(aioclient_mock, "/v1/watchers/login")) == 1
    assert hass.states.get("sensor.crowdsec_active_bans").state == "3"


async def test_outage_shows_in_binary_sensor_and_recovers_quietly(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)

    aioclient_mock.clear_requests()
    aioclient_mock.get(f"{URL}/v1/alerts", exc=aiohttp.ClientError)
    await _refresh(hass, config_entry)
    assert hass.states.get("binary_sensor.crowdsec_lapi_reachable").state == "off"
    assert hass.states.get("sensor.crowdsec_active_bans").state == "unavailable"

    # Nach dem Ausfall melden unveränderte Sperren nichts als neu.
    changes = async_capture_events(hass, "state_changed")
    mock_api(aioclient_mock)
    await _refresh(hass, config_entry)
    assert hass.states.get("binary_sensor.crowdsec_lapi_reachable").state == "on"
    assert _event_changes(changes) == []


# --------------------------------------------------------------------------- #
# Aktionen                                                                     #
# --------------------------------------------------------------------------- #


async def test_actions_need_options(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(
            DOMAIN, "delete_decision", {"ip": "203.0.113.7"}, blocking=True
        )
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "add_decision", {"ip": "203.0.113.7"}, blocking=True)


@pytest.mark.parametrize("options", [{"control_unban": True}])
@pytest.mark.parametrize(
    ("target", "param", "value"),
    [
        ("203.0.113.7", "ip", "203.0.113.7"),
        ("203.0.113.7/32", "ip", "203.0.113.7"),
        ("2001:db8:1003::20", "ip", "2001:db8:1003::20"),
        ("2001:db8:1003::/64", "range", "2001:db8:1003::/64"),
    ],
)
async def test_delete_decision(
    hass: HomeAssistant, config_entry, aioclient_mock, target, param, value
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    mock_api(aioclient_mock)
    aioclient_mock.delete(f"{URL}/v1/decisions", text=json.dumps({"nbDeleted": "2"}))
    result = await hass.services.async_call(
        DOMAIN, "delete_decision", {"ip": target}, blocking=True, return_response=True
    )
    assert result == {"deleted": 2}
    ((_, url, _, headers),) = _calls(aioclient_mock, "/v1/decisions", "DELETE")
    assert url.query[param] == value
    assert len(url.query) == 1
    assert headers["Authorization"] == "Bearer jwt-token"


@pytest.mark.parametrize("options", [{"control_unban": True}])
async def test_delete_decision_rejects_garbage(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    with pytest.raises(vol.Invalid, match="invalid IP"):
        await hass.services.async_call(
            DOMAIN, "delete_decision", {"ip": "not-an-ip"}, blocking=True
        )
    assert _calls(aioclient_mock, "/v1/decisions", "DELETE") == []


@pytest.mark.parametrize("options", [{"control_ban": True}])
async def test_add_decision(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    mock_api(aioclient_mock)
    aioclient_mock.post(f"{URL}/v1/alerts", text='["42"]')
    await hass.services.async_call(
        DOMAIN,
        "add_decision",
        {"ip": "203.0.113.0/24", "duration": "24h", "reason": "test"},
        blocking=True,
    )
    ((_, _, body, _),) = _calls(aioclient_mock, "/v1/alerts", "POST")
    (alert,) = body
    (decision,) = alert["decisions"]
    assert decision["value"] == "203.0.113.0/24"
    assert decision["scope"] == "Range"
    assert decision["type"] == "ban"
    assert decision["duration"] == "24h"
    assert decision["origin"] == "cscli"
    assert alert["source"] == {"scope": "Range", "value": "203.0.113.0/24"}
    assert alert["message"] == "test"
    assert alert["scenario"] == f"manual 'range' from '{MACHINE}'"


@pytest.mark.parametrize("options", [{"control_ban": True}])
@pytest.mark.parametrize("duration", ["4d", "forever", "1h 30m"])
async def test_add_decision_rejects_bad_duration(
    hass: HomeAssistant, config_entry, aioclient_mock, duration
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    with pytest.raises(vol.Invalid, match="does not match"):
        await hass.services.async_call(
            DOMAIN, "add_decision", {"ip": "203.0.113.7", "duration": duration}, blocking=True
        )


# --------------------------------------------------------------------------- #
# Verschiedenes                                                                #
# --------------------------------------------------------------------------- #


async def test_entity_ids_ignore_area(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    """Auch wenn das Gerät schon einen Bereich hat, bekommen Entitäten kein Bereichs-Präfix."""
    mock_api(aioclient_mock)
    config_entry.add_to_hass(hass)
    area = ar.async_get(hass).async_create("Waschraum")
    devices = dr.async_get(hass)
    device = devices.async_get_or_create(
        config_entry_id=config_entry.entry_id, identifiers={(DOMAIN, config_entry.entry_id)}
    )
    devices.async_update_device(device.id, area_id=area.id)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("sensor.crowdsec_active_bans") is not None
    assert not [e for e in hass.states.async_entity_ids() if "waschraum" in e]


async def test_unload(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    assert await hass.config_entries.async_unload(config_entry.entry_id)
    assert config_entry.state is ConfigEntryState.NOT_LOADED


# --------------------------------------------------------------------------- #
# Config-Flow                                                                  #
# --------------------------------------------------------------------------- #


async def test_user_flow(hass: HomeAssistant, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            "url": "192.0.2.144",
            "machine_id": " homeassistant ",
            "password": "secret",
            "verify_ssl": True,
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "CrowdSec (192.0.2.144)"
    assert result["data"] == ENTRY_DATA
    assert result["result"].unique_id == MACHINE


@pytest.mark.parametrize(
    ("url", "login", "error"),
    [
        (URL, {"status": 403}, "invalid_auth"),
        (URL, {"status": 401}, "invalid_auth"),
        (URL, {"exc": aiohttp.ClientError}, "cannot_connect"),
        (URL, {"status": 500}, "cannot_connect"),
        (URL, {"status": 200, "text": "<html>kein CrowdSec</html>"}, "cannot_connect"),
        ("ftp://192.0.2.144", {"status": 200}, "invalid_url"),
    ],
)
async def test_user_flow_errors(hass: HomeAssistant, aioclient_mock, url, login, error) -> None:
    aioclient_mock.post(f"{URL}/v1/watchers/login", **login)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**ENTRY_DATA, "url": url}
    )
    assert result["errors"] == {"base": error}


async def test_user_flow_already_configured(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], ENTRY_DATA)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reauth(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    config_entry.add_to_hass(hass)
    mock_api(aioclient_mock)
    result = await config_entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"password": "new"})
    assert result["reason"] == "reauth_successful"
    assert config_entry.data["password"] == "new"
    assert config_entry.data["machine_id"] == MACHINE


async def test_reconfigure_rejects_other_machine(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    config_entry.add_to_hass(hass)
    mock_api(aioclient_mock)
    result = await config_entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**ENTRY_DATA, "machine_id": "somebody-else"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "different_machine"


async def test_reconfigure_changes_address(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    config_entry.add_to_hass(hass)
    mock_api(aioclient_mock)
    aioclient_mock.post(
        "http://192.0.2.200:8080/v1/watchers/login", text=json.dumps({"token": "t"})
    )
    result = await config_entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**ENTRY_DATA, "url": "192.0.2.200"}
    )
    assert result["reason"] == "reconfigure_successful"
    assert config_entry.data["url"] == "http://192.0.2.200:8080"


async def test_options_enable_controls(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    result = await hass.config_entries.options.async_init(config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"scan_interval": 30, "control_unban": True}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    assert config_entry.options == {
        "scan_interval": 30,
        "control_unban": True,
        "control_ban": False,
    }
    assert config_entry.runtime_data.update_interval.total_seconds() == 30
