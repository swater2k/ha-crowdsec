"""Entitäten aus den Prometheus-Metriken: Agents, Bouncer, Blocklist und der Options-Flow dazu."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr
import pytest

from custom_components.crowdsec.const import DOMAIN

from .conftest import mock_api

FIXTURES = Path(__file__).parent / "fixtures"
LAPI_METRICS = "http://192.0.2.144:6060/metrics"
AGENT_METRICS = "http://192.0.2.20:6060/metrics"
METRIC_OPTIONS = {
    "scan_interval": 60,
    "web_ui_url": "https://crowdsec.example.org",
    "metrics_url": LAPI_METRICS,
    "agent_metrics": f"caddy-agent = {AGENT_METRICS}",
    "agent_timeout": 5,
    "bouncer_timeout": 10,
    "log_timeout": 60,
}


def _mock_metrics(aioclient_mock, *, lapi: str | None = None, agent: str | None = None) -> None:
    lapi = (FIXTURES / "metrics_lapi.txt").read_text() if lapi is None else lapi
    agent = (FIXTURES / "metrics_agent.txt").read_text() if agent is None else agent
    aioclient_mock.get(LAPI_METRICS, text=lapi)
    aioclient_mock.get(AGENT_METRICS, text=agent)


async def _setup(hass: HomeAssistant, entry) -> None:
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


async def _refresh(hass: HomeAssistant, entry) -> None:
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()


def _device(hass: HomeAssistant, entry, identifier: str) -> dr.DeviceEntry:
    """Neuere Versionen suchen je Konfigurationseintrag, ältere nur über die Kennung."""
    devices = dr.async_get(hass)
    if hasattr(devices, "async_get_device_by_identifier"):
        device = devices.async_get_device_by_identifier((DOMAIN, identifier), entry.entry_id)
    else:
        device = devices.async_get_device(identifiers={(DOMAIN, identifier)})
    assert device is not None, identifier
    return device


def _state(hass: HomeAssistant, entity_id: str) -> str:
    state = hass.states.get(entity_id)
    assert state is not None, entity_id
    return state.state


async def test_without_metrics_only_alert_sensors_per_agent(
    hass: HomeAssistant, config_entry, aioclient_mock
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_alerts_last_24_hours") == "3"
    assert _state(hass, "sensor.crowdsec_agent_netbird_traefik_alerts_last_24_hours") == "1"
    assert hass.states.get("binary_sensor.crowdsec_agent_caddy_agent_online") is None
    assert hass.states.get("sensor.crowdsec_blocklist_decisions") is None
    assert hass.states.get("binary_sensor.crowdsec_metrics_reachable") is None
    # Nur die beiden Metrik-Endpunkte wären zusätzliche Abrufe – es gibt keine.
    assert not [c for c in aioclient_mock.mock_calls if c[1].path == "/metrics"]


@pytest.mark.parametrize("options", [METRIC_OPTIONS])
async def test_metric_entities(hass: HomeAssistant, config_entry, aioclient_mock, freezer) -> None:
    freezer.move_to("2026-10-01T14:00:00+00:00")
    mock_api(aioclient_mock)
    _mock_metrics(aioclient_mock)
    await _setup(hass, config_entry)

    # LAPI
    assert _state(hass, "binary_sensor.crowdsec_metrics_reachable") == "on"
    assert _state(hass, "sensor.crowdsec_blocklist_decisions") == "15500"
    assert _state(hass, "sensor.crowdsec_last_blocklist_pull") == "2026-10-01T12:00:00+00:00"
    assert _state(hass, "sensor.crowdsec_version").startswith("v1.7.8")

    # Agents: Heartbeat vor 30 s bzw. vor 10 min (Schwelle 5 min)
    assert _state(hass, "binary_sensor.crowdsec_agent_caddy_agent_online") == "on"
    assert _state(hass, "binary_sensor.crowdsec_agent_netbird_traefik_online") == "off"
    assert (
        _state(hass, "sensor.crowdsec_agent_caddy_agent_last_heartbeat")
        == "2026-10-01T13:59:30+00:00"
    )
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_log_lines_read") == "1234.0"
    assert hass.states.get("sensor.crowdsec_agent_caddy_agent_log_lines_read").attributes[
        "sources"
    ] == {"/var/log/caddy/access.log": 1000, "/var/log/caddy/robben.log": 234}
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_unparsed_log_lines") == "10.0"
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_appsec_requests") == "80.0"
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_appsec_blocks") == "4.0"
    assert _state(hass, "binary_sensor.crowdsec_agent_caddy_agent_reading_logs") == "on"
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_last_log_line") == "unknown"
    # Ohne Agent-Endpunkt gibt es für netbird-traefik keine Log-Sensoren.
    assert hass.states.get("sensor.crowdsec_agent_netbird_traefik_log_lines_read") is None

    # Bouncer
    assert _state(hass, "binary_sensor.crowdsec_bouncer_caddy_active") == "on"
    assert _state(hass, "sensor.crowdsec_bouncer_caddy_last_pull") == "unknown"
    assert _state(hass, "binary_sensor.crowdsec_bouncer_traefik_netbird_active") == "on"

    # Geräte: Agents und Bouncer hängen an der LAPI, die LAPI verlinkt die Web UI.
    main = _device(hass, config_entry, config_entry.entry_id)
    assert main.configuration_url == "https://crowdsec.example.org"
    agent = _device(hass, config_entry, f"{config_entry.entry_id}_agent_caddy-agent")
    assert agent.name == "CrowdSec Agent caddy-agent"
    assert agent.via_device_id == main.id


@pytest.mark.parametrize("options", [METRIC_OPTIONS])
async def test_bouncer_and_logs_go_quiet(
    hass: HomeAssistant, config_entry, aioclient_mock, freezer
) -> None:
    freezer.move_to("2026-10-01T14:00:00+00:00")
    mock_api(aioclient_mock)
    _mock_metrics(aioclient_mock)
    await _setup(hass, config_entry)

    # caddy fragt weiter an, traefik-netbird nicht mehr; neue Logzeilen kommen an.
    freezer.tick(timedelta(minutes=8))
    lapi = (FIXTURES / "metrics_lapi.txt").read_text().replace("} 1520", "} 1600")
    agent = (FIXTURES / "metrics_agent.txt").read_text().replace("} 234", "} 300")
    mock_api(aioclient_mock)
    _mock_metrics(aioclient_mock, lapi=lapi, agent=agent)
    await _refresh(hass, config_entry)
    assert _state(hass, "sensor.crowdsec_bouncer_caddy_last_pull") == "2026-10-01T14:08:00+00:00"
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_last_log_line") == (
        "2026-10-01T14:08:00+00:00"
    )

    freezer.tick(timedelta(minutes=8))
    await _refresh(hass, config_entry)
    assert _state(hass, "binary_sensor.crowdsec_bouncer_caddy_active") == "on"
    assert _state(hass, "binary_sensor.crowdsec_bouncer_traefik_netbird_active") == "off"
    # Der Heartbeat bleibt beim Stand der Fixture stehen: nach 16 Minuten offline.
    assert _state(hass, "binary_sensor.crowdsec_agent_caddy_agent_online") == "off"

    # Logs: Schwelle 60 Minuten
    freezer.tick(timedelta(minutes=61))
    await _refresh(hass, config_entry)
    assert _state(hass, "binary_sensor.crowdsec_agent_caddy_agent_reading_logs") == "off"


@pytest.mark.parametrize("options", [METRIC_OPTIONS])
async def test_metrics_outage_keeps_the_rest(
    hass: HomeAssistant, config_entry, aioclient_mock, freezer
) -> None:
    freezer.move_to("2026-10-01T14:00:00+00:00")
    mock_api(aioclient_mock)
    _mock_metrics(aioclient_mock)
    await _setup(hass, config_entry)

    mock_api(aioclient_mock)
    aioclient_mock.get(LAPI_METRICS, exc=aiohttp.ClientError)
    aioclient_mock.get(AGENT_METRICS, status=500)
    await _refresh(hass, config_entry)

    assert _state(hass, "binary_sensor.crowdsec_lapi_reachable") == "on"
    assert _state(hass, "sensor.crowdsec_active_bans") == "3"
    assert _state(hass, "binary_sensor.crowdsec_metrics_reachable") == "off"
    assert _state(hass, "binary_sensor.crowdsec_agent_caddy_agent_metrics_reachable") == "off"
    assert _state(hass, "sensor.crowdsec_blocklist_decisions") == "unavailable"
    assert _state(hass, "sensor.crowdsec_agent_caddy_agent_log_lines_read") == "unavailable"
    # Der zuletzt bekannte Heartbeat bleibt: der Agent ist weiter online.
    assert _state(hass, "binary_sensor.crowdsec_agent_caddy_agent_online") == "on"


@pytest.mark.parametrize("options", [{"scan_interval": 60, "metrics_url": LAPI_METRICS}])
async def test_new_bouncer_adds_entities_later(
    hass: HomeAssistant, config_entry, aioclient_mock, freezer
) -> None:
    freezer.move_to("2026-10-01T14:00:00+00:00")
    mock_api(aioclient_mock)
    _mock_metrics(aioclient_mock)
    await _setup(hass, config_entry)
    assert hass.states.get("binary_sensor.crowdsec_bouncer_firewall_active") is None

    lapi = (FIXTURES / "metrics_lapi.txt").read_text() + (
        'cs_lapi_bouncer_requests_total{bouncer="firewall",method="GET",'
        'route="/v1/decisions/stream"} 1\n'
    )
    mock_api(aioclient_mock)
    _mock_metrics(aioclient_mock, lapi=lapi)
    await _refresh(hass, config_entry)
    assert _state(hass, "binary_sensor.crowdsec_bouncer_firewall_active") == "on"


# --------------------------------------------------------------------------- #
# Options-Flow                                                                 #
# --------------------------------------------------------------------------- #


def _input(**metrics) -> dict:
    return {"scan_interval": 60, "metrics": {"agent_timeout": 5, **metrics}}


async def test_options_metrics_saved(hass: HomeAssistant, config_entry, aioclient_mock) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    _mock_metrics(aioclient_mock)
    result = await hass.config_entries.options.async_init(config_entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            **_input(
                metrics_url=LAPI_METRICS,
                agent_metrics=f"caddy-agent = {AGENT_METRICS}",
                bouncer_timeout=15,
            ),
            "web_ui_url": "https://crowdsec.example.org",
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options["metrics_url"] == LAPI_METRICS
    assert config_entry.options["agent_metrics"] == f"caddy-agent = {AGENT_METRICS}"
    assert config_entry.options["bouncer_timeout"] == 15
    assert config_entry.options["log_timeout"] == 1440
    assert config_entry.options["web_ui_url"] == "https://crowdsec.example.org"


@pytest.mark.parametrize(
    ("user_input", "error", "failed"),
    [
        (_input(metrics_url="ftp://x"), "invalid_metrics_url", ""),
        (_input(agent_metrics="caddy http://x"), "invalid_agent_metrics", "caddy http://x"),
        ({**_input(), "web_ui_url": "crowdsec"}, "invalid_web_ui_url", ""),
        (_input(metrics_url=LAPI_METRICS), "metrics_unreachable", "LAPI"),
        (
            _input(agent_metrics=f"caddy-agent = {AGENT_METRICS}"),
            "metrics_unreachable",
            "caddy-agent",
        ),
    ],
)
async def test_options_metrics_errors(
    hass: HomeAssistant, config_entry, aioclient_mock, user_input, error, failed
) -> None:
    mock_api(aioclient_mock)
    await _setup(hass, config_entry)
    aioclient_mock.get(LAPI_METRICS, text="no metrics here")
    aioclient_mock.get(AGENT_METRICS, exc=aiohttp.ClientError)
    result = await hass.config_entries.options.async_init(config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(result["flow_id"], user_input)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}
    assert result["description_placeholders"]["failed"] == failed
