"""Prometheus-Parser, Auswertung der Metriken und Aktivitätserkennung (ohne Home Assistant)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from custom_components.crowdsec.bans import summarize_alerts
from custom_components.crowdsec.metrics import (
    ActivityTracker,
    parse_agent_endpoints,
    summarize_agent,
    summarize_lapi,
)
from custom_components.crowdsec.prometheus import parse

from .conftest import load

FIXTURES = Path(__file__).parent / "fixtures"
T0 = datetime(2026, 10, 1, 14, 0, tzinfo=UTC)


def _text(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_labels_escapes_and_timestamps() -> None:
    samples = parse(
        "# HELP x y\n"
        'cs_a{source="/var/log/a \\"b\\".log",x="1\\\\2"} 3 1700000000000\n'
        "cs_b 4.5\n"
        "cs_c{} NaN\n"
        "broken{line 1\n"
        'cs_d{k="unterminated} 1\n'
        "\n"
    )
    assert [s.name for s in samples] == ["cs_a", "cs_b", "cs_c"]
    assert samples[0].labels == {"source": '/var/log/a "b".log', "x": "1\\2"}
    assert samples[0].value == 3
    assert samples[1].labels == {}


def test_summarize_lapi() -> None:
    metrics = summarize_lapi(parse(_text("metrics_lapi.txt")))
    assert metrics.version == "v1.7.8-debian-pragmatic-amd64-f209766e"
    assert metrics.heartbeats["caddy-agent"] == datetime(2026, 10, 1, 13, 59, 30, tzinfo=UTC)
    assert set(metrics.heartbeats) == {"caddy-agent", "netbird-traefik"}
    # Je Bouncer über alle Routen und Methoden summiert.
    assert metrics.bouncer_requests == {"caddy": 1520, "traefik-netbird": 312}
    # Nur CAPI und abonnierte Listen, nicht die lokalen Sperren.
    assert metrics.blocklist_decisions == 15500
    assert metrics.capi_last_pull == datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def test_summarize_lapi_without_decisions_metric() -> None:
    """Ein Agent-Endpunkt hat keine Decision-Metrik: dann gibt es keinen Wert, nicht 0."""
    metrics = summarize_lapi(parse(_text("metrics_agent.txt")))
    assert metrics.blocklist_decisions is None
    assert metrics.heartbeats == {}


def test_summarize_agent() -> None:
    metrics = summarize_agent(parse(_text("metrics_agent.txt")))
    assert metrics.version == "v1.7.8"
    assert metrics.lines_read == 1234
    assert metrics.lines_by_source == {
        "/var/log/caddy/access.log": 1000,
        "/var/log/caddy/robben.log": 234,
    }
    assert metrics.lines_parsed == 990
    assert metrics.lines_unparsed == 10
    assert metrics.appsec_requests == 80
    assert metrics.appsec_blocks == 4


def test_summarize_agent_appsec_without_blocks() -> None:
    metrics = summarize_agent(parse('cs_appsec_reqs_total{source="x",appsec_engine="a"} 5\n'))
    assert metrics.appsec_requests == 5
    assert metrics.appsec_blocks == 0
    assert metrics.lines_read is None


def test_activity_tracker() -> None:
    tracker = ActivityTracker()
    limit = timedelta(minutes=10)
    assert tracker.is_active("b", T0, limit) is None

    tracker.update("b", 100, T0)
    assert tracker.last_change("b") is None
    # Ohne beobachtete Änderung zählt der erste Abruf als Bezug.
    assert tracker.is_active("b", T0 + timedelta(minutes=9), limit) is True
    assert tracker.is_active("b", T0 + timedelta(minutes=11), limit) is False

    tracker.update("b", 100, T0 + timedelta(minutes=5))
    assert tracker.last_change("b") is None
    tracker.update("b", 120, T0 + timedelta(minutes=12))
    assert tracker.last_change("b") == T0 + timedelta(minutes=12)
    assert tracker.is_active("b", T0 + timedelta(minutes=20), limit) is True

    # Neustart: der Zähler beginnt wieder klein – auch das ist Aktivität.
    tracker.update("b", 3, T0 + timedelta(minutes=30))
    assert tracker.last_change("b") == T0 + timedelta(minutes=30)


def test_parse_agent_endpoints() -> None:
    assert parse_agent_endpoints(
        "# Kommentar\ncaddy = http://192.0.2.20:6060/metrics\n\n  authelia=https://a:6060/metrics  \n"
    ) == {"caddy": "http://192.0.2.20:6060/metrics", "authelia": "https://a:6060/metrics"}
    assert parse_agent_endpoints("") == {}


@pytest.mark.parametrize(
    "value",
    [
        "caddy http://x:6060/metrics",
        "= http://x:6060/metrics",
        "caddy = x:6060/metrics",
        "caddy = http://a/metrics\ncaddy = http://b/metrics",
    ],
)
def test_parse_agent_endpoints_rejects(value: str) -> None:
    with pytest.raises(ValueError):
        parse_agent_endpoints(value)


def test_alerts_by_machine_skips_manual_bans() -> None:
    stats = summarize_alerts(load("alerts_crowdsec") + load("alerts_manual"))
    assert stats.by_machine == {"caddy-agent": 3, "netbird-traefik": 1}
