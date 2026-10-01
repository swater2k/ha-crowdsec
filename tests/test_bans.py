"""Auswertung der Alerts – reine Logik ohne Home Assistant."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from custom_components.crowdsec.api import normalize_url
from custom_components.crowdsec.bans import (
    extract_bans,
    parse_go_duration,
    parse_time,
    summarize_alerts,
)

from .conftest import load


def test_parse_go_duration() -> None:
    assert parse_go_duration("3h58m52s") == timedelta(hours=3, minutes=58, seconds=52)
    assert parse_go_duration("14m9s") == timedelta(minutes=14, seconds=9)
    assert parse_go_duration("164h30m14s") == timedelta(hours=164, minutes=30, seconds=14)
    assert parse_go_duration("52.5s") == timedelta(seconds=52.5)
    assert parse_go_duration("250ms") == timedelta(milliseconds=250)
    assert parse_go_duration("0s") == timedelta(0)
    assert parse_go_duration("") is None
    assert parse_go_duration("4d") is None
    assert parse_go_duration("soon") is None
    assert parse_go_duration(None) is None


def test_parse_time() -> None:
    assert parse_time("2026-10-01T13:30:10Z") == datetime(2026, 10, 1, 13, 30, 10, tzinfo=UTC)
    assert parse_time("2026-10-01T13:30:10") == datetime(2026, 10, 1, 13, 30, 10, tzinfo=UTC)
    assert parse_time("kaputt") is None
    assert parse_time(None) is None


def test_extract_bans_dedups_by_value_and_sorts_newest_first() -> None:
    bans = extract_bans(load("alerts_crowdsec"))
    assert [b.value for b in bans] == ["2001:db8:1003::20", "198.51.100.53", "203.0.113.46"]
    # Zwei Alerts für 198.51.100.53: der neuere gewinnt.
    lt = bans[1]
    assert lt.scenario == "crowdsecurity/http-sensitive-files"
    assert lt.decision_id == 540093
    assert lt.country == "LT"
    assert lt.asn == "61272 Example Hosting"
    assert lt.scope == "Ip"


def test_extract_bans_ignores_foreign_origin_simulation_and_other_types() -> None:
    alert = load("alerts_crowdsec")[0]
    capi = {**alert["decisions"][0], "id": 1, "origin": "CAPI", "value": "192.0.2.1"}
    simulated = {**alert["decisions"][0], "id": 2, "simulated": True, "value": "192.0.2.2"}
    captcha = {**alert["decisions"][0], "id": 3, "type": "captcha", "value": "192.0.2.3"}
    assert extract_bans([{**alert, "decisions": [capi, simulated, captcha]}]) == []
    assert extract_bans([{**alert, "decisions": None}]) == []


def test_extract_manual_range_ban() -> None:
    (ban,) = extract_bans(load("alerts_manual"))
    assert (ban.scope, ban.value, ban.origin) == ("Range", "2001:db8:aa::/64", "cscli")
    assert ban.country is None
    assert ban.asn is None


def test_event_data_has_expiry_but_attributes_are_stable() -> None:
    (ban, *_) = extract_bans(load("alerts_crowdsec"))
    now = datetime(2026, 10, 1, 14, 0, tzinfo=UTC)
    event = ban.as_event_data(now)
    assert event["value"] == "2001:db8:1003::20"
    assert event["duration"] == "3h58m52s"
    assert event["expires_at"] == (now + timedelta(hours=3, minutes=58, seconds=52)).isoformat()
    # Die Sensor-Attribute enthalten nichts, was sich von Abruf zu Abruf ändert.
    assert "duration" not in ban.as_attributes()
    assert "expires_at" not in ban.as_attributes()


def test_summarize_alerts_counts_each_alert_once() -> None:
    alerts = load("alerts_crowdsec")
    stats = summarize_alerts(alerts + alerts)  # doppelt geliefert (beide Herkünfte)
    assert stats.total == 4
    assert stats.by_country == {"LT": 2, "US": 1, "TR": 1}
    assert stats.by_scenario["crowdsecurity/http-probing"] == 1
    assert summarize_alerts([]).total == 0


def test_normalize_url() -> None:
    assert normalize_url("192.0.2.144") == "http://192.0.2.144:8080"
    assert normalize_url("http://192.0.2.144:9000/") == "http://192.0.2.144:9000"
    assert normalize_url("https://crowdsec.example.net/v1/") == "https://crowdsec.example.net"
    assert normalize_url("[2001:db8::1]") == "http://[2001:db8::1]:8080"
    for bad in ("ftp://example.net", "http://", ""):
        try:
            normalize_url(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
