"""Auswertung der LAPI-Alerts – bewusst ohne Home-Assistant-Abhängigkeit."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import re
from typing import Any

LOCAL_ORIGINS = ("crowdsec", "cscli")

_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")
_UNIT_SECONDS = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}
_MIN_DATETIME = datetime.min.replace(tzinfo=UTC)


def parse_time(value: Any) -> datetime | None:
    """ISO-8601 mit Zeitzone; ohne Angabe gilt UTC."""
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_go_duration(value: Any) -> timedelta | None:
    """Go-Dauer wie ``3h58m52s`` oder ``14m9s`` (so liefert die LAPI Restlaufzeiten)."""
    if not value or not isinstance(value, str):
        return None
    parts = _DURATION_PART.findall(value)
    if not parts or "".join(n + u for n, u in parts) != value.lstrip("-"):
        return None
    seconds = sum(float(number) * _UNIT_SECONDS[unit] for number, unit in parts)
    return timedelta(seconds=-seconds if value.startswith("-") else seconds)


@dataclass(frozen=True, slots=True)
class Ban:
    decision_id: int
    value: str
    scope: str  # "Ip" | "Range"
    origin: str  # "crowdsec" | "cscli"
    scenario: str
    duration: str  # Restlaufzeit zum Zeitpunkt des Abrufs
    country: str | None
    asn: str | None
    created_at: datetime | None

    @property
    def key(self) -> tuple[str, str]:
        return (self.scope, self.value)

    def as_attributes(self) -> dict[str, Any]:
        """Stabile Attribute; die Restlaufzeit gehört nicht dazu (sie ändert sich je Abruf)."""
        return {
            "scope": self.scope,
            "origin": self.origin,
            "scenario": self.scenario,
            "country": self.country,
            "asn": self.asn,
            "decision_id": self.decision_id,
            "banned_at": self.created_at.isoformat() if self.created_at else None,
        }

    def as_event_data(self, now: datetime) -> dict[str, Any]:
        remaining = parse_go_duration(self.duration)
        return {
            "value": self.value,
            **self.as_attributes(),
            "duration": self.duration,
            "expires_at": (now + remaining).isoformat() if remaining else None,
        }


def extract_bans(alerts: list[dict[str, Any]]) -> list[Ban]:
    """Eine Sperre je (scope, value), neueste zuerst; nur lokale, aktive Bans."""
    by_key: dict[tuple[str, str], Ban] = {}
    for alert in alerts:
        source = alert.get("source") or {}
        created = parse_time(alert.get("created_at"))
        for decision in alert.get("decisions") or []:
            if (
                decision.get("origin") not in LOCAL_ORIGINS
                or decision.get("type") != "ban"
                or decision.get("simulated")
            ):
                continue
            as_number = source.get("as_number")
            ban = Ban(
                decision_id=decision["id"],
                value=decision["value"],
                scope=decision.get("scope", "Ip"),
                origin=decision["origin"],
                scenario=decision.get("scenario") or alert.get("scenario") or "",
                duration=decision.get("duration", ""),
                country=source.get("cn"),
                asn=f"{as_number} {source.get('as_name') or ''}".strip() if as_number else None,
                created_at=created,
            )
            old = by_key.get(ban.key)
            if old is None or (created and (old.created_at is None or created > old.created_at)):
                by_key[ban.key] = ban
    return sorted(by_key.values(), key=lambda b: b.created_at or _MIN_DATETIME, reverse=True)


@dataclass(frozen=True, slots=True)
class AlertStats:
    total: int = 0
    by_country: dict[str, int] | None = None
    by_scenario: dict[str, int] | None = None


def summarize_alerts(alerts: list[dict[str, Any]], top: int = 5) -> AlertStats:
    """Zählt Alerts (je ID einmal) und liefert die häufigsten Länder und Szenarien."""
    unique = {a["id"]: a for a in alerts if "id" in a}
    countries: Counter[str] = Counter()
    scenarios: Counter[str] = Counter()
    for alert in unique.values():
        if country := (alert.get("source") or {}).get("cn"):
            countries[country] += 1
        if scenario := alert.get("scenario"):
            scenarios[scenario] += 1
    return AlertStats(
        total=len(unique),
        by_country=dict(countries.most_common(top)),
        by_scenario=dict(scenarios.most_common(top)),
    )
