"""Auswertung der Prometheus-Metriken – bewusst ohne Home-Assistant-Abhängigkeit.

Zwei Quellen: die Metriken der zentralen LAPI (Heartbeats der Agents, Abrufe
der Bouncer, Community-Blocklist) und optional die Metriken einzelner Agents
(gelesene Logzeilen, Parser, AppSec).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import math
import re

from .prometheus import Sample

# Gelesene Zeilen je Datenquelle: cs_filesource_hits_total, cs_dockersource_hits_total,
# cs_journalctlsource_hits_total, cs_cloudwatch_stream_hits_total usw.
_ACQUISITION = re.compile(r"^cs_(\w+source|cloudwatch_stream|kinesis_stream)_hits_total$")
# Herkunft der Decisions aus Blocklisten (Community-Blocklist und abonnierte Listen).
BLOCKLIST_ORIGINS = ("CAPI", "lists")


def _timestamp(value: float) -> datetime | None:
    if not math.isfinite(value) or value <= 0:
        return None
    return datetime.fromtimestamp(value, UTC)


def _version(samples: Iterable[Sample]) -> str | None:
    for sample in samples:
        if sample.name == "cs_info" and (version := sample.labels.get("version")):
            return version
    return None


@dataclass(frozen=True, slots=True)
class LapiMetrics:
    version: str | None = None
    heartbeats: dict[str, datetime] = field(default_factory=dict)
    bouncer_requests: dict[str, float] = field(default_factory=dict)
    blocklist_decisions: int | None = None
    capi_last_pull: datetime | None = None


@dataclass(frozen=True, slots=True)
class AgentMetrics:
    version: str | None = None
    lines_read: float | None = None
    lines_by_source: dict[str, float] = field(default_factory=dict)
    lines_parsed: float | None = None
    lines_unparsed: float | None = None
    appsec_requests: float | None = None
    appsec_blocks: float | None = None


def summarize_lapi(samples: list[Sample]) -> LapiMetrics:
    heartbeats: dict[str, datetime] = {}
    bouncers: dict[str, float] = {}
    blocklist: int | None = None
    capi_last_pull: datetime | None = None
    for sample in samples:
        if sample.name == "cs_machines_last_heartbeat_timestamp":
            if (machine := sample.labels.get("machine")) and (ts := _timestamp(sample.value)):
                heartbeats[machine] = ts
        elif sample.name == "cs_lapi_bouncer_requests_total":
            if bouncer := sample.labels.get("bouncer"):
                bouncers[bouncer] = bouncers.get(bouncer, 0.0) + sample.value
        elif sample.name == "cs_active_decisions":
            # Die Metrik gibt es nur auf der LAPI; ohne Blocklist-Decisions bleibt sie 0.
            blocklist = blocklist or 0
            if sample.labels.get("origin") in BLOCKLIST_ORIGINS:
                blocklist += int(sample.value)
        elif sample.name == "cs_capi_last_pull_timestamp":
            capi_last_pull = _timestamp(sample.value)
    return LapiMetrics(
        version=_version(samples),
        heartbeats=heartbeats,
        bouncer_requests=bouncers,
        blocklist_decisions=blocklist,
        capi_last_pull=capi_last_pull,
    )


def summarize_agent(samples: list[Sample]) -> AgentMetrics:
    by_source: dict[str, float] = {}
    parsed: float | None = None
    unparsed: float | None = None
    appsec_requests: float | None = None
    appsec_blocks: float | None = None
    for sample in samples:
        if _ACQUISITION.match(sample.name):
            source = sample.labels.get("source", "")
            by_source[source] = by_source.get(source, 0.0) + sample.value
        elif sample.name == "cs_parser_hits_ok_total":
            parsed = (parsed or 0.0) + sample.value
        elif sample.name == "cs_parser_hits_ko_total":
            unparsed = (unparsed or 0.0) + sample.value
        elif sample.name == "cs_appsec_reqs_total":
            appsec_requests = (appsec_requests or 0.0) + sample.value
        elif sample.name == "cs_appsec_block_total":
            appsec_blocks = (appsec_blocks or 0.0) + sample.value
    if by_source:
        # Die Parser-Zähler erscheinen erst mit dem ersten Treffer bzw. Fehlschlag.
        parsed = parsed or 0.0
        unparsed = unparsed or 0.0
    if appsec_requests is not None and appsec_blocks is None:
        appsec_blocks = 0.0  # der Zähler erscheint erst mit der ersten Blockierung
    return AgentMetrics(
        version=_version(samples),
        lines_read=sum(by_source.values()) if by_source else None,
        lines_by_source=by_source,
        lines_parsed=parsed,
        lines_unparsed=unparsed,
        appsec_requests=appsec_requests,
        appsec_blocks=appsec_blocks,
    )


@dataclass(slots=True)
class _Track:
    total: float
    first_seen: datetime
    last_change: datetime | None = None


class ActivityTracker:
    """Merkt sich je Schlüssel, wann sich ein Zähler zuletzt geändert hat.

    Prometheus-Zähler sagen nur „wie viele“, nicht „wann zuletzt“. Eine Änderung
    zählt als Aktivität – auch ein kleinerer Wert, denn nach einem Neustart
    beginnt der Zähler wieder bei 0. Fehlt ein Schlüssel in einem Abruf, bleibt
    der alte Stand erhalten; nach einem Neustart der LAPI tauchen Bouncer erst
    mit ihrem nächsten Abruf wieder auf.
    """

    def __init__(self) -> None:
        self._tracks: dict[str, _Track] = {}

    def update(self, key: str, total: float, now: datetime) -> None:
        track = self._tracks.get(key)
        if track is None:
            self._tracks[key] = _Track(total=total, first_seen=now)
            return
        if total != track.total:
            track.last_change = now
        track.total = total

    def keys(self) -> list[str]:
        return list(self._tracks)

    def last_change(self, key: str) -> datetime | None:
        track = self._tracks.get(key)
        return track.last_change if track else None

    def is_active(self, key: str, now: datetime, threshold: timedelta) -> bool | None:
        """Aktiv, wenn sich der Zähler innerhalb der Schwelle geändert hat.

        Vor der ersten beobachteten Änderung gilt der erste Abruf als Bezug: ein
        frisch gestartetes Home Assistant meldet also nicht sofort alles als tot.
        """
        track = self._tracks.get(key)
        if track is None:
            return None
        return now - (track.last_change or track.first_seen) <= threshold


def parse_agent_endpoints(value: str) -> dict[str, str]:
    """``name = url`` je Zeile; leere Zeilen und ``#``-Kommentare werden übersprungen.

    Wirft ``ValueError`` mit der fehlerhaften Zeile.
    """
    endpoints: dict[str, str] = {}
    for raw in value.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, url = line.partition("=")
        name, url = name.strip(), url.strip()
        if not sep or not name or not url.startswith(("http://", "https://")):
            raise ValueError(line)
        if name in endpoints:
            raise ValueError(line)
        endpoints[name] = url
    return endpoints
