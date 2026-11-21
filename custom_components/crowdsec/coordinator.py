"""DataUpdateCoordinator für die CrowdSec-LAPI und ihre Metriken."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import CrowdSecApi, CrowdSecAuthError, CrowdSecConnectionError, async_fetch_metrics
from .bans import AlertStats, Ban, extract_bans, summarize_alerts
from .const import (
    CONF_AGENT_METRICS,
    CONF_AGENT_TIMEOUT,
    CONF_BOUNCER_TIMEOUT,
    CONF_LOG_TIMEOUT,
    CONF_METRICS_URL,
    CONF_SCAN_INTERVAL,
    DEFAULT_AGENT_TIMEOUT,
    DEFAULT_BOUNCER_TIMEOUT,
    DEFAULT_LOG_TIMEOUT,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    ORIGINS,
    STATS_INTERVAL,
)
from .metrics import (
    ActivityTracker,
    AgentMetrics,
    LapiMetrics,
    parse_agent_endpoints,
    summarize_agent,
    summarize_lapi,
)

if TYPE_CHECKING:
    from . import CrowdSecConfigEntry

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CrowdSecData:
    active_bans: list[Ban] = field(default_factory=list)
    new_bans: list[Ban] = field(default_factory=list)  # seit dem letzten Abruf
    bans_last_hour: int = 0
    stats: AlertStats = field(default_factory=AlertStats)
    # None: keine LAPI-Metriken eingerichtet oder Endpunkt nicht erreichbar.
    lapi_metrics: LapiMetrics | None = None
    # Je eingerichtetem Agent-Endpunkt; None, wenn der Abruf fehlschlug.
    agent_metrics: dict[str, AgentMetrics | None] = field(default_factory=dict)
    agents: list[str] = field(default_factory=list)
    bouncers: list[str] = field(default_factory=list)

    @property
    def last_ban(self) -> Ban | None:
        return self.active_bans[0] if self.active_bans else None


def _minutes(entry: CrowdSecConfigEntry, key: str, default: int) -> timedelta:
    return timedelta(minutes=int(entry.options.get(key, default)))


class CrowdSecCoordinator(DataUpdateCoordinator[CrowdSecData]):
    config_entry: CrowdSecConfigEntry

    def __init__(self, hass: HomeAssistant, entry: CrowdSecConfigEntry, api: CrowdSecApi) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            config_entry=entry,
            update_interval=timedelta(
                seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
            ),
        )
        self.api = api
        # None = noch kein Abruf; der erste Abruf löst keine Ereignisse aus, sonst
        # meldet jeder Neustart von Home Assistant alle aktiven Sperren als neu.
        self._seen: set[tuple[str, str]] | None = None
        self._stats: AlertStats = AlertStats()
        self._stats_at: datetime | None = None

        self._session = async_get_clientsession(hass)
        self.metrics_url: str | None = entry.options.get(CONF_METRICS_URL) or None
        try:
            self.agent_endpoints = parse_agent_endpoints(entry.options.get(CONF_AGENT_METRICS, ""))
        except ValueError:  # der Options-Flow lässt das nicht durch
            _LOGGER.warning("Ignoring invalid agent metrics configuration")
            self.agent_endpoints = {}
        self.agent_timeout = _minutes(entry, CONF_AGENT_TIMEOUT, DEFAULT_AGENT_TIMEOUT)
        self.bouncer_timeout = _minutes(entry, CONF_BOUNCER_TIMEOUT, DEFAULT_BOUNCER_TIMEOUT)
        self.log_timeout = _minutes(entry, CONF_LOG_TIMEOUT, DEFAULT_LOG_TIMEOUT)

        # Der Heartbeat liegt auf der LAPI nur im Speicher: nach deren Neustart
        # fehlt ein Agent, bis er sich wieder meldet. Der letzte bekannte Wert
        # bleibt deshalb erhalten.
        self.heartbeats: dict[str, datetime] = {}
        self.bouncer_activity = ActivityTracker()
        self.log_activity = ActivityTracker()

    async def _async_update_data(self) -> CrowdSecData:
        now = dt_util.utcnow()
        try:
            active: list[dict[str, Any]] = []
            for origin in ORIGINS:
                active += await self.api.async_get_alerts(
                    has_active_decision="true", origin=origin, limit=500
                )
            if self._stats_at is None or now - self._stats_at >= timedelta(seconds=STATS_INTERVAL):
                recent: list[dict[str, Any]] = []
                for origin in ORIGINS:
                    recent += await self.api.async_get_alerts(
                        since="24h", origin=origin, limit=1000
                    )
                self._stats = summarize_alerts(recent)
                self._stats_at = now
        except CrowdSecAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except CrowdSecConnectionError as err:
            raise UpdateFailed(f"LAPI not reachable: {err}") from err

        lapi_metrics, agent_metrics = await self._async_fetch_metrics(now)

        bans = extract_bans(active)
        previous = self._seen
        self._seen = {ban.key for ban in bans}
        hour_ago = now - timedelta(hours=1)
        agents = set(self._stats.by_machine or {}) | set(self.heartbeats) | set(agent_metrics)
        return CrowdSecData(
            active_bans=bans,
            new_bans=[] if previous is None else [b for b in bans if b.key not in previous],
            bans_last_hour=sum(1 for b in bans if b.created_at and b.created_at >= hour_ago),
            stats=self._stats,
            lapi_metrics=lapi_metrics,
            agent_metrics=agent_metrics,
            agents=sorted(agents),
            bouncers=sorted(self.bouncer_activity.keys()),
        )

    async def _async_fetch_metrics(
        self, now: datetime
    ) -> tuple[LapiMetrics | None, dict[str, AgentMetrics | None]]:
        """Metriken sind ein Zusatz: ein Fehler hier lässt den Rest weiterlaufen."""
        names = list(self.agent_endpoints)
        urls = [self.agent_endpoints[name] for name in names]
        if self.metrics_url:
            urls.append(self.metrics_url)
        results = await asyncio.gather(
            *(async_fetch_metrics(self._session, url) for url in urls), return_exceptions=True
        )
        for url, result in zip(urls, results, strict=True):
            if isinstance(result, CrowdSecConnectionError):
                _LOGGER.debug("Metrics not available: %s", result)
            elif isinstance(result, BaseException):
                _LOGGER.warning("Unexpected error reading %s: %s", url, result)

        agent_metrics: dict[str, AgentMetrics | None] = {}
        for name, result in zip(names, results, strict=False):
            if isinstance(result, BaseException):
                agent_metrics[name] = None
                continue
            metrics = summarize_agent(result)
            if metrics.lines_read is not None:
                self.log_activity.update(name, metrics.lines_read, now)
            agent_metrics[name] = metrics

        lapi_metrics: LapiMetrics | None = None
        if self.metrics_url and not isinstance(results[-1], BaseException):
            lapi_metrics = summarize_lapi(results[-1])
            for machine, seen in lapi_metrics.heartbeats.items():
                if machine not in self.heartbeats or seen > self.heartbeats[machine]:
                    self.heartbeats[machine] = seen
            for bouncer, total in lapi_metrics.bouncer_requests.items():
                self.bouncer_activity.update(bouncer, total, now)
        return lapi_metrics, agent_metrics

    def agent_online(self, machine: str) -> bool | None:
        if not self.metrics_url:
            return None
        if (seen := self.heartbeats.get(machine)) is None:
            return False
        return dt_util.utcnow() - seen <= self.agent_timeout

    def bouncer_active(self, bouncer: str) -> bool | None:
        return self.bouncer_activity.is_active(bouncer, dt_util.utcnow(), self.bouncer_timeout)

    def agent_reading_logs(self, name: str) -> bool | None:
        return self.log_activity.is_active(name, dt_util.utcnow(), self.log_timeout)
