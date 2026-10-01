"""DataUpdateCoordinator für die CrowdSec-LAPI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import CrowdSecApi, CrowdSecAuthError, CrowdSecConnectionError
from .bans import AlertStats, Ban, extract_bans, summarize_alerts
from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN, ORIGINS, STATS_INTERVAL

if TYPE_CHECKING:
    from . import CrowdSecConfigEntry

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CrowdSecData:
    active_bans: list[Ban] = field(default_factory=list)
    new_bans: list[Ban] = field(default_factory=list)  # seit dem letzten Abruf
    bans_last_hour: int = 0
    stats: AlertStats = field(default_factory=AlertStats)

    @property
    def last_ban(self) -> Ban | None:
        return self.active_bans[0] if self.active_bans else None


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

        bans = extract_bans(active)
        previous = self._seen
        self._seen = {ban.key for ban in bans}
        hour_ago = now - timedelta(hours=1)
        return CrowdSecData(
            active_bans=bans,
            new_bans=[] if previous is None else [b for b in bans if b.key not in previous],
            bans_last_hour=sum(1 for b in bans if b.created_at and b.created_at >= hour_ago),
            stats=self._stats,
        )
