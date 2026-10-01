"""Ereignis-Entität „Neue Sperre“."""

from __future__ import annotations

import logging

from homeassistant.components.event import EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from . import CrowdSecConfigEntry
from .const import EVENT_BAN, MAX_EVENTS_PER_UPDATE
from .coordinator import CrowdSecCoordinator
from .entity import CrowdSecEntity

_LOGGER = logging.getLogger(__name__)
PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CrowdSecConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([NewBan(entry.runtime_data, entry)])


class NewBan(CrowdSecEntity, EventEntity):
    """Feuert einmal je neuer lokaler Sperre (nicht je Alert).

    Die Attribute des Ereignisses: ``value``, ``scope`` (Ip/Range), ``origin``
    (crowdsec/cscli), ``scenario``, ``country``, ``asn``, ``decision_id``,
    ``banned_at``, ``duration`` (Restlaufzeit) und ``expires_at``.
    """

    _attr_translation_key = "new_ban"

    def __init__(self, coordinator: CrowdSecCoordinator, entry: CrowdSecConfigEntry) -> None:
        super().__init__(coordinator, entry, "new_ban")
        self._attr_event_types = [EVENT_BAN]

    @callback
    def _handle_coordinator_update(self) -> None:
        data = self.coordinator.data
        if data is None or not data.new_bans:
            super()._handle_coordinator_update()
            return
        if len(data.new_bans) > MAX_EVENTS_PER_UPDATE:
            _LOGGER.warning(
                "%d new bans in one update, reporting only the newest %d",
                len(data.new_bans),
                MAX_EVENTS_PER_UPDATE,
            )
        now = dt_util.utcnow()
        # Neueste zuletzt melden; je Ereignis ein Zustand, sonst sähe eine
        # Automation nur das letzte.
        for ban in reversed(data.new_bans[:MAX_EVENTS_PER_UPDATE]):
            self._trigger_event(EVENT_BAN, ban.as_event_data(now))
            self.async_write_ha_state()
