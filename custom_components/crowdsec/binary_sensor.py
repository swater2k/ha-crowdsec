"""Binärsensor „LAPI erreichbar“."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import CrowdSecConfigEntry
from .coordinator import CrowdSecCoordinator
from .entity import CrowdSecEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CrowdSecConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([LapiReachable(entry.runtime_data, entry)])


class LapiReachable(CrowdSecEntity, BinarySensorEntity):
    _attr_translation_key = "lapi_reachable"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: CrowdSecCoordinator, entry: CrowdSecConfigEntry) -> None:
        super().__init__(coordinator, entry, "lapi_reachable")

    @property
    def available(self) -> bool:
        # Gerade der Ausfall soll sichtbar sein, nicht „nicht verfügbar“.
        return True

    @property
    def is_on(self) -> bool:
        return self.coordinator.last_update_success
