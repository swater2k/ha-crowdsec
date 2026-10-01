"""Basis-Entität."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CrowdSecCoordinator
from .stable_id import StableEntityIdMixin

if TYPE_CHECKING:
    from . import CrowdSecConfigEntry


class CrowdSecEntity(StableEntityIdMixin, CoordinatorEntity[CrowdSecCoordinator]):
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CrowdSecCoordinator, entry: CrowdSecConfigEntry, key: str
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._id_prefix = DOMAIN
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="CrowdSec",
            manufacturer="CrowdSec",
            model="Local API",
            entry_type=DeviceEntryType.SERVICE,
        )
