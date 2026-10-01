"""Sensoren."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.typing import StateType

from . import CrowdSecConfigEntry
from .const import MAX_LISTED_BANS
from .coordinator import CrowdSecCoordinator, CrowdSecData
from .entity import CrowdSecEntity

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class CrowdSecSensorDescription(SensorEntityDescription):
    value_fn: Callable[[CrowdSecData], StateType]
    attrs_fn: Callable[[CrowdSecData], dict[str, Any]] | None = None


def _active_attrs(data: CrowdSecData) -> dict[str, Any]:
    # Gekürzt: Attribute über 16 KB lehnt der Recorder ab.
    return {
        "bans": [
            {"value": b.value, "scope": b.scope, "scenario": b.scenario, "country": b.country}
            for b in data.active_bans[:MAX_LISTED_BANS]
        ]
    }


def _stats_attrs(data: CrowdSecData) -> dict[str, Any]:
    return {
        "top_countries": data.stats.by_country or {},
        "top_scenarios": data.stats.by_scenario or {},
    }


def _last_ban_attrs(data: CrowdSecData) -> dict[str, Any]:
    return data.last_ban.as_attributes() if data.last_ban else {}


SENSORS: tuple[CrowdSecSensorDescription, ...] = (
    CrowdSecSensorDescription(
        key="active_bans",
        translation_key="active_bans",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: len(d.active_bans),
        attrs_fn=_active_attrs,
    ),
    CrowdSecSensorDescription(
        key="alerts_24h",
        translation_key="alerts_24h",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.stats.total,
        attrs_fn=_stats_attrs,
    ),
    CrowdSecSensorDescription(
        key="bans_last_hour",
        translation_key="bans_last_hour",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.bans_last_hour,
    ),
    CrowdSecSensorDescription(
        key="last_ban",
        translation_key="last_ban",
        value_fn=lambda d: d.last_ban.value if d.last_ban else None,
        attrs_fn=_last_ban_attrs,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CrowdSecConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(CrowdSecSensor(coordinator, entry, desc) for desc in SENSORS)


class CrowdSecSensor(CrowdSecEntity, SensorEntity):
    entity_description: CrowdSecSensorDescription

    def __init__(
        self,
        coordinator: CrowdSecCoordinator,
        entry: CrowdSecConfigEntry,
        description: CrowdSecSensorDescription,
    ) -> None:
        super().__init__(coordinator, entry, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> StateType:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator.data)
