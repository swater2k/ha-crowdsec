"""Binärsensoren: Erreichbarkeit der LAPI und ihrer Metriken, Zustand der Agents und Bouncer."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import CrowdSecConfigEntry
from .coordinator import CrowdSecCoordinator, CrowdSecData
from .entity import AGENT, BOUNCER, CrowdSecEntity, CrowdSecSubEntity, async_setup_dynamic

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CrowdSecConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[BinarySensorEntity] = [LapiReachable(coordinator, entry)]
    if coordinator.metrics_url:
        entities.append(LapiMetricsReachable(coordinator, entry))
    async_add_entities(entities)

    def build() -> Iterable[tuple[str, Callable[[], Entity]]]:
        data = coordinator.data
        if data is None:
            return
        for kind, names, descriptions in (
            (AGENT, data.agents, AGENT_BINARY_SENSORS),
            (BOUNCER, data.bouncers, BOUNCER_BINARY_SENSORS),
        ):
            for name in names:
                for desc in descriptions:
                    if desc.exists_fn(coordinator, name):
                        yield (
                            f"{kind}_{name}_{desc.key}",
                            lambda k=kind, n=name, d=desc: CrowdSecSubBinarySensor(
                                coordinator, entry, k, n, d
                            ),
                        )

    async_setup_dynamic(coordinator, entry, async_add_entities, build)


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


class LapiMetricsReachable(CrowdSecEntity, BinarySensorEntity):
    _attr_translation_key = "metrics_reachable"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: CrowdSecCoordinator, entry: CrowdSecConfigEntry) -> None:
        super().__init__(coordinator, entry, "metrics_reachable")

    @property
    def available(self) -> bool:
        return True

    @property
    def is_on(self) -> bool:
        data = self.coordinator.data
        return (
            self.coordinator.last_update_success
            and data is not None
            and data.lapi_metrics is not None
        )


@dataclass(frozen=True, kw_only=True)
class SubBinarySensorDescription(BinarySensorEntityDescription):
    is_on_fn: Callable[[CrowdSecCoordinator, CrowdSecData, str], bool | None]
    exists_fn: Callable[[CrowdSecCoordinator, str], bool]
    # Erreichbarkeit soll auch bei einem Ausfall einen Zustand haben.
    always_available: bool = False


AGENT_BINARY_SENSORS: tuple[SubBinarySensorDescription, ...] = (
    SubBinarySensorDescription(
        key="online",
        translation_key="agent_online",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        exists_fn=lambda c, n: c.metrics_url is not None,
        is_on_fn=lambda c, d, n: c.agent_online(n),
    ),
    SubBinarySensorDescription(
        key="reading_logs",
        translation_key="reading_logs",
        device_class=BinarySensorDeviceClass.RUNNING,
        exists_fn=lambda c, n: n in c.agent_endpoints,
        is_on_fn=lambda c, d, n: c.agent_reading_logs(n),
    ),
    SubBinarySensorDescription(
        key="metrics_reachable",
        translation_key="metrics_reachable",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        always_available=True,
        exists_fn=lambda c, n: n in c.agent_endpoints,
        is_on_fn=lambda c, d, n: d.agent_metrics.get(n) is not None,
    ),
)

BOUNCER_BINARY_SENSORS: tuple[SubBinarySensorDescription, ...] = (
    SubBinarySensorDescription(
        key="active",
        translation_key="bouncer_active",
        device_class=BinarySensorDeviceClass.RUNNING,
        exists_fn=lambda c, n: True,
        is_on_fn=lambda c, d, n: c.bouncer_active(n),
    ),
)


class CrowdSecSubBinarySensor(CrowdSecSubEntity, BinarySensorEntity):
    entity_description: SubBinarySensorDescription

    def __init__(
        self,
        coordinator: CrowdSecCoordinator,
        entry: CrowdSecConfigEntry,
        kind: str,
        name: str,
        description: SubBinarySensorDescription,
    ) -> None:
        super().__init__(coordinator, entry, kind, name, description.key)
        self.entity_description = description

    @property
    def available(self) -> bool:
        if self.entity_description.always_available:
            return True
        return super().available

    @property
    def is_on(self) -> bool | None:
        data = self.coordinator.data
        if data is None or not self.coordinator.last_update_success:
            return False if self.entity_description.always_available else None
        return self.entity_description.is_on_fn(self.coordinator, data, self._name)
