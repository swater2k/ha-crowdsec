"""Sensoren der LAPI sowie je Agent und je Bouncer."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.typing import StateType

from . import CrowdSecConfigEntry
from .const import MAX_LISTED_BANS
from .coordinator import CrowdSecCoordinator, CrowdSecData
from .entity import AGENT, BOUNCER, CrowdSecEntity, CrowdSecSubEntity, async_setup_dynamic
from .metrics import AgentMetrics

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class CrowdSecSensorDescription(SensorEntityDescription):
    value_fn: Callable[[CrowdSecData], StateType | datetime]
    attrs_fn: Callable[[CrowdSecData], dict[str, Any]] | None = None
    # Nur mit eingerichteten LAPI-Metriken anlegen und nur verfügbar, wenn sie ankommen.
    needs_metrics: bool = False


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
        "by_agent": data.stats.by_machine or {},
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
    CrowdSecSensorDescription(
        key="blocklist_decisions",
        translation_key="blocklist_decisions",
        state_class=SensorStateClass.MEASUREMENT,
        needs_metrics=True,
        value_fn=lambda d: d.lapi_metrics.blocklist_decisions if d.lapi_metrics else None,
    ),
    CrowdSecSensorDescription(
        key="blocklist_last_pull",
        translation_key="blocklist_last_pull",
        device_class=SensorDeviceClass.TIMESTAMP,
        needs_metrics=True,
        value_fn=lambda d: d.lapi_metrics.capi_last_pull if d.lapi_metrics else None,
    ),
    CrowdSecSensorDescription(
        key="version",
        translation_key="version",
        entity_category=EntityCategory.DIAGNOSTIC,
        needs_metrics=True,
        value_fn=lambda d: d.lapi_metrics.version if d.lapi_metrics else None,
    ),
)


@dataclass(frozen=True, kw_only=True)
class SubSensorDescription(SensorEntityDescription):
    """Sensor eines Agents oder Bouncers; die Funktionen bekommen dessen Namen."""

    value_fn: Callable[[CrowdSecCoordinator, CrowdSecData, str], StateType | datetime]
    exists_fn: Callable[[CrowdSecCoordinator, CrowdSecData, str], bool]
    available_fn: Callable[[CrowdSecCoordinator, CrowdSecData, str], bool] | None = None
    attrs_fn: Callable[[CrowdSecCoordinator, CrowdSecData, str], dict[str, Any]] | None = None


def _agent(data: CrowdSecData, name: str) -> AgentMetrics | None:
    return data.agent_metrics.get(name)


def _has_endpoint(c: CrowdSecCoordinator, _d: CrowdSecData, name: str) -> bool:
    return name in c.agent_endpoints


def _endpoint_ok(_c: CrowdSecCoordinator, d: CrowdSecData, name: str) -> bool:
    return _agent(d, name) is not None


def _has_appsec(c: CrowdSecCoordinator, d: CrowdSecData, name: str) -> bool:
    return (m := _agent(d, name)) is not None and m.appsec_requests is not None


AGENT_SENSORS: tuple[SubSensorDescription, ...] = (
    SubSensorDescription(
        key="alerts_24h",
        translation_key="agent_alerts_24h",
        state_class=SensorStateClass.MEASUREMENT,
        exists_fn=lambda c, d, n: True,
        value_fn=lambda c, d, n: (d.stats.by_machine or {}).get(n, 0),
    ),
    SubSensorDescription(
        key="last_heartbeat",
        translation_key="last_heartbeat",
        device_class=SensorDeviceClass.TIMESTAMP,
        exists_fn=lambda c, d, n: c.metrics_url is not None,
        value_fn=lambda c, d, n: c.heartbeats.get(n),
    ),
    SubSensorDescription(
        key="lines_read",
        translation_key="lines_read",
        state_class=SensorStateClass.TOTAL_INCREASING,
        exists_fn=_has_endpoint,
        available_fn=_endpoint_ok,
        value_fn=lambda c, d, n: m.lines_read if (m := _agent(d, n)) else None,
        attrs_fn=lambda c, d, n: {"sources": m.lines_by_source} if (m := _agent(d, n)) else {},
    ),
    SubSensorDescription(
        key="lines_unparsed",
        translation_key="lines_unparsed",
        state_class=SensorStateClass.TOTAL_INCREASING,
        exists_fn=_has_endpoint,
        available_fn=_endpoint_ok,
        value_fn=lambda c, d, n: m.lines_unparsed if (m := _agent(d, n)) else None,
    ),
    SubSensorDescription(
        key="last_log_line",
        translation_key="last_log_line",
        device_class=SensorDeviceClass.TIMESTAMP,
        exists_fn=_has_endpoint,
        value_fn=lambda c, d, n: c.log_activity.last_change(n),
    ),
    SubSensorDescription(
        key="appsec_requests",
        translation_key="appsec_requests",
        state_class=SensorStateClass.TOTAL_INCREASING,
        exists_fn=_has_appsec,
        available_fn=_endpoint_ok,
        value_fn=lambda c, d, n: m.appsec_requests if (m := _agent(d, n)) else None,
    ),
    SubSensorDescription(
        key="appsec_blocks",
        translation_key="appsec_blocks",
        state_class=SensorStateClass.TOTAL_INCREASING,
        exists_fn=_has_appsec,
        available_fn=_endpoint_ok,
        value_fn=lambda c, d, n: m.appsec_blocks if (m := _agent(d, n)) else None,
    ),
    SubSensorDescription(
        key="version",
        translation_key="version",
        entity_category=EntityCategory.DIAGNOSTIC,
        exists_fn=_has_endpoint,
        available_fn=_endpoint_ok,
        value_fn=lambda c, d, n: m.version if (m := _agent(d, n)) else None,
    ),
)

BOUNCER_SENSORS: tuple[SubSensorDescription, ...] = (
    SubSensorDescription(
        key="last_pull",
        translation_key="bouncer_last_pull",
        device_class=SensorDeviceClass.TIMESTAMP,
        exists_fn=lambda c, d, n: True,
        value_fn=lambda c, d, n: c.bouncer_activity.last_change(n),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CrowdSecConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        CrowdSecSensor(coordinator, entry, desc)
        for desc in SENSORS
        if not desc.needs_metrics or coordinator.metrics_url
    )

    def build() -> Iterable[tuple[str, Callable[[], Entity]]]:
        data = coordinator.data
        if data is None:
            return
        for kind, names, descriptions in (
            (AGENT, data.agents, AGENT_SENSORS),
            (BOUNCER, data.bouncers, BOUNCER_SENSORS),
        ):
            for name in names:
                for desc in descriptions:
                    if desc.exists_fn(coordinator, data, name):
                        yield (
                            f"{kind}_{name}_{desc.key}",
                            lambda k=kind, n=name, d=desc: CrowdSecSubSensor(
                                coordinator, entry, k, n, d
                            ),
                        )

    async_setup_dynamic(coordinator, entry, async_add_entities, build)


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
    def available(self) -> bool:
        if not super().available:
            return False
        return not self.entity_description.needs_metrics or (
            self.coordinator.data.lapi_metrics is not None
        )

    @property
    def native_value(self) -> StateType | datetime:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator.data)


class CrowdSecSubSensor(CrowdSecSubEntity, SensorEntity):
    entity_description: SubSensorDescription

    def __init__(
        self,
        coordinator: CrowdSecCoordinator,
        entry: CrowdSecConfigEntry,
        kind: str,
        name: str,
        description: SubSensorDescription,
    ) -> None:
        super().__init__(coordinator, entry, kind, name, description.key)
        self.entity_description = description

    @property
    def available(self) -> bool:
        if not super().available:
            return False
        check = self.entity_description.available_fn
        return check is None or check(self.coordinator, self.coordinator.data, self._name)

    @property
    def native_value(self) -> StateType | datetime:
        return self.entity_description.value_fn(self.coordinator, self.coordinator.data, self._name)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator, self.coordinator.data, self._name)
