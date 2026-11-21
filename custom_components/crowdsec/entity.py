"""Basis-Entitäten: die LAPI selbst sowie je Agent und je Bouncer ein eigenes Gerät."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_WEB_UI_URL, DOMAIN
from .coordinator import CrowdSecCoordinator
from .stable_id import StableEntityIdMixin

if TYPE_CHECKING:
    from . import CrowdSecConfigEntry

AGENT = "agent"
BOUNCER = "bouncer"


def main_device(entry: CrowdSecConfigEntry) -> DeviceInfo:
    info = DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="CrowdSec",
        manufacturer="CrowdSec",
        model="Local API",
        entry_type=DeviceEntryType.SERVICE,
    )
    if url := entry.options.get(CONF_WEB_UI_URL):
        info["configuration_url"] = url
    return info


# Ab Home Assistant 2026.10 verweist ein Gerät per Geräte-ID auf sein übergeordnetes
# Gerät (``via_device_id``); ``via_device`` mit Kennung gilt dort als veraltet.
_VIA_DEVICE_ID = "via_device_id" in DeviceInfo.__optional_keys__


def sub_device(
    entry: CrowdSecConfigEntry, kind: str, name: str, main_device_id: str | None
) -> DeviceInfo:
    info = DeviceInfo(
        identifiers={(DOMAIN, f"{entry.entry_id}_{kind}_{name}")},
        name=f"CrowdSec {'Agent' if kind == AGENT else 'Bouncer'} {name}",
        manufacturer="CrowdSec",
        model="Security Engine" if kind == AGENT else "Bouncer",
        entry_type=DeviceEntryType.SERVICE,
    )
    if _VIA_DEVICE_ID:
        if main_device_id:
            info["via_device_id"] = main_device_id  # type: ignore[typeddict-unknown-key]
    else:
        info["via_device"] = (DOMAIN, entry.entry_id)
    return info


class CrowdSecEntity(StableEntityIdMixin, CoordinatorEntity[CrowdSecCoordinator]):
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CrowdSecCoordinator, entry: CrowdSecConfigEntry, key: str
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._id_prefix = DOMAIN
        self._attr_device_info = main_device(entry)


class CrowdSecSubEntity(StableEntityIdMixin, CoordinatorEntity[CrowdSecCoordinator]):
    """Entität eines Agents oder Bouncers; die ID trägt dessen Namen."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CrowdSecCoordinator,
        entry: CrowdSecConfigEntry,
        kind: str,
        name: str,
        key: str,
    ) -> None:
        super().__init__(coordinator)
        self._kind = kind
        self._name = name
        self._attr_unique_id = f"{entry.entry_id}_{kind}_{name}_{key}"
        self._id_prefix = f"{DOMAIN} {kind} {name}"
        self._attr_device_info = sub_device(entry, kind, name, coordinator.main_device_id)


def async_setup_dynamic(
    coordinator: CrowdSecCoordinator,
    entry: CrowdSecConfigEntry,
    async_add_entities: Callable[[Iterable[Entity]], None],
    build: Callable[[], Iterable[tuple[str, Callable[[], Entity]]]],
) -> None:
    """Fügt Entitäten hinzu, sobald ihr Agent oder Bouncer zum ersten Mal auftaucht.

    ``build`` liefert ``(schlüssel, fabrik)``; jede Fabrik läuft nur einmal je
    Schlüssel. Verschwundene Agents bleiben als „nicht verfügbar“ bzw. mit dem
    letzten Stand stehen und lassen sich in Home Assistant löschen.
    """
    known: set[str] = set()

    @callback
    def _add() -> None:
        new: list[Entity] = []
        for key, make in build():
            if key not in known:
                known.add(key)
                new.append(make())
        if new:
            async_add_entities(new)

    _add()
    entry.async_on_unload(coordinator.async_add_listener(_add))
