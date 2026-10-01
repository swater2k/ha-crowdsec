"""Aktionen zum Aufheben und Setzen von Sperren."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
import voluptuous as vol

from .api import CrowdSecError
from .const import CONF_CONTROL_BAN, CONF_CONTROL_UNBAN, DOMAIN

if TYPE_CHECKING:
    from . import CrowdSecConfigEntry

ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_IP = "ip"
ATTR_DURATION = "duration"
ATTR_REASON = "reason"

DEFAULT_DURATION = "4h"
DEFAULT_REASON = "Home Assistant"


def _ip_or_cidr(value: Any) -> str:
    value = str(value).strip()
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as err:
        raise vol.Invalid(f"invalid IP address or range: {value}") from err
    return value


# Go-Dauer: Einheiten ms, s, m, h – „d“ für Tage kennt die LAPI nicht.
_DURATION = vol.All(cv.string, vol.Match(r"^(\d+(\.\d+)?(ms|s|m|h))+$"))

DELETE_SCHEMA = vol.Schema(
    {vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string, vol.Required(ATTR_IP): _ip_or_cidr}
)
ADD_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required(ATTR_IP): _ip_or_cidr,
        vol.Optional(ATTR_DURATION, default=DEFAULT_DURATION): _DURATION,
        vol.Optional(ATTR_REASON, default=DEFAULT_REASON): cv.string,
    }
)


def _target(value: str) -> tuple[str, str]:
    """(``Ip``|``Range``, normalisierter Wert); ein /32 bzw. /128 zählt als einzelne Adresse."""
    network = ipaddress.ip_network(value, strict=False)
    if network.num_addresses == 1:
        return "Ip", str(network.network_address)
    return "Range", str(network)


def _entry(hass: HomeAssistant, call: ServiceCall, option: str) -> CrowdSecConfigEntry:
    entries = [
        e for e in hass.config_entries.async_entries(DOMAIN) if e.state is ConfigEntryState.LOADED
    ]
    if entry_id := call.data.get(ATTR_CONFIG_ENTRY_ID):
        entries = [e for e in entries if e.entry_id == entry_id]
        if not entries:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="entry_not_found"
            )
    if len(entries) != 1:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_ambiguous")
    entry = entries[0]
    if not entry.options.get(option, False):
        raise ServiceValidationError(
            translation_domain=DOMAIN,
            translation_key="control_disabled",
            translation_placeholders={"title": entry.title},
        )
    return entry


def async_setup_services(hass: HomeAssistant) -> None:
    async def delete_decision(call: ServiceCall) -> dict[str, Any]:
        entry = _entry(hass, call, CONF_CONTROL_UNBAN)
        coordinator = entry.runtime_data
        scope, value = _target(call.data[ATTR_IP])
        try:
            deleted = await coordinator.api.async_delete_decisions(
                **({"ip": value} if scope == "Ip" else {"range_": value})
            )
        except CrowdSecError as err:
            raise HomeAssistantError(f"CrowdSec: {err}") from err
        await coordinator.async_request_refresh()
        return {"deleted": deleted}

    async def add_decision(call: ServiceCall) -> None:
        entry = _entry(hass, call, CONF_CONTROL_BAN)
        coordinator = entry.runtime_data
        scope, value = _target(call.data[ATTR_IP])
        try:
            await coordinator.api.async_add_decision(
                scope=scope,
                value=value,
                duration=call.data[ATTR_DURATION],
                reason=call.data[ATTR_REASON],
            )
        except CrowdSecError as err:
            raise HomeAssistantError(f"CrowdSec: {err}") from err
        await coordinator.async_request_refresh()

    hass.services.async_register(
        DOMAIN,
        "delete_decision",
        delete_decision,
        schema=DELETE_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(DOMAIN, "add_decision", add_decision, schema=ADD_SCHEMA)
