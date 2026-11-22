"""CrowdSec-Integration für Home Assistant."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import CrowdSecApi
from .const import CONF_MACHINE_ID, CONF_WEB_UI_URL, DOMAIN
from .coordinator import CrowdSecCoordinator
from .entity import main_device
from .services import async_setup_services

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.EVENT, Platform.SENSOR]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

type CrowdSecConfigEntry = ConfigEntry[CrowdSecCoordinator]


def build_api(hass: HomeAssistant, data: dict) -> CrowdSecApi:
    session = async_get_clientsession(hass, verify_ssl=data.get(CONF_VERIFY_SSL, True))
    return CrowdSecApi(session, data[CONF_URL], data[CONF_MACHINE_ID], data[CONF_PASSWORD])


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    coordinator = CrowdSecCoordinator(hass, entry, build_api(hass, dict(entry.data)))
    # Das Gerät der LAPI vorab anlegen: Agents und Bouncer verweisen per ID darauf.
    # configuration_url ausdrücklich setzen, damit ein entfernter Link verschwindet.
    device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        **{**main_device(entry), "configuration_url": entry.options.get(CONF_WEB_UI_URL) or None},
    )
    coordinator.main_device_id = device.id
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: CrowdSecConfigEntry, device: dr.DeviceEntry
) -> bool:
    """Agents und Bouncer, die nicht mehr auftauchen, lassen sich in der UI löschen.

    Das Gerät der LAPI selbst und alles, was die LAPI gerade noch meldet, nicht –
    das würde beim nächsten Neustart ohnehin wieder angelegt.
    """
    return not any(
        domain == DOMAIN and entry.runtime_data.is_current(identifier)
        for domain, identifier in device.identifiers
    )


def option_enabled(entry: CrowdSecConfigEntry, option: str) -> bool:
    return bool(entry.options.get(option, False))
