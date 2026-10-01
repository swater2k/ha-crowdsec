"""CrowdSec-Integration für Home Assistant."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import CrowdSecApi
from .const import CONF_MACHINE_ID, DOMAIN
from .coordinator import CrowdSecCoordinator
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
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: CrowdSecConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


def option_enabled(entry: CrowdSecConfigEntry, option: str) -> bool:
    return bool(entry.options.get(option, False))
