"""Diagnose-Download."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_URL
from homeassistant.core import HomeAssistant

from . import CrowdSecConfigEntry
from .const import CONF_MACHINE_ID

TO_REDACT = {CONF_PASSWORD, CONF_URL, CONF_MACHINE_ID, "value"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: CrowdSecConfigEntry
) -> dict[str, Any]:
    coordinator = entry.runtime_data
    data = coordinator.data
    result: dict[str, Any] = {
        "entry": {
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": dict(entry.options),
        },
        "last_update_success": coordinator.last_update_success,
    }
    if data is None:
        return result
    result.update(
        {
            "active_bans": async_redact_data(
                [
                    {"value": b.value, **b.as_attributes(), "duration": b.duration}
                    for b in data.active_bans
                ],
                TO_REDACT,
            ),
            "bans_last_hour": data.bans_last_hour,
            "alerts_24h": data.stats.total,
            "top_countries": data.stats.by_country,
            "top_scenarios": data.stats.by_scenario,
        }
    )
    return result
