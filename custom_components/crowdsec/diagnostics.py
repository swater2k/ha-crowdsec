"""Diagnose-Download."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_URL
from homeassistant.core import HomeAssistant

from . import CrowdSecConfigEntry
from .const import CONF_AGENT_METRICS, CONF_MACHINE_ID, CONF_METRICS_URL, CONF_WEB_UI_URL

TO_REDACT = {
    CONF_PASSWORD,
    CONF_URL,
    CONF_MACHINE_ID,
    CONF_METRICS_URL,
    CONF_AGENT_METRICS,
    CONF_WEB_UI_URL,
    "value",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: CrowdSecConfigEntry
) -> dict[str, Any]:
    coordinator = entry.runtime_data
    data = coordinator.data
    result: dict[str, Any] = {
        "entry": {
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": async_redact_data(dict(entry.options), TO_REDACT),
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
            "alerts_by_agent": data.stats.by_machine,
            "lapi_metrics": None
            if data.lapi_metrics is None
            else {
                "version": data.lapi_metrics.version,
                "heartbeats": {m: ts.isoformat() for m, ts in data.lapi_metrics.heartbeats.items()},
                "bouncer_requests": data.lapi_metrics.bouncer_requests,
                "blocklist_decisions": data.lapi_metrics.blocklist_decisions,
            },
            "agent_metrics": {
                name: None
                if m is None
                else {
                    "version": m.version,
                    "lines_read": m.lines_read,
                    "sources": len(m.lines_by_source),
                    "lines_unparsed": m.lines_unparsed,
                    "appsec_requests": m.appsec_requests,
                    "appsec_blocks": m.appsec_blocks,
                }
                for name, m in data.agent_metrics.items()
            },
        }
    )
    return result
