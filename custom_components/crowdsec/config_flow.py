"""Config-, Reauth-, Reconfigure- und Options-Flow."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any
from urllib.parse import urlsplit

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import voluptuous as vol

from . import build_api
from .api import CrowdSecAuthError, CrowdSecConnectionError, CrowdSecError, normalize_url
from .const import (
    CONF_CONTROL_BAN,
    CONF_CONTROL_UNBAN,
    CONF_MACHINE_ID,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)

_PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
# Hassfest verbietet URLs in Übersetzungen – das Beispiel kommt als Platzhalter.
PLACEHOLDERS = {"example_url": "http://192.168.1.10:8080"}


def _schema(defaults: Mapping[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_URL, default=defaults.get(CONF_URL, "")): TextSelector(),
            vol.Required(CONF_MACHINE_ID, default=defaults.get(CONF_MACHINE_ID, "")): (
                TextSelector()
            ),
            vol.Required(CONF_PASSWORD): _PASSWORD,
            vol.Required(CONF_VERIFY_SSL, default=defaults.get(CONF_VERIFY_SSL, True)): (
                BooleanSelector()
            ),
        }
    )


def _normalize(user_input: Mapping[str, Any]) -> dict[str, Any]:
    return {
        CONF_URL: normalize_url(user_input[CONF_URL]),
        CONF_MACHINE_ID: user_input[CONF_MACHINE_ID].strip(),
        CONF_PASSWORD: user_input[CONF_PASSWORD],
        CONF_VERIFY_SSL: bool(user_input.get(CONF_VERIFY_SSL, True)),
    }


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, str]:
    """Anmelden; liefert die Fehler (leer bei Erfolg)."""
    try:
        await build_api(hass, data).async_check()
    except CrowdSecAuthError:
        return {"base": "invalid_auth"}
    except CrowdSecConnectionError:
        return {"base": "cannot_connect"}
    except CrowdSecError:
        return {"base": "invalid_response"}
    except Exception:
        _LOGGER.exception("Unexpected error during validation")
        return {"base": "unknown"}
    return {}


class CrowdSecConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = _normalize(user_input)
            except ValueError:
                errors["base"] = "invalid_url"
            else:
                errors = await validate_input(self.hass, data)
                if not errors:
                    # Die LAPI hat keine Instanz-ID; die Machine ist das Stabilste.
                    await self.async_set_unique_id(data[CONF_MACHINE_ID])
                    self._abort_if_unique_id_configured(updates={CONF_URL: data[CONF_URL]})
                    host = urlsplit(data[CONF_URL]).hostname or data[CONF_URL]
                    return self.async_create_entry(title=f"CrowdSec ({host})", data=data)
        return self.async_show_form(
            step_id="user",
            data_schema=_schema(user_input or {}),
            errors=errors,
            description_placeholders=PLACEHOLDERS,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {**entry.data, CONF_PASSWORD: user_input[CONF_PASSWORD]}
            errors = await validate_input(self.hass, data)
            if not errors:
                return self.async_update_reload_and_abort(entry, data_updates=data)
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): _PASSWORD}),
            description_placeholders={"machine": entry.data[CONF_MACHINE_ID]},
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = _normalize(user_input)
            except ValueError:
                errors["base"] = "invalid_url"
            else:
                errors = await validate_input(self.hass, data)
                if not errors:
                    await self.async_set_unique_id(data[CONF_MACHINE_ID])
                    self._abort_if_unique_id_mismatch(reason="different_machine")
                    return self.async_update_reload_and_abort(entry, data_updates=data)
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_schema(user_input or dict(entry.data)),
            errors=errors,
            description_placeholders=PLACEHOLDERS,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> CrowdSecOptionsFlow:
        return CrowdSecOptionsFlow()


class CrowdSecOptionsFlow(OptionsFlowWithReload):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(
                data={
                    CONF_SCAN_INTERVAL: int(user_input[CONF_SCAN_INTERVAL]),
                    CONF_CONTROL_UNBAN: bool(user_input.get(CONF_CONTROL_UNBAN, False)),
                    CONF_CONTROL_BAN: bool(user_input.get(CONF_CONTROL_BAN, False)),
                }
            )
        opts = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL,
                        default=opts.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=MIN_SCAN_INTERVAL,
                            max=MAX_SCAN_INTERVAL,
                            step=5,
                            unit_of_measurement="s",
                            mode=NumberSelectorMode.BOX,
                        )
                    ),
                    vol.Optional(
                        CONF_CONTROL_UNBAN, default=opts.get(CONF_CONTROL_UNBAN, False)
                    ): BooleanSelector(),
                    vol.Optional(
                        CONF_CONTROL_BAN, default=opts.get(CONF_CONTROL_BAN, False)
                    ): BooleanSelector(),
                }
            ),
        )
