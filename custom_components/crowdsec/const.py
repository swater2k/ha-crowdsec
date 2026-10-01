"""Konstanten der CrowdSec-Integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "crowdsec"

# Die LAPI lehnt den Login ab (401 „incorrect Username or Password“), wenn der
# User-Agent nicht aus genau einem Teil der Form ``name/version`` besteht –
# auch bei richtigem Passwort. Der Standard-Agent von Home Assistant
# („HomeAssistant/x aiohttp/y Python/z“) fällt dadurch durch. Die Version muss
# zur manifest.json passen (ein Test prüft das).
USER_AGENT: Final = "ha-crowdsec/0.1.1"

CONF_MACHINE_ID: Final = "machine_id"
CONF_SCAN_INTERVAL: Final = "scan_interval"

# Steuerfunktionen – jede einzeln über die Optionen freischaltbar.
CONF_CONTROL_UNBAN: Final = "control_unban"
CONF_CONTROL_BAN: Final = "control_ban"

DEFAULT_PORT: Final = 8080
DEFAULT_SCAN_INTERVAL: Final = 60
MIN_SCAN_INTERVAL: Final = 15
MAX_SCAN_INTERVAL: Final = 900
# Die 24-Stunden-Statistik lädt alle Alerts samt Ereignissen; das muss nicht
# jede Minute sein.
STATS_INTERVAL: Final = 300

# Nur lokal entstandene Sperren. Die Community-Blocklist (CAPI) hängt in
# einem einzigen Alert Zehntausende Decisions an; der Filter greift auf dem
# Server, sonst würden pro Abruf mehrere Megabyte übertragen.
ORIGINS: Final = ("crowdsec", "cscli")

EVENT_BAN: Final = "ban"
MAX_EVENTS_PER_UPDATE: Final = 25
MAX_LISTED_BANS: Final = 10
