<p align="center">
  <img src="custom_components/crowdsec/brand/icon@2x.png" alt="CrowdSec integration icon" width="128">
</p>

<h1 align="center">CrowdSec for Home Assistant</h1>

<p align="center">
  <a href="https://github.com/hacs/integration"><img src="https://img.shields.io/badge/HACS-Custom-41BDF5.svg" alt="HACS Custom"></a>
  <a href="https://github.com/swater2k/ha-crowdsec/releases"><img src="https://img.shields.io/github/v/release/swater2k/ha-crowdsec" alt="Release"></a>
</p>

A custom integration for the [CrowdSec](https://www.crowdsec.net/) Local API (LAPI): active bans, alert statistics, an event for every new ban, optional actions to lift and set bans — and, from the Prometheus metrics, the health of every agent and bouncer.

> [!NOTE]
> Community project, not affiliated with CrowdSec.

## How it connects

The integration signs in to the LAPI as a **machine** (watcher) and reads alerts. A bouncer key cannot be used: only a machine can read alerts and delete decisions.

It reports only **locally created bans** (origin `crowdsec` and `cscli`). The community blocklist is deliberately left out: it arrives as a few huge alerts with tens of thousands of decisions, which would make every poll several megabytes. The filter is applied by the LAPI, not in Home Assistant.

## Features

- **Active bans**: count, plus the most recent ones with scenario and country as attributes
- **Alerts of the last 24 hours** with the most frequent countries and scenarios as attributes, for a daily summary
- **Bans in the last hour**, for a threshold notification
- **Last ban** with scenario, country, AS, origin and decision ID
- **New ban event**: fires once per banned address or range, not once per alert, and carries all details
- **LAPI reachable** binary sensor
- **Optional actions**, each turned on separately: lift bans and set manual bans
- **One device per agent** with its alerts of the last 24 hours
- **Optional metrics** of the LAPI: is every agent online (heartbeat), is every bouncer still asking for decisions, size of the community blocklist and its last pull
- **Optional metrics per agent**: log lines read, unparsed lines, a "reading logs" sensor that turns off when a log goes quiet, and AppSec requests and blocks
- Link to a web UI on the device page
- Fully local polling

## Requirements

- Home Assistant **2026.2** or newer
- CrowdSec with the Local API reachable from Home Assistant (default port `8080`)

## Installation

1. HACS → ⋮ → **Custom repositories** → add `https://github.com/swater2k/ha-crowdsec`, type **Integration**
2. Download **CrowdSec** and restart Home Assistant
3. **Settings → Devices & services → Add integration → CrowdSec**

Manual alternative: copy `custom_components/crowdsec` into your `custom_components` folder and restart.

## Setup

### 1. Let Home Assistant through

If the LAPI sits behind a firewall, allow TCP port `8080` from the Home Assistant host.

### 2. Create a machine

Run this on the CrowdSec host. The credentials go into a file instead of the terminal; delete the file after entering the password:

```bash
umask 077
cscli machines add homeassistant --auto -f /root/ha-machine.yaml
cscli machines list
```

The machine must show as validated. Read the password from the file, enter it in the next step and remove the file with `shred -u`.

### 3. Add the integration

| Field | Default | Description |
|---|---|---|
| LAPI URL | – | Address of the Local API, for example `http://192.168.1.10:8080`. Without a scheme, `http` and port `8080` are assumed. |
| Machine ID | – | The machine created above |
| Password | – | Its password |
| Verify SSL certificate | on | Only relevant for `https` |

The machine ID is used as unique ID, so a changed address can be fixed with **Reconfigure** without losing entities.

### Options

| Option | Default | Description |
|---|---|---|
| Polling interval | `60 s` | How often active bans are read (15–900 s). New bans are reported with this delay. The 24-hour statistics are refreshed every 5 minutes. |
| Control: lift bans | off | Enables the action `crowdsec.delete_decision` |
| Control: set bans | off | Enables the action `crowdsec.add_decision` |
| Web UI address | – | Link on the CrowdSec device, for example to CrowdSec Web UI |

The section **Metrics** is optional, see [Metrics](#metrics):

| Option | Default | Description |
|---|---|---|
| LAPI metrics | – | Metrics endpoint of the LAPI host, for example `http://192.168.1.10:6060/metrics` |
| Agent metrics | – | One agent per line as `name = address`, for example `caddy = http://192.168.1.20:6060/metrics` |
| Agent offline after | `5 min` | Agents send a heartbeat every minute |
| Bouncer inactive after | `10 min` | Time without any request of the bouncer to the LAPI |
| No log lines after | `1440 min` | Time without a new log line; some logs are quiet for hours |

## Entities

Entity IDs have no area prefix. They are built from the name in the language Home Assistant used when the entity was created, so check them under **Settings → Entities**.

| Entity | Type | Notes |
|---|---|---|
| Active bans | sensor | Attribute `bans` lists up to 10 |
| Alerts last 24 hours | sensor | Attributes `top_countries`, `top_scenarios` |
| Bans last hour | sensor | |
| Last ban | sensor | State is the address; attributes `scope`, `origin`, `scenario`, `country`, `asn`, `decision_id`, `banned_at` |
| New ban | event | Event type `ban` |
| LAPI reachable | binary sensor (diagnostic) | Stays available during an outage and turns off |
| Blocklist decisions | sensor | Needs LAPI metrics. Active decisions from the community blocklist and subscribed lists |
| Last blocklist pull | sensor (timestamp) | Needs LAPI metrics |
| Version | sensor (diagnostic) | Needs LAPI metrics |
| Metrics reachable | binary sensor (diagnostic) | Needs LAPI metrics |

### Agents and bouncers

Every agent gets its own device, linked to the CrowdSec device. Agents are taken from the alerts, the heartbeats and the configured agent metrics; bouncers from the LAPI metrics. New ones are added automatically. Entity IDs contain the name, for example `binary_sensor.crowdsec_agent_caddy_online`.

| Entity | Device | Needs | Notes |
|---|---|---|---|
| Alerts last 24 hours | agent | – | Alerts with a local ban; manual bans are not counted |
| Online | agent | LAPI metrics | Off when the last heartbeat is older than the threshold |
| Last heartbeat | agent | LAPI metrics | Timestamp |
| Log lines read | agent | agent metrics | Total, attribute `sources` per log file |
| Unparsed log lines | agent | agent metrics | Total; a sudden rise usually means a changed log format |
| Last log line | agent | agent metrics | Time a new line was last seen; unknown until the first new line after a restart |
| Reading logs | agent | agent metrics | Off when no new line arrived within the threshold |
| AppSec requests, AppSec blocks | agent | agent metrics | Only for agents running AppSec |
| Version, Metrics reachable | agent | agent metrics | Diagnostic |
| Active | bouncer | LAPI metrics | Off when the bouncer did not ask the LAPI within the threshold |
| Last pull | bouncer | LAPI metrics | Time of the last request seen; unknown until the first request after a restart |

Right after a restart of Home Assistant, agents and bouncers count as active until the threshold has passed, so a restart does not report everything as down.

Alerts without a ban (for example from allowlisted addresses) are not counted: the statistics only cover alerts that led to a local ban.

### The new ban event

Each event carries `value`, `scope` (`Ip` or `Range`), `origin` (`crowdsec` or `cscli`), `scenario`, `country`, `asn`, `decision_id`, `banned_at`, `duration` (remaining) and `expires_at`. The first poll after a restart reports nothing, so a restart does not announce every active ban as new. At most 25 events are reported per poll.

```yaml
triggers:
  - trigger: state
    entity_id: event.crowdsec_new_ban
conditions:
  - condition: template
    value_template: "{{ trigger.to_state.attributes.origin == 'cscli' }}"
actions:
  - action: notify.notify
    data:
      message: "Manual ban: {{ trigger.to_state.attributes.value }}"
```

## Metrics

CrowdSec serves Prometheus metrics on port `6060`, by default only on `127.0.0.1`. They are read without authentication.

1. On the LAPI host (and on every agent you want to watch), set `listen_addr` in `/etc/crowdsec/config.yaml` to the host's address and restart CrowdSec. For an agent in Docker, also publish port `6060`.

   ```yaml
   prometheus:
     enabled: true
     level: full
     listen_addr: 192.168.1.10
     listen_port: 6060
   ```

2. Allow TCP port `6060` from the Home Assistant host only.
3. Enter the addresses in the options. Name agent endpoints after their machine (`cscli machines list`), then their sensors join the device of that agent.

The LAPI metrics alone already tell whether every agent and bouncer is alive. Agent metrics add the log and AppSec counters.

```yaml
triggers:
  - trigger: state
    entity_id:
      - binary_sensor.crowdsec_agent_caddy_online
      - binary_sensor.crowdsec_bouncer_caddy_active
    to: "off"
    for: "00:05:00"
actions:
  - action: notify.notify
    data:
      message: "CrowdSec: {{ trigger.to_state.name }} is down"
```

## Actions

| Action | Needs option | Description |
|---|---|---|
| `crowdsec.delete_decision` | Control: lift bans | Delete the decisions for an address or CIDR range. A single address also lifts ranges that contain it, like `cscli decisions delete --ip`. Returns `deleted`, the number of removed decisions. |
| `crowdsec.add_decision` | Control: set bans | Ban an address or range, with a duration (Go notation with `ms`, `s`, `m`, `h`, for example `4h`; days are not supported, use `168h` for a week) and a reason. The UI offers common durations and accepts any other. |

```yaml
action: crowdsec.delete_decision
data:
  ip: 203.0.113.7
response_variable: result
```

## Removal

1. **Settings → Devices & services → CrowdSec → ⋮ → Delete**
2. Remove the machine on the CrowdSec host with `cscli machines delete homeassistant`
3. Remove the repository in HACS and restart Home Assistant

## Troubleshooting

- **"The LAPI is not reachable"**: check address, port and the firewall rule for the Home Assistant host.
- **"Machine ID or password rejected"**: the machine is probably not validated yet. Run `cscli machines validate <name>` and check `cscli machines list`.
- **A ban is not reported**: bans from the community blocklist are never reported. Everything else shows up within one polling interval.
- **"No CrowdSec metrics from: …"**: the endpoint is not reachable or answers without CrowdSec metrics. Check `listen_addr`, the published port of a Docker agent and the firewall rule for port `6060`.
- **An agent shows offline right after a LAPI restart**: the LAPI keeps heartbeats in memory only; the agent comes back with its next heartbeat within a minute.
- **An extra agent device appears**: every machine that sends heartbeats or creates alerts gets a device. Disable or delete devices you do not need.
- **Diagnostics**: Settings → Devices & services → CrowdSec → ⋮ → Download diagnostics. URL, machine ID, password and all addresses are redacted.

```yaml
logger:
  logs:
    custom_components.crowdsec: debug
```

## License

[MIT](LICENSE)
