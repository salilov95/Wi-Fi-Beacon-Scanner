<p align="center">
  <b>English</b> · <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <img src="docs/images/logo.png" width="96" alt="">
</p>

<h1 align="center">Wi-Fi Beacon Scanner</h1>

<p align="center">
  Wi-Fi scanner and troubleshooting tool for Windows 10/11: what access points advertise, where coverage
  is weak, and why a laptop roams or drops the connection.
</p>

<p align="center">
  <a href="https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/latest"><img alt="Download" src="https://img.shields.io/badge/download-Windows_10%2F11-0a6c8f?style=flat-square&logo=windows"></a>
  <a href="https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/salilov95/Wi-Fi-Beacon-Scanner?style=flat-square"></a>
  <a href="https://github.com/salilov95/Wi-Fi-Beacon-Scanner/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/salilov95/Wi-Fi-Beacon-Scanner/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-3776ab?style=flat-square&logo=python&logoColor=white">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-none-2ea44f?style=flat-square">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square"></a>
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#where-the-data-comes-from">Data sources</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="docs/images/main.png" alt="Main window: network table and 2.4 GHz channel spectrum">
</p>

> The user interface is in Russian. Screenshots below show the Russian UI; the documentation is available
> in both English and Russian.

<details>
<summary>UI glossary: tab and menu names</summary>

| In the app | Meaning |
|---|---|
| Сканировать · Авто | Scan · Auto-scan |
| Мои SSID | My SSIDs (your networks; problems are reported for them) |
| Каналы · Обзор · Утилизация | Channels · Overview · Utilization |
| Сигнал во времени · Подключение · Обход | Signal over time · Connection journal · Floor plan survey |
| Проблемы · Beacon | Problems · Beacon decoder |
| Сессии · Журнал Windows · Сравнение | Sessions · Windows event log · Compare |
| Экспорт · Вид · О программе | Export · View · About |
| Проверить обновления · Папка с журналом | Check for updates · Log folder |

</details>

## Features

- **Network table** - every access point on 2.4, 5 and 6 GHz: signal and trend, channel and width, security
  (WPA2/WPA3, PMF, AKM), Wi-Fi generation, maximum MCS and PHY rate, channel load, clients, vendor.
  Auto-scan every 5 seconds; columns can be hidden and resized.
- **802.11 amendments** - d, e, h, i, k, r, u, v, w plus mc (FTM), TWT, Multiple BSSID and Hotspot 2.0
  in a table column, a filter and the beacon decoder.
- **Channels** - spectrum view per band with the DFS range and a hint on which channel is the least busy.
- **Laptop connection journal** - roams, disconnects with the reason reported by Windows, ping-pong,
  sticky client on a weak AP.
- **Connection sessions** - client state machine: association, 802.1X/EAP and 4-way handshake, DHCP,
  with the duration of each stage; 802.1X result with the failure reason and Windows events around the session.
- **Windows event log** - WLAN-AutoConfig for the last day, 3 days or week: connections, failures and
  disconnects with reasons; loads on start and refreshes every minute.
- **Floor plan survey** - coverage map from measurement points (site survey).
- **Signal over time** - RSSI charts and a heat map with auto-scan.
- **Channel utilization** - QBSS Load from beacons, green to red.
- **Problems** - 29 checks for security, roaming, RF and network hygiene, each with a hint on what to check.
- **Beacon decoder** - every Information Element of the selected AP.
- **Reports** - PDF, Excel, HTML, CSV, JSON: all networks, only yours, or exactly what the table shows.
- **Ready for fleet deployment** - silent installer, seven themes, no external dependencies.

### 802.11 amendments

Which amendments each AP advertises: d, e, h, i, k, r, u, v, w, plus FTM (802.11mc), FILS, mesh, TWT,
Multiple BSSID and Hotspot 2.0. The table shows a row of letters; the filter offers "has all selected" or
"has none of the selected", with the number of BSSs next to each item. Per-AP details (MDID, 802.11u network
type, Power Constraint, Extended Capabilities bits) are on the Beacon tab. Where each letter comes from is
described in the [documentation](docs/en/diagnostics.md#80211-amendments-column-and-filter).

<img src="docs/images/standards.png" alt="802.11 amendments filter">

### Laptop connection journal

The app polls its own connection once per second: which AP the laptop is on, with what signal and rate.
You see every roam (from, to, RSSI before and after, time spent on the previous AP), disconnects with the
reason from Windows, ping-pong between two APs, and the sticky client case when the laptop holds on to a weak
AP while a stronger one is available. The MCS of the current connection is estimated from the Rx/Tx rates.

<img src="docs/images/connection.png" alt="Connection journal: signal chart with roams and a disconnect">

### Connection sessions

Every connection and every roam is broken down into stages using Windows notifications: association,
authentication (802.1X/EAP exchange and 4-way handshake), and IPv4 via DHCP. You see how long each stage took,
how 802.1X ended (success, or failure with the reason and EAP error code, EAP type, machine or user
credentials), when the DHCP lease arrived and from which server. A fast FT roam (tens of ms) is immediately
distinguishable from a roam with full 802.1X authentication (hundreds of ms). Session details also list the
Windows event log entries around it. No administrator rights required.

<img src="docs/images/sessions.png" alt="Connection sessions: stages, 802.1X, DHCP">

### Windows event log

Events from `Microsoft-Windows-WLAN-AutoConfig/Operational` with the text written by Windows itself:
connection start and result, association, security checks and 4-way handshake, 802.1X, disconnects with
the reason. The last day is loaded on start and refreshed every minute; filters by stage and level, a summary
of the most frequent reasons, all event fields on click, CSV export.

<img src="docs/images/winlog.png" alt="Windows WLAN-AutoConfig event log">

### Floor plan survey

Load a floor plan, walk around with the laptop and mark where you are. At each point the app runs a scan and
builds a coverage map: signal of the selected network, the laptop's own connection signal, or how many APs are
heard for roaming. Far from the measurement points the map shows nothing rather than guessing. The project is
saved to a file, the map to PNG.

<img src="docs/images/survey.png" alt="Coverage map on a floor plan">

### Signal over time

RSSI of every AP of the selected network across scans: lines are colored by level, the background shows quality
zones. The "AP × scan" heat map shows at a glance which AP disappears.

<img src="docs/images/signal.png" alt="Signal over time per AP">

<img src="docs/images/heatmap.png" alt="Signal heat map">

### Channel utilization

How much airtime is busy on each channel according to the APs themselves (QBSS Load), the number of clients
and the history across scans. Channels where APs do not report load are listed separately.

<img src="docs/images/utilization.png" alt="Channel utilization">

### Problems

Open and WEP networks, TKIP, no PMF, 802.11k/r/v enabled on some APs only, different security settings within
one SSID, overlapping 2.4 GHz channels, overloaded channels, weak signal. Clicking a problem highlights the
affected APs in the table. Full list in the [documentation](docs/en/diagnostics.md).

<img src="docs/images/findings.png" alt="Problems with hints">

### Beacon decoder

All Information Elements of the selected AP, decoded and in hex: RSN, HT/VHT/HE Capabilities and Operation,
MCS sets, BSS Color, 6 GHz parameters, vendor IEs.

<img src="docs/images/beacon.png" alt="Beacon decoder">

### Overview

Number of APs per channel, distribution by signal level, security, Wi-Fi generation, channel width and vendor.

<img src="docs/images/overview.png" alt="Air overview">

### Reports and themes

PDF and Excel reports (with color scales for signal and load), HTML, CSV, measurement history, connection
journal, JSON snapshot. Seven color themes, including a dark one.

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/images/report.png" alt="PDF report"></td>
    <td width="50%" valign="top"><img src="docs/images/dark.png" alt="Dark theme"></td>
  </tr>
</table>

## Where the data comes from

Windows only - no administrator rights, no access to the wireless controller:

| Source | What it provides |
|---|---|
| `WlanScan` + `WlanGetNetworkBssList` (Native Wifi) | beacons / probe responses cached by the WLAN AutoConfig service: raw IEs, RSSI, frequency, Capability |
| `WlanQueryInterface`, once per second | the laptop's own connection: BSSID, RSSI, Rx/Tx rates, channel |
| `WlanRegisterNotification` (ACM, MSM, ONEX) | connection and roaming stages, failure reasons, 802.1X result and EAP error |
| `GetAdaptersInfo` | IPv4, DHCP server, lease time |
| `Microsoft-Windows-WLAN-AutoConfig/Operational` event log | history of connections, failures and disconnects with Windows' own text |
| Wireshark `manuf` file | vendor by OUI |

This is not monitor mode: retransmissions, EAPOL and roaming frames are not visible this way. The UI is a local
page on `127.0.0.1` in a dedicated Edge window; the app only goes online when you click "Check for updates".

## Installation

Download from the [Releases](https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/latest) page:

| File | Purpose |
|---|---|
| `WiFiBeaconScanner-Setup-<version>.exe` | installer: Program Files, Start menu shortcut, regular uninstall |
| `WiFiBeaconScanner.exe` | portable single-file version, no installation |

Silent install (SCCM, Intune, GPO, PDQ):

```
WiFiBeaconScanner-Setup-1.0.1.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
```

The files are not code-signed, so SmartScreen asks for confirmation when you run them manually
("More info" → "Run anyway"). Details in [Installation and deployment](docs/en/deployment.md).

From source (Python 3.8+, no dependencies):

```
python -m wifi_beacon_scanner gui            # scan
python -m wifi_beacon_scanner gui --demo     # try it on demo data (works on any OS)
```

## Documentation

- [Installation and deployment](docs/en/deployment.md) - silent install, where data is stored, limitations
- [Diagnostics](docs/en/diagnostics.md) - all checks, 802.11 amendments, signal scale, channel load, MCS and PHY rate
- [Connection journal and sessions](docs/en/connection-journal.md) - roams, disconnects, connection stages, 802.1X, DHCP
- [Development, build and release](docs/en/development.md) - running from source, CLI, tests, building the exe, releases
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE)
