# Installation and deployment

[← README](../../README.md) · [Русский](../ru/deployment.md)

## Release files

On the [Releases](https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases) page:

- `WiFiBeaconScanner2-Setup-<version>.exe` - installer for the current user (no administrator rights, Start menu
  shortcut, entry in "Installed apps", regular uninstall);
- `WiFiBeaconScanner2.exe` - portable single-file version, no installation;
- `SHA256SUMS.txt` - checksums.

Requirements: Windows 10 or 11 (x64) and the Microsoft Edge WebView2 runtime. It is part of Windows 11 and is
delivered to current Windows 10 with Edge updates; if it is missing, the installer downloads it (this needs
internet access), while the portable exe will not start without it.

Silent install for deploying to many laptops (SCCM, Intune, GPO, PDQ) - run it in the user's context, the app is
installed per user:

    WiFiBeaconScanner2-Setup-2.0.0.exe /S

Silent uninstall:

    "%LOCALAPPDATA%\Wi-Fi Beacon Scanner 2\uninstall.exe" /S

A new version installs over the old one. Version 2 installs next to version 1.x and does not change it: they have
different folders, settings and Start menu shortcuts. Uninstall 1.x separately (Settings → Apps) when it is no
longer needed.

The files are not code-signed. When a downloaded file is run manually, SmartScreen shows "Windows protected
your PC" → "More info" → "Run anyway"; there is no such prompt when deploying via SCCM/Intune/GPO.
To get rid of the warning entirely you need a code-signing certificate (corporate PKI or OV/EV) and `signtool`.

The app log: `%LOCALAPPDATA%\WiFiBeaconScanner2\logs\app.log` - send it if something goes wrong
(View → About → "Log folder").

## Where the app stores data

| What | Where |
|---|---|
| Program | `%LOCALAPPDATA%\Wi-Fi Beacon Scanner 2` (`wbs-app.exe`, `uninstall.exe`) |
| Start menu shortcut | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Wi-Fi Beacon Scanner 2.lnk` |
| View settings, language, "My SSIDs", column widths | `%APPDATA%\WiFiBeaconScanner2\prefs.json`; until it exists, the 1.x settings (`%APPDATA%\WiFiBeaconScanner\prefs.json`) are used, the 1.x file is never changed |
| App log | `%LOCALAPPDATA%\WiFiBeaconScanner2\logs\app.log` (up to 1 MB plus three previous files): start-up, scans, page errors |
| WebView2 profile of the window | `%LOCALAPPDATA%\io.github.salilov95.wifibeaconscanner2` |
| Exports | wherever the user saved them; the app writes nothing else |

Uninstall removes the program and the shortcut; the settings, the log and the WebView2 profile stay (delete the
three folders above by hand if needed).

## Interface language

English or Russian. On first start the app follows the Windows display language (Russian for a Russian
Windows, English otherwise); the user can switch it in View → Language, and the choice is saved in `prefs.json`
(`"lang": "en"` or `"ru"`). For a whole fleet the language can be fixed in that file or with the `--lang en`
command-line option (for one run). Problems, beacon decoding and PDF/Excel/HTML reports use the same language.
Windows event log messages are shown as Windows provides them, in the system language; connection journal
events keep the language they were recorded in.

## Command-line options

| Option | What it does |
|---|---|
| `--demo [scan.json]` | demo mode without Wi-Fi: a built-in office or your own saved scan, with a demo connection journal |
| `--ssid NAME` | "My SSIDs" for this run (can be repeated; `--ssid=NAME` also works) |
| `--manuf PATH` | vendor database (Wireshark `manuf` file) instead of the built-in one |
| `--lang en` / `--lang ru` | interface and report language for this run |

The 1.x options `--port`, `--no-browser` and `--keep-running` are accepted and ignored: version 2 has no local server.

## How the app works

The window is WebView2; the page and the program talk to each other inside the process, through the app's own
`wbs` protocol. There is no local server and no open network port. Closing the window exits the app.

The app does not go online by itself. The only exception is View → "Check for updates": a single request to
`api.github.com` (through the Windows system proxy).

PDF reports are printed by the installed Microsoft Edge (headless). If headless printing is blocked by policy,
the app shows the reason and offers to open the report so you can save it as PDF with Ctrl+P.

## Limitations

- Verified on a laptop with MediaTek Wi-Fi 6 MT7921 (Windows 11): scanning, window, connection journal,
  sessions and the Windows event log. Parsing of 802.1X failure reasons has not yet been checked against
  real failures.
- This is not monitor mode: we see what the WLAN AutoConfig service provides. Retransmissions, EAPOL and
  roaming frames are not visible this way.
- Windows rate-limits scans; `WlanScan` may return an error, in which case the cache is read.
- Since Windows 11 24H2, Wi-Fi scanning requires location permission. On the first scan Windows shows a prompt
  by itself; until access is granted, `WlanScan` and `WlanGetNetworkBssList` return `ERROR_ACCESS_DENIED`.
  The app shows a banner with an "Open location settings" button and retries with auto-scan.
  For GPO/Intune deployment: "Privacy → Location → Let desktop apps access your location" must be enabled.
- Channel load and station count come from QBSS Load, which not every AP advertises.
  No IE means no number, not "0%".
- Extension IDs for Wi-Fi 7 (EHT: 106/108) still need to be checked against the current 802.11be text;
  "Wi-Fi 7" detection has not been confirmed on a real AP.
- A snapshot contains SSIDs and BSSIDs of all networks around: make sure sharing it is acceptable before
  sending it to anyone.
