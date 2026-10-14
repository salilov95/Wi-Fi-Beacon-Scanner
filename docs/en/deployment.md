# Installation and deployment

[← README](../../README.md) · [Русский](../ru/deployment.md)

## Release files

On the [Releases](https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases) page:

- `WiFiBeaconScanner-Setup-<version>.exe` - installer (Program Files, Start menu shortcut, regular uninstall);
- `WiFiBeaconScanner.exe` - portable single-file version, no installation;
- `SHA256SUMS.txt` - checksums.

Silent install for deploying to many laptops (SCCM, Intune, GPO, PDQ):

    WiFiBeaconScanner-Setup-1.0.1.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-

Silent uninstall:

    "C:\Program Files\Wi-Fi Beacon Scanner\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

Without administrator rights you can install for the current user only: add `/CURRENTUSER`. A new version
installs over the old one: the running app is closed, settings (`%APPDATA%\WiFiBeaconScanner`) are kept.

The files are not code-signed. When a downloaded file is run manually, SmartScreen shows "Windows protected
your PC" → "More info" → "Run anyway"; there is no such prompt when deploying via SCCM/Intune/GPO.
To get rid of the warning entirely you need a code-signing certificate (corporate PKI or OV/EV) and `signtool`.

The installed version runs without a console window and exits by itself when the window is closed. The app log:
`%LOCALAPPDATA%\WiFiBeaconScanner\logs\app.log` - send it if something goes wrong
(View → About → "Log folder").

## Where the app stores data

| What | Where |
|---|---|
| Program | `C:\Program Files\Wi-Fi Beacon Scanner` (with `/CURRENTUSER` - in the user profile) |
| View settings, "My SSIDs", column widths | `%APPDATA%\WiFiBeaconScanner\prefs.json` |
| App log | `%LOCALAPPDATA%\WiFiBeaconScanner\logs\app.log` (up to 1 MB plus three previous files): start-up, scans, page errors |
| Console output of the installed version | `%LOCALAPPDATA%\WiFiBeaconScanner\logs\console.log` |
| Edge window profile | `%LOCALAPPDATA%\WiFiBeaconScanner\edge-profile` |
| Exports | wherever the user saved them; the app writes nothing else |

Uninstall keeps the settings and the log. Settings of versions before 0.7.0 (`%APPDATA%\WifiDiag`) are picked up
on first start.

## How the app works

Python starts a server on `127.0.0.1` only (not reachable from the network); an Edge window in app mode is the
UI for it. Access is protected by a one-time token. Close the window and the app exits within a few seconds
(reloading the page does not stop it). To keep it running, start it with `--keep-running`.

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
